//! Bounded recursive-DNS client for Workglen. No search suffixes, subprocesses,
//! local DNSSEC validation, or automatic public resolver fallback. Configured
//! recursive resolvers retain responsibility for DNSSEC; AD is never trusted as
//! proof of validation. Transport futures are cancellable by the caller.
use pratique::asyncio::{AsyncReadExt, AsyncWriteExt, socket::SocketBudget};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseCode {
    NoError,
    NXDomain,
}
impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoError => "NoError",
            Self::NXDomain => "NXDomain",
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    NoRecords(ResponseCode),
    InvalidName,
    Malformed,
    Timeout,
    Resolver(String),
    Response(u8),
    Limit,
}
impl Error {
    pub fn is_no_records_found(&self) -> bool {
        matches!(self, Self::NoRecords(_))
    }
    pub fn is_nx_domain(&self) -> bool {
        matches!(self, Self::NoRecords(ResponseCode::NXDomain))
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolver(s) => write!(f, "DNS resolver: {s}"),
            e => write!(f, "DNS {e:?}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Resolver(e.to_string())
    }
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name(String);
impl Name {
    pub fn parse(s: &str) -> Result<Self> {
        if s == "." {
            return Ok(Self(".".into()));
        }
        let s = s.strip_suffix('.').unwrap_or(s);
        if s.is_empty() || s.len() > 1024 {
            return Err(Error::InvalidName);
        }
        let s = workglen_idna::domain_to_ascii(s)
            .map_err(|_| Error::InvalidName)?
            .to_ascii_lowercase();
        if s.len() > 253
            || s.split('.').any(|l| {
                l.is_empty()
                    || l.len() > 63
                    || !l
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
        {
            return Err(Error::InvalidName);
        }
        Ok(Self(format!("{s}.")))
    }
    pub fn to_ascii(&self) -> String {
        self.0.clone()
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn to_lowercase(&self) -> Self {
        self.clone()
    }
    pub fn is_empty(&self) -> bool {
        self.0 == "."
    }
}
impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct A(pub Ipv4Addr);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AAAA(pub Ipv6Addr);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MX {
    pub preference: u16,
    pub exchange: Name,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TXT {
    pub txt_data: Vec<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    A(A),
    AAAA(AAAA),
    MX(MX),
    TXT(TXT),
    PTR(Name),
    CNAME(Name),
}
impl RData {
    pub fn record_type(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::AAAA(_) => RecordType::AAAA,
            Self::MX(_) => RecordType::MX,
            Self::TXT(_) => RecordType::TXT,
            Self::PTR(_) => RecordType::PTR,
            Self::CNAME(_) => RecordType::CNAME,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Record {
    pub name: Name,
    pub data: RData,
    pub ttl: u32,
}
#[derive(Clone, Debug)]
pub struct Lookup {
    records: Vec<Record>,
    until: Instant,
}
impl Lookup {
    pub fn answers(&self) -> &[Record] {
        &self.records
    }
    pub fn valid_until(&self) -> Instant {
        self.until
    }
}
#[derive(Clone, Debug)]
pub struct Config {
    pub servers: Vec<SocketAddr>,
    pub timeout: Duration,
    pub attempts: usize,
    pub cache_size: usize,
    /// Hard cap on live UDP sockets and pending/connected TCP sockets.
    pub max_sockets: usize,
}
impl Config {
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        Self {
            servers,
            timeout: Duration::from_secs(3),
            attempts: 2,
            cache_size: 256,
            max_sockets: 256,
        }
    }
    pub fn system() -> Result<Self> {
        Self::resolv_conf(&std::fs::read_to_string("/etc/resolv.conf")?)
    }
    pub fn resolv_conf(text: &str) -> Result<Self> {
        let mut servers = Vec::new();
        for line in text.lines() {
            let line = line.split(['#', ';']).next().unwrap_or("");
            let mut parts = line.split_whitespace();
            if parts.next() == Some("nameserver") {
                if servers.len() >= 3 {
                    break;
                }
                let ip = parts
                    .next()
                    .ok_or(Error::InvalidName)?
                    .parse::<IpAddr>()
                    .map_err(|_| Error::InvalidName)?;
                servers.push(SocketAddr::new(ip, 53));
            }
        }
        if servers.is_empty() {
            return Err(Error::Resolver("no nameservers configured".into()));
        }
        Ok(Self::new(servers))
    }
}
struct Cached {
    value: Result<Lookup>,
    until: Instant,
    used: u64,
}
#[derive(Default)]
struct Cache {
    entries: HashMap<(Name, RecordType), Cached>,
    clock: u64,
}
pub struct Resolver {
    config: Config,
    cache: Mutex<Cache>,
    sockets: SocketBudget,
    health: Mutex<Vec<ServerHealth>>,
}
#[derive(Clone, Default)]
struct ServerHealth {
    failures: u32,
    retry_after: Option<Instant>,
}
impl Resolver {
    pub fn new(config: Config) -> Result<Self> {
        if config.servers.is_empty()
            || config.servers.len() > 8
            || config.attempts == 0
            || config.attempts > 4
            || config.timeout.is_zero()
            || config.timeout > Duration::from_secs(30)
            || config.cache_size > 4096
            || config.max_sockets == 0
            || config.max_sockets > 4096
        {
            return Err(Error::Limit);
        }
        let sockets = SocketBudget::new(config.max_sockets)?;
        Ok(Self {
            sockets,
            health: Mutex::new(vec![ServerHealth::default(); config.servers.len()]),
            config,
            cache: Mutex::new(Cache::default()),
        })
    }
    // Passive health checks use actual validated DNS exchanges. Do not create
    // background probes or silently send questions to public fallback services.
    fn server_order(&self) -> Vec<usize> {
        let health = self.health.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let mut order: Vec<_> = (0..self.config.servers.len()).collect();
        order.sort_by_key(|&i| (health[i].retry_after.is_some_and(|t| t > now), i));
        order
    }
    fn server_result(&self, index: usize, success: bool) {
        let mut health = self.health.lock().unwrap_or_else(|e| e.into_inner());
        let state = &mut health[index];
        if success {
            *state = ServerHealth::default();
        } else {
            state.failures = state.failures.saturating_add(1);
            let delay = 1u64 << state.failures.min(5);
            state.retry_after = Some(Instant::now() + Duration::from_secs(delay));
        }
    }
    fn cached(&self, key: &(Name, RecordType)) -> Option<Result<Lookup>> {
        let mut c = self.cache.lock().ok()?;
        c.clock = c.clock.wrapping_add(1);
        let clock = c.clock;
        if let Some(e) = c.entries.get_mut(key)
            && e.until > Instant::now()
        {
            e.used = clock;
            return Some(e.value.clone());
        }
        c.entries.remove(key);
        None
    }
    fn cache(&self, key: (Name, RecordType), value: Result<Lookup>, until: Instant) {
        if self.config.cache_size == 0 || until <= Instant::now() {
            return;
        }
        if let Ok(mut c) = self.cache.lock() {
            c.entries.retain(|_, v| v.until > Instant::now());
            if c.entries.len() >= self.config.cache_size
                && !c.entries.contains_key(&key)
                && let Some(k) = c
                    .entries
                    .iter()
                    .min_by_key(|(_, v)| v.used)
                    .map(|(k, _)| k.clone())
            {
                c.entries.remove(&k);
            }
            c.clock = c.clock.wrapping_add(1);
            let used = c.clock;
            c.entries.insert(key, Cached { value, until, used });
        }
    }
    pub async fn lookup(&self, name: impl AsRef<str>, kind: RecordType) -> Result<Lookup> {
        let original = Name::parse(name.as_ref())?;
        let key = (original.clone(), kind);
        if let Some(v) = self.cached(&key) {
            return v;
        }
        let mut current = original;
        let mut seen = HashSet::new();
        let mut ttl = u32::MAX;
        for _ in 0..16 {
            if !seen.insert(current.clone()) {
                return Err(Error::Malformed);
            }
            let response = self.exchange(&current, kind).await?;
            ttl = ttl.min(response.ttl);
            match response.outcome {
                Outcome::Data(records) => {
                    let until = Instant::now() + Duration::from_secs(u64::from(ttl.min(86400)));
                    let value = Lookup { records, until };
                    self.cache(key, Ok(value.clone()), until);
                    return Ok(value);
                }
                Outcome::Alias(target) => {
                    current = target;
                }
                Outcome::Absent(code) => {
                    let value = Err(Error::NoRecords(code));
                    let until = Instant::now() + Duration::from_secs(u64::from(ttl.min(10800)));
                    self.cache(key, value.clone(), until);
                    return value;
                }
            }
        }
        Err(Error::Limit)
    }
    async fn exchange(&self, name: &Name, kind: RecordType) -> Result<Parsed> {
        let mut last = Error::Resolver("no nameservers configured".into());
        for _ in 0..self.config.attempts {
            for index in self.server_order() {
                let server = self.config.servers[index];
                let mut random = [0; 2];
                pratique::crypto::rand::fill(&mut random)
                    .map_err(|e| Error::Resolver(e.to_string()))?;
                let id = u16::from_be_bytes(random);
                let query = query(name, kind, id);
                let attempt = async {
                    let socket = self.sockets.udp_bind(SocketAddr::new(
                        if server.is_ipv4() {
                            Ipv4Addr::UNSPECIFIED.into()
                        } else {
                            Ipv6Addr::UNSPECIFIED.into()
                        },
                        0,
                    ))?;
                    socket.connect(server)?;
                    socket.send(&query).await?;
                    let mut buf = vec![0; 65535];
                    // Connected socket pins the sender. Ignore mismatched transaction IDs
                    // without resetting the attempt deadline or accepting their contents.
                    loop {
                        let n = socket.recv(&mut buf).await?;
                        if n < 2 || buf[..2] != random {
                            continue;
                        }
                        let packet = &buf[..n];
                        validate_question(packet, name, kind, id)?;
                        if word(packet, 2)? & 0x0200 != 0 {
                            // The UDP socket is no longer needed; release it before TCP admission.
                            drop(socket);
                            let mut tcp = self.sockets.tcp_connect(server).await?;
                            tcp.write_all(&(query.len() as u16).to_be_bytes()).await?;
                            tcp.write_all(&query).await?;
                            let mut prefix = [0; 2];
                            tcp.read_exact(&mut prefix).await?;
                            let len = u16::from_be_bytes(prefix) as usize;
                            if len < 12 {
                                return Err(Error::Malformed);
                            }
                            let mut reply = vec![0; len];
                            tcp.read_exact(&mut reply).await?;
                            return parse(&reply, name, kind, id);
                        }
                        return parse(packet, name, kind, id);
                    }
                };
                match pratique::asyncio::timeout(self.config.timeout, attempt).await {
                    Ok(Ok(p)) => {
                        self.server_result(index, true);
                        return Ok(p);
                    }
                    Ok(Err(e)) => {
                        // Local admission exhaustion says nothing about the peer.
                        if e != Error::Limit {
                            self.server_result(index, false);
                        }
                        last = e;
                    }
                    Err(_) => {
                        self.server_result(index, false);
                        last = Error::Timeout;
                    }
                }
            }
        }
        Err(last)
    }
    pub async fn txt_lookup(&self, name: Name) -> Result<Lookup> {
        self.lookup(name.as_str(), RecordType::TXT).await
    }
    pub async fn mx_lookup(&self, name: Name) -> Result<Lookup> {
        self.lookup(name.as_str(), RecordType::MX).await
    }
    pub async fn ipv4_lookup(&self, name: Name) -> Result<Lookup> {
        self.lookup(name.as_str(), RecordType::A).await
    }
    pub async fn ipv6_lookup(&self, name: Name) -> Result<Lookup> {
        self.lookup(name.as_str(), RecordType::AAAA).await
    }
    pub async fn reverse_lookup(&self, ip: IpAddr) -> Result<Lookup> {
        let s = match ip {
            IpAddr::V4(ip) => {
                let b = ip.octets();
                format!("{}.{}.{}.{}.in-addr.arpa.", b[3], b[2], b[1], b[0])
            }
            IpAddr::V6(ip) => {
                let mut s = String::new();
                for b in ip.octets().iter().rev() {
                    s.push_str(&format!("{:x}.{:x}.", b & 15, b >> 4));
                }
                s.push_str("ip6.arpa.");
                s
            }
        };
        self.lookup(s, RecordType::PTR).await
    }
    pub async fn lookup_ip(&self, name: Name) -> Result<Lookup> {
        match self.ipv4_lookup(name.clone()).await {
            Ok(v) => Ok(v),
            Err(e) if e.is_no_records_found() => self.ipv6_lookup(name).await,
            Err(e) => Err(e),
        }
    }
}
fn word(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(
        b.get(at..at + 2)
            .ok_or(Error::Malformed)?
            .try_into()
            .unwrap(),
    ))
}
fn dword(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        b.get(at..at + 4)
            .ok_or(Error::Malformed)?
            .try_into()
            .unwrap(),
    ))
}
fn wire_name(b: &[u8], cursor: &mut usize) -> Result<Name> {
    let mut at = *cursor;
    let mut jumped = false;
    let mut labels = Vec::new();
    let mut bytes = 1;
    for _ in 0..128 {
        let n = *b.get(at).ok_or(Error::Malformed)? as usize;
        if n & 0xc0 == 0xc0 {
            let ptr = (word(b, at)? & 0x3fff) as usize;
            if ptr >= at || ptr < 12 {
                return Err(Error::Malformed);
            }
            if !jumped {
                *cursor = at + 2;
                jumped = true;
            }
            at = ptr;
            continue;
        }
        if n & 0xc0 != 0 {
            return Err(Error::Malformed);
        }
        at += 1;
        if n == 0 {
            if !jumped {
                *cursor = at;
            }
            return Ok(Name(if labels.is_empty() {
                ".".into()
            } else {
                format!("{}.", labels.join("."))
            }));
        }
        bytes += n + 1;
        if bytes > 255 {
            return Err(Error::Malformed);
        }
        let label = b.get(at..at + n).ok_or(Error::Malformed)?;
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        {
            return Err(Error::Malformed);
        }
        labels.push(String::from_utf8(label.to_ascii_lowercase()).map_err(|_| Error::Malformed)?);
        at += n;
    }
    Err(Error::Limit)
}
fn query(name: &Name, kind: RecordType, id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(272);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name
        .0
        .trim_end_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
    {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&(kind as u16).to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    out
}
fn validate_question(b: &[u8], name: &Name, kind: RecordType, id: u16) -> Result<usize> {
    let flags = word(b, 2)?;
    if b.len() < 12
        || word(b, 0)? != id
        || flags & 0xf800 != 0x8000
        || flags & 0x0040 != 0
        || word(b, 4)? != 1
    {
        return Err(Error::Malformed);
    }
    let mut at = 12;
    if wire_name(b, &mut at)? != *name || word(b, at)? != kind as u16 || word(b, at + 2)? != 1 {
        return Err(Error::Malformed);
    }
    Ok(at + 4)
}
enum Outcome {
    Data(Vec<Record>),
    Alias(Name),
    Absent(ResponseCode),
}
struct Parsed {
    outcome: Outcome,
    ttl: u32,
}
fn parse(b: &[u8], name: &Name, kind: RecordType, id: u16) -> Result<Parsed> {
    let mut at = validate_question(b, name, kind, id)?;
    let flags = word(b, 2)?;
    if flags & 0x0200 != 0 {
        return Err(Error::Malformed);
    }
    let rcode = (flags & 15) as u8;
    if !matches!(rcode, 0 | 3) {
        return Err(Error::Response(rcode));
    }
    let an = word(b, 6)? as usize;
    let ns = word(b, 8)? as usize;
    let ar = word(b, 10)? as usize;
    if an + ns + ar > 512 {
        return Err(Error::Limit);
    }
    let mut records = Vec::new();
    let mut negative = None;
    for index in 0..an + ns + ar {
        let owner = wire_name(b, &mut at)?;
        let typ = word(b, at)?;
        let class = word(b, at + 2)?;
        let ttl = dword(b, at + 4)?;
        let len = word(b, at + 8)? as usize;
        at += 10;
        let end = at
            .checked_add(len)
            .filter(|e| *e <= b.len())
            .ok_or(Error::Malformed)?;
        let start = at;
        let data = if class != 1 {
            None
        } else {
            match typ {
                1 => {
                    if len != 4 {
                        return Err(Error::Malformed);
                    }
                    Some(RData::A(A(Ipv4Addr::from(
                        <[u8; 4]>::try_from(&b[at..end]).unwrap(),
                    ))))
                }
                28 => {
                    if len != 16 {
                        return Err(Error::Malformed);
                    }
                    Some(RData::AAAA(AAAA(Ipv6Addr::from(
                        <[u8; 16]>::try_from(&b[at..end]).unwrap(),
                    ))))
                }
                5 | 12 => {
                    let target = wire_name(b, &mut at)?;
                    if at != end {
                        return Err(Error::Malformed);
                    }
                    Some(if typ == 5 {
                        RData::CNAME(target)
                    } else {
                        RData::PTR(target)
                    })
                }
                15 => {
                    let preference = word(b, at)?;
                    at += 2;
                    let exchange = wire_name(b, &mut at)?;
                    if at != end {
                        return Err(Error::Malformed);
                    }
                    Some(RData::MX(MX {
                        preference,
                        exchange,
                    }))
                }
                16 => {
                    let mut txt_data = Vec::new();
                    while at < end {
                        let n = b[at] as usize;
                        at += 1;
                        if at + n > end {
                            return Err(Error::Malformed);
                        }
                        txt_data.push(b[at..at + n].to_vec());
                        at += n;
                    }
                    Some(RData::TXT(TXT { txt_data }))
                }
                6 => {
                    wire_name(b, &mut at)?;
                    wire_name(b, &mut at)?;
                    if at + 20 != end {
                        return Err(Error::Malformed);
                    }
                    let minimum = dword(b, at + 16)?;
                    if index >= an
                        && index < an + ns
                        && (owner.0 == "."
                            || name.0 == owner.0
                            || name.0.ends_with(&format!(".{}", owner.0)))
                    {
                        negative = Some(
                            negative.map_or(ttl.min(minimum), |n: u32| n.min(ttl).min(minimum)),
                        );
                    }
                    None
                }
                _ => None,
            }
        };
        if index < an
            && let Some(data) = data
        {
            records.push(Record {
                name: owner,
                data,
                ttl,
            });
        }
        at = end;
        if at < start {
            return Err(Error::Malformed);
        }
    }
    if at != b.len() {
        return Err(Error::Malformed);
    }
    let mut current = name.clone();
    let mut seen = HashSet::new();
    let mut ttl = u32::MAX;
    for _ in 0..16 {
        if !seen.insert(current.clone()) {
            return Err(Error::Malformed);
        }
        let selected: Vec<_> = records
            .iter()
            .filter(|r| r.name == current && r.data.record_type() == kind)
            .cloned()
            .collect();
        let aliases: Vec<_> = records
            .iter()
            .filter(|r| r.name == current)
            .filter_map(|r| {
                if let RData::CNAME(n) = &r.data {
                    Some((n, r.ttl))
                } else {
                    None
                }
            })
            .collect();
        if !selected.is_empty() {
            if rcode != 0 || (!aliases.is_empty() && kind != RecordType::CNAME) {
                return Err(Error::Malformed);
            }
            ttl = ttl.min(selected.iter().map(|r| r.ttl).min().unwrap());
            return Ok(Parsed {
                outcome: Outcome::Data(selected),
                ttl,
            });
        }
        if let Some((target, _)) = aliases.first() {
            if aliases.iter().any(|(n, _)| *n != *target) {
                return Err(Error::Malformed);
            }
            ttl = ttl.min(aliases.iter().map(|(_, age)| *age).min().unwrap());
            current = (*target).clone();
            continue;
        }
        if current != *name && rcode == 0 && negative.is_none() {
            return Ok(Parsed {
                outcome: Outcome::Alias(current),
                ttl,
            });
        }
        return Ok(Parsed {
            outcome: Outcome::Absent(if rcode == 3 {
                ResponseCode::NXDomain
            } else {
                ResponseCode::NoError
            }),
            ttl: ttl.min(negative.unwrap_or(0)),
        });
    }
    Err(Error::Limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(name: &str, kind: RecordType, flags: u16) -> Vec<u8> {
        let mut b = query(&Name::parse(name).unwrap(), kind, 123);
        b[2..4].copy_from_slice(&flags.to_be_bytes());
        b
    }
    fn rr(b: &mut Vec<u8>, owner: &str, typ: u16, ttl: u32, data: &[u8]) {
        let q = query(&Name::parse(owner).unwrap(), RecordType::A, 0);
        b.extend_from_slice(&q[12..q.len() - 4]);
        b.extend_from_slice(&typ.to_be_bytes());
        b.extend_from_slice(&[0, 1]);
        b.extend_from_slice(&ttl.to_be_bytes());
        b.extend_from_slice(&(data.len() as u16).to_be_bytes());
        b.extend_from_slice(data);
    }
    fn name(s: &str) -> Vec<u8> {
        let q = query(&Name::parse(s).unwrap(), RecordType::A, 0);
        q[12..q.len() - 4].to_vec()
    }
    #[test]
    fn names_and_system_config() {
        assert_eq!(
            Name::parse("BÜCHER.example").unwrap().as_str(),
            "xn--bcher-kva.example."
        );
        assert!(Name::parse("a..b").is_err());
        assert!(Name::parse(&format!("{}.test", "a".repeat(64))).is_err());
        let c = Config::resolv_conf(
            "search should.not.be.used\nnameserver 127.0.0.1 # test\nnameserver ::1\n",
        )
        .unwrap();
        assert_eq!(c.servers.len(), 2);
        assert!(Config::resolv_conf("search foo").is_err());
        assert!(Resolver::new(Config::new(vec![])).is_err());
    }
    #[test]
    fn failed_resolver_is_deprioritized_then_reprobed_without_public_fallback() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let healthy = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        healthy
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let peers = vec![silent.local_addr().unwrap(), healthy.local_addr().unwrap()];
        let worker = std::thread::spawn(move || {
            for domain in ["first.test", "second.test"] {
                let mut packet = [0; 512];
                let (n, peer) = healthy.recv_from(&mut packet).unwrap();
                let mut answer = packet[..n].to_vec();
                answer[2] = 0x81;
                answer[3] = 0x80;
                answer[6..8].copy_from_slice(&1u16.to_be_bytes());
                rr(&mut answer, domain, 1, 0, &[1, 2, 3, 4]);
                healthy.send_to(&answer, peer).unwrap();
            }
        });
        let mut config = Config::new(peers);
        config.attempts = 1;
        config.timeout = Duration::from_millis(50);
        let resolver = Resolver::new(config).unwrap();
        pratique::asyncio::block_on(async {
            assert!(resolver.lookup("first.test", RecordType::A).await.is_ok());
            assert_eq!(resolver.server_order(), vec![1, 0]);
            assert!(resolver.lookup("second.test", RecordType::A).await.is_ok());
        });
        silent.set_nonblocking(true).unwrap();
        let mut buf = [0; 512];
        assert!(silent.recv_from(&mut buf).is_ok());
        assert_eq!(
            silent.recv_from(&mut buf).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        resolver.health.lock().unwrap()[0].retry_after =
            Some(Instant::now() - Duration::from_secs(1));
        assert_eq!(resolver.server_order(), vec![0, 1]);
        resolver.server_result(0, true);
        assert_eq!(resolver.health.lock().unwrap()[0].failures, 0);
        worker.join().unwrap();
    }
    #[test]
    fn valid_negative_answer_is_not_retried_on_another_resolver() {
        let negative = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let unused = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let config = Config::new(vec![
            negative.local_addr().unwrap(),
            unused.local_addr().unwrap(),
        ]);
        negative
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let worker = std::thread::spawn(move || {
            let mut b = [0; 512];
            let (n, peer) = negative.recv_from(&mut b).unwrap();
            b[2] = 0x81;
            b[3] = 0x83;
            negative.send_to(&b[..n], peer).unwrap();
        });
        let resolver = Resolver::new(config).unwrap();
        let result = pratique::asyncio::block_on(resolver.lookup("absent.test", RecordType::TXT));
        assert_eq!(
            result.unwrap_err(),
            Error::NoRecords(ResponseCode::NXDomain)
        );
        unused.set_nonblocking(true).unwrap();
        let mut b = [0; 512];
        assert_eq!(
            unused.recv_from(&mut b).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(
            resolver
                .health
                .lock()
                .unwrap()
                .iter()
                .all(|h| h.failures == 0)
        );
        worker.join().unwrap();
    }
    #[test]
    fn owner_binding_alias_and_ttl() {
        let mut b = response("alias.test", RecordType::A, 0x8180);
        b[6..8].copy_from_slice(&3u16.to_be_bytes());
        rr(&mut b, "unrelated.test", 1, 90, &[6, 6, 6, 6]);
        rr(&mut b, "alias.test", 5, 20, &name("target.test"));
        rr(&mut b, "target.test", 1, 60, &[1, 2, 3, 4]);
        let parsed = parse(&b, &Name::parse("alias.test").unwrap(), RecordType::A, 123).unwrap();
        assert_eq!(parsed.ttl, 20);
        let Outcome::Data(records) = parsed.outcome else {
            panic!()
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
        // Duplicate aliases still form one RRset; its shortest TTL applies.
        b[6..8].copy_from_slice(&4u16.to_be_bytes());
        rr(&mut b, "alias.test", 5, 0, &name("target.test"));
        let parsed = parse(&b, &Name::parse("alias.test").unwrap(), RecordType::A, 123).unwrap();
        assert_eq!(parsed.ttl, 0);
        b[0] = 7;
        assert!(parse(&b, &Name::parse("alias.test").unwrap(), RecordType::A, 123).is_err());
    }
    #[test]
    fn aliases_cannot_mix_with_data_or_cycle() {
        for target in ["a.test", "b.test"] {
            let mut b = response("a.test", RecordType::A, 0x8180);
            b[6..8].copy_from_slice(&2u16.to_be_bytes());
            rr(&mut b, "a.test", 5, 60, &name(target));
            rr(&mut b, target, 5, 60, &name("a.test"));
            assert!(parse(&b, &Name::parse("a.test").unwrap(), RecordType::A, 123).is_err());
        }
        let mut b = response("a.test", RecordType::A, 0x8180);
        b[6..8].copy_from_slice(&2u16.to_be_bytes());
        rr(&mut b, "a.test", 5, 60, &name("b.test"));
        rr(&mut b, "a.test", 1, 60, &[1, 1, 1, 1]);
        assert!(parse(&b, &Name::parse("a.test").unwrap(), RecordType::A, 123).is_err());
    }
    #[test]
    fn txt_fragments_and_null_mx() {
        let mut b = response("test", RecordType::TXT, 0x8180);
        b[6..8].copy_from_slice(&1u16.to_be_bytes());
        rr(&mut b, "test", 16, 30, &[2, b'a', b'b', 1, b'c']);
        let Outcome::Data(records) = parse(&b, &Name::parse("test").unwrap(), RecordType::TXT, 123)
            .unwrap()
            .outcome
        else {
            panic!()
        };
        let RData::TXT(t) = &records[0].data else {
            panic!()
        };
        assert_eq!(t.txt_data.concat(), b"abc");
        let mut b = response("test", RecordType::MX, 0x8180);
        b[6..8].copy_from_slice(&1u16.to_be_bytes());
        rr(&mut b, "test", 15, 30, &[0, 0, 0]);
        let Outcome::Data(records) = parse(&b, &Name::parse("test").unwrap(), RecordType::MX, 123)
            .unwrap()
            .outcome
        else {
            panic!()
        };
        let RData::MX(m) = &records[0].data else {
            panic!()
        };
        assert_eq!(m.exchange.as_str(), ".");
    }
    #[test]
    fn negative_soa_and_temporary_errors() {
        let mut b = response("missing.test", RecordType::A, 0x8183);
        b[8..10].copy_from_slice(&1u16.to_be_bytes());
        let mut soa = name("ns.test");
        soa.extend(name("hostmaster.test"));
        for n in [1u32, 2, 3, 4, 60] {
            soa.extend(n.to_be_bytes());
        }
        rr(&mut b, "test", 6, 120, &soa);
        let parsed = parse(
            &b,
            &Name::parse("missing.test").unwrap(),
            RecordType::A,
            123,
        )
        .unwrap();
        assert_eq!(parsed.ttl, 60);
        assert!(matches!(
            parsed.outcome,
            Outcome::Absent(ResponseCode::NXDomain)
        ));
        b[3] = 0x82;
        assert!(matches!(
            parse(
                &b,
                &Name::parse("missing.test").unwrap(),
                RecordType::A,
                123
            ),
            Err(Error::Response(2))
        ));
    }
    #[test]
    fn packet_bounds_and_mutations() {
        let mut b = response("host.test", RecordType::A, 0x8180);
        b[6..8].copy_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let host = Name::parse("host.test").unwrap();
        assert!(parse(&b, &host, RecordType::A, 123).is_ok());
        for n in 0..b.len() {
            assert!(parse(&b[..n], &host, RecordType::A, 123).is_err());
        }
        let mut looped = b.clone();
        looped[12] = 0xc0;
        looped[13] = 12;
        assert!(parse(&looped, &host, RecordType::A, 123).is_err());
        for i in 0..b.len() {
            for byte in 0..=255 {
                let mut x = b.clone();
                x[i] = byte;
                let _ = parse(&x, &host, RecordType::A, 123);
            }
        }
    }
    #[test]
    fn udp_truncation_retries_tcp_and_caches() {
        use std::io::{Read, Write};
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = std::net::UdpSocket::bind(addr).unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let worker = std::thread::spawn(move || {
            let mut b = [0; 512];
            let (n, peer) = udp.recv_from(&mut b).unwrap();
            let mut truncated = b[..n].to_vec();
            truncated[2] = 0x83;
            truncated[3] = 0x80;
            udp.send_to(&truncated, peer).unwrap();
            let (mut stream, _) = tcp.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut len = [0; 2];
            stream.read_exact(&mut len).unwrap();
            let mut q = vec![0; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut q).unwrap();
            q[2] = 0x81;
            q[3] = 0x80;
            q[6..8].copy_from_slice(&1u16.to_be_bytes());
            rr(&mut q, "local.test", 1, 60, &[1, 2, 3, 4]);
            stream.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
            stream.write_all(&q).unwrap();
        });
        pratique::asyncio::block_on(async {
            let r = Resolver::new(Config::new(vec![addr])).unwrap();
            assert_eq!(
                r.lookup("local.test", RecordType::A)
                    .await
                    .unwrap()
                    .answers()
                    .len(),
                1
            );
            assert_eq!(
                r.lookup("LOCAL.TEST.", RecordType::A)
                    .await
                    .unwrap()
                    .answers()
                    .len(),
                1
            );
        });
        worker.join().unwrap();
    }
    #[test]
    fn spoofed_id_ignored_and_zero_ttl_not_cached() {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let worker = std::thread::spawn(move || {
            for _ in 0..2 {
                let mut b = [0; 512];
                let (n, peer) = udp.recv_from(&mut b).unwrap();
                let mut reply = b[..n].to_vec();
                reply[2] = 0x81;
                reply[3] = 0x80;
                reply[6..8].copy_from_slice(&1u16.to_be_bytes());
                rr(&mut reply, "local.test", 1, 0, &[1, 2, 3, 4]);
                let mut forged = reply.clone();
                forged[0] ^= 1;
                udp.send_to(&forged, peer).unwrap();
                udp.send_to(&reply, peer).unwrap();
            }
        });
        pratique::asyncio::block_on(async {
            let r = Resolver::new(Config::new(vec![addr])).unwrap();
            for _ in 0..2 {
                assert_eq!(
                    r.lookup("local.test", RecordType::A)
                        .await
                        .unwrap()
                        .answers()
                        .len(),
                    1
                );
            }
        });
        worker.join().unwrap();
    }
    #[test]
    fn cache_and_cancellation_are_bounded() {
        pratique::asyncio::block_on(async {
            let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut cfg = Config::new(vec![udp.local_addr().unwrap()]);
            cfg.cache_size = 2;
            let r = Resolver::new(cfg).unwrap();
            let now = Instant::now();
            for n in 0..20 {
                r.cache(
                    (Name::parse(&format!("{n}.test")).unwrap(), RecordType::A),
                    Err(Error::NoRecords(ResponseCode::NXDomain)),
                    now + Duration::from_secs(30),
                );
            }
            assert_eq!(r.cache.lock().unwrap().entries.len(), 2);
            let start = Instant::now();
            assert!(
                pratique::asyncio::timeout(
                    Duration::from_millis(25),
                    r.lookup("timeout.test", RecordType::A)
                )
                .await
                .is_err()
            );
            assert!(start.elapsed() < Duration::from_secs(1));
            assert_eq!(r.sockets.in_use(), 0);
        });
    }

    #[test]
    fn wrong_id_flood_cannot_starve_the_attempt_deadline() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        udp.set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let peer = std::thread::spawn(move || {
            let mut packet = [0; 512];
            let (n, addr) = udp.recv_from(&mut packet).unwrap();
            packet[0] ^= 1;
            while !done.load(Ordering::Acquire) {
                let _ = udp.send_to(&packet[..n], addr);
            }
        });
        let mut cfg = Config::new(vec![addr]);
        cfg.attempts = 1;
        cfg.timeout = Duration::from_millis(35);
        let r = Resolver::new(cfg).unwrap();
        let start = Instant::now();
        let result = pratique::asyncio::block_on(r.lookup("flood.test", RecordType::A));
        stop.store(true, Ordering::Release);
        peer.join().unwrap();
        assert!(matches!(result, Err(Error::Timeout)));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(r.sockets.in_use(), 0);
    }

    #[test]
    fn udp_tcp_prefix_and_trickled_payload_share_one_attempt_deadline() {
        use std::io::{Read, Write};
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = std::net::UdpSocket::bind(addr).unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let peer = std::thread::spawn(move || {
            let mut bytes = [0; 512];
            let (n, peer) = udp.recv_from(&mut bytes).unwrap();
            std::thread::sleep(Duration::from_millis(15));
            bytes[2] = 0x83;
            bytes[3] = 0x80;
            udp.send_to(&bytes[..n], peer).unwrap();
            let (mut stream, _) = tcp.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut prefix = [0; 2];
            stream.read_exact(&mut prefix).unwrap();
            let mut request = vec![0; u16::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut request).unwrap();
            stream.write_all(&100u16.to_be_bytes()).unwrap();
            for _ in 0..100 {
                if stream.write_all(&[0]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let mut cfg = Config::new(vec![addr]);
        cfg.attempts = 1;
        cfg.timeout = Duration::from_millis(60);
        cfg.max_sockets = 1;
        let r = Resolver::new(cfg).unwrap();
        let start = Instant::now();
        let result = pratique::asyncio::block_on(r.lookup("slow.test", RecordType::A));
        assert!(matches!(result, Err(Error::Timeout)));
        assert!(start.elapsed() < Duration::from_millis(500));
        assert_eq!(r.sockets.in_use(), 0);
        peer.join().unwrap();
    }

    #[test]
    fn cancellation_releases_dns_admission_and_does_not_poison_the_cache() {
        use std::{
            future::Future,
            task::{Context, Waker},
        };
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut cfg = Config::new(vec![addr]);
        cfg.max_sockets = 1;
        cfg.attempts = 1;
        let r = Resolver::new(cfg).unwrap();
        let mut first = Box::pin(r.lookup("abandoned.test", RecordType::A));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(first.as_mut().poll(&mut cx).is_pending());
        assert_eq!(r.sockets.in_use(), 1);
        assert!(pratique::asyncio::block_on(r.lookup("busy.test", RecordType::A)).is_err());
        assert!(r.cache.lock().unwrap().entries.is_empty());
        drop(first);
        assert_eq!(r.sockets.in_use(), 0);
        let peer = std::thread::spawn(move || {
            let mut packet = [0; 512];
            let (n, peer) = udp.recv_from(&mut packet).unwrap();
            let mut reply = packet[..n].to_vec();
            reply[2] = 0x81;
            reply[3] = 0x80;
            reply[6..8].copy_from_slice(&1u16.to_be_bytes());
            rr(&mut reply, "valid.test", 1, 60, &[192, 0, 2, 1]);
            udp.send_to(&reply, peer).unwrap();
        });
        let value = pratique::asyncio::block_on(r.lookup("valid.test", RecordType::A)).unwrap();
        assert_eq!(value.answers().len(), 1);
        assert_eq!(r.sockets.in_use(), 0);
        peer.join().unwrap();
    }
}
