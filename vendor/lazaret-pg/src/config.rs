use crate::{Client, Error, Result};
use pratique::zeroize::Zeroizing;
use std::{
    collections::BTreeMap,
    fmt,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Tcp(String),
    Unix(PathBuf),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
    Disable,
    Require,
    VerifyFull,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelBinding {
    Disable,
    Prefer,
    Require,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSessionAttrs {
    Any,
    ReadWrite,
    ReadOnly,
    Primary,
    Standby,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    ReadCommitted,
    RepeatableRead,
    Serializable,
}
impl IsolationLevel {
    pub(crate) fn sql(self) -> &'static str {
        match self {
            Self::ReadCommitted => "READ COMMITTED",
            Self::RepeatableRead => "REPEATABLE READ",
            Self::Serializable => "SERIALIZABLE",
        }
    }
}

/// Explicit configuration. Parsing does not read environment variables or files.
/// TLS always verifies the chain and hostname, including `sslmode=require`.
#[derive(Clone)]
pub struct Config {
    pub(crate) hosts: Vec<Host>,
    pub(crate) hostaddrs: Vec<IpAddr>,
    pub(crate) port: u16,
    pub(crate) user: Option<String>,
    pub(crate) database: Option<String>,
    pub(crate) password: Option<Zeroizing<Vec<u8>>>,
    pub(crate) ssl: SslMode,
    pub(crate) binding: ChannelBinding,
    pub(crate) ca: Option<PathBuf>,
    pub(crate) connect_timeout: Duration,
    pub(crate) timeout: Duration,
    pub(crate) options: Option<String>,
    pub(crate) application: String,
    pub(crate) target: TargetSessionAttrs,
    pub(crate) passfile: Option<PathBuf>,
    pub(crate) allow_cleartext: bool,
    pub(crate) require_auth: Option<(bool, Vec<String>)>,
}
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("ssl", &self.ssl)
            .field("channel_binding", &self.binding)
            .finish_non_exhaustive()
    }
}
impl Default for Config {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            hostaddrs: Vec::new(),
            port: 5432,
            user: None,
            database: None,
            password: None,
            ssl: SslMode::VerifyFull,
            binding: ChannelBinding::Prefer,
            ca: None,
            connect_timeout: Duration::from_secs(5),
            timeout: Duration::from_secs(30),
            options: None,
            application: "lazaret-pg".into(),
            target: TargetSessionAttrs::Any,
            passfile: None,
            allow_cleartext: false,
            require_auth: None,
        }
    }
}
impl Config {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn host(&mut self, value: &str) -> &mut Self {
        self.hosts = vec![if value.starts_with('/') {
            Host::Unix(value.into())
        } else {
            Host::Tcp(value.into())
        }];
        self
    }
    pub fn hostaddr(&mut self, value: IpAddr) -> &mut Self {
        self.hostaddrs = vec![value];
        self
    }
    pub fn port(&mut self, value: u16) -> &mut Self {
        self.port = value;
        self
    }
    pub fn user(&mut self, value: &str) -> &mut Self {
        self.user = Some(value.into());
        self
    }
    pub fn dbname(&mut self, value: &str) -> &mut Self {
        self.database = Some(value.into());
        self
    }
    pub fn password(&mut self, value: impl AsRef<[u8]>) -> &mut Self {
        self.password = Some(Zeroizing::new(value.as_ref().to_vec()));
        self
    }
    pub fn ssl_mode(&mut self, value: SslMode) -> &mut Self {
        self.ssl = value;
        self
    }
    pub fn channel_binding(&mut self, value: ChannelBinding) -> &mut Self {
        self.binding = value;
        self
    }
    pub fn ca_file(&mut self, value: impl AsRef<Path>) -> &mut Self {
        self.ca = Some(value.as_ref().into());
        self
    }
    pub fn connect_timeout(&mut self, value: Duration) -> &mut Self {
        self.connect_timeout = value;
        self
    }
    pub fn operation_timeout(&mut self, value: Duration) -> &mut Self {
        self.timeout = value;
        self
    }
    pub fn options(&mut self, value: &str) -> &mut Self {
        self.options = Some(value.into());
        self
    }
    pub fn application_name(&mut self, value: &str) -> &mut Self {
        self.application = value.into();
        self
    }
    pub fn target_session_attrs(&mut self, value: TargetSessionAttrs) -> &mut Self {
        self.target = value;
        self
    }
    pub fn passfile(&mut self, value: impl AsRef<Path>) -> &mut Self {
        self.passfile = Some(value.as_ref().into());
        self
    }
    pub fn allow_cleartext_password(&mut self, value: bool) -> &mut Self {
        self.allow_cleartext = value;
        self
    }
    pub fn get_hosts(&self) -> &[Host] {
        &self.hosts
    }
    pub fn get_hostaddrs(&self) -> &[IpAddr] {
        &self.hostaddrs
    }
    pub fn get_user(&self) -> Option<&str> {
        self.user.as_deref()
    }
    pub fn get_dbname(&self) -> Option<&str> {
        self.database.as_deref()
    }
    pub fn get_ssl_mode(&self) -> SslMode {
        self.ssl
    }
    pub fn connect(&self) -> Result<Client> {
        Client::connect(self.clone())
    }
    pub fn validate(&self) -> Result<()> {
        if self.hosts.len() != 1 || self.hostaddrs.len() > 1 || self.port == 0 {
            return Err(Error::config(
                "exactly one host and a valid port are required",
            ));
        }
        for value in [
            self.user.as_deref(),
            self.database.as_deref(),
            Some(&self.application),
            self.options.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.len() > 16384 || value.as_bytes().contains(&0) {
                return Err(Error::config(
                    "connection value exceeds limit or contains NUL",
                ));
            }
        }
        if self.user.as_deref().is_none_or(str::is_empty)
            || self.database.as_deref().is_none_or(str::is_empty)
        {
            return Err(Error::config("database and user are required"));
        }
        if self
            .password
            .as_ref()
            .is_some_and(|p| p.len() > 16384 || p.contains(&0))
        {
            return Err(Error::config("invalid password length or NUL"));
        }
        if self.connect_timeout.is_zero()
            || self.timeout.is_zero()
            || self.connect_timeout > Duration::from_secs(300)
            || self.timeout > Duration::from_secs(3600)
        {
            return Err(Error::config("invalid connection or operation timeout"));
        }
        match &self.hosts[0] {
            Host::Tcp(s)
                if s.is_empty()
                    || s.len() > 253
                    || s.contains(',')
                    || s.chars().any(char::is_control) =>
            {
                return Err(Error::config("invalid or multiple hosts"));
            }
            Host::Unix(p)
                if !p.is_absolute()
                    || p.components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                    || !self.hostaddrs.is_empty() =>
            {
                return Err(Error::config(
                    "invalid Unix socket path or hostaddr override",
                ));
            }
            _ => {}
        }
        Ok(())
    }
    /// Explicit opt-in to PG* environment/default passfile lookup. Workglen uses FromStr instead.
    pub fn from_env() -> Result<Self> {
        let mut values = BTreeMap::new();
        for (key, env) in [
            ("host", "PGHOST"),
            ("hostaddr", "PGHOSTADDR"),
            ("port", "PGPORT"),
            ("user", "PGUSER"),
            ("password", "PGPASSWORD"),
            ("dbname", "PGDATABASE"),
            ("sslmode", "PGSSLMODE"),
            ("sslrootcert", "PGSSLROOTCERT"),
            ("channel_binding", "PGCHANNELBINDING"),
            ("application_name", "PGAPPNAME"),
            ("options", "PGOPTIONS"),
            ("connect_timeout", "PGCONNECT_TIMEOUT"),
            ("require_auth", "PGREQUIREAUTH"),
            ("target_session_attrs", "PGTARGETSESSIONATTRS"),
            ("passfile", "PGPASSFILE"),
        ] {
            if let Some(v) = std::env::var_os(env) {
                #[cfg(unix)]
                {
                    use std::os::unix::ffi::OsStrExt;
                    values.insert(key.to_string(), v.as_os_str().as_bytes().to_vec());
                }
                #[cfg(not(unix))]
                {
                    values.insert(key.to_string(), v.to_string_lossy().as_bytes().to_vec());
                }
            }
        }
        values
            .entry("host".into())
            .or_insert_with(|| b"/tmp".to_vec());
        if !values.contains_key("user") {
            values.insert(
                "user".into(),
                std::env::var("USER")
                    .unwrap_or_else(|_| "postgres".into())
                    .into_bytes(),
            );
        }
        if !values.contains_key("dbname") {
            values.insert("dbname".into(), values["user"].clone());
        }
        if !values.contains_key("passfile")
            && let Some(home) = std::env::var_os("HOME")
        {
            let p = PathBuf::from(home).join(".pgpass");
            if p.exists() {
                values.insert("passfile".into(), p.to_string_lossy().as_bytes().to_vec());
            }
        }
        Self::from_values(values)
    }
    fn from_values(values: BTreeMap<String, Vec<u8>>) -> Result<Self> {
        let mut out = Self::new();
        let has_application = values.contains_key("application_name");
        for (key, bytes) in values {
            if key == "password" {
                out.password = Some(Zeroizing::new(bytes));
                continue;
            }
            let v = std::str::from_utf8(&bytes)
                .map_err(|_| Error::config("non-UTF8 connection value"))?;
            if v.contains('\0') {
                return Err(Error::config("NUL in connection value"));
            }
            match key.as_str() {
                "host" => {
                    out.host(v);
                }
                "hostaddr" => {
                    out.hostaddr(
                        v.parse()
                            .map_err(|_| Error::config("hostaddr must be a literal IP"))?,
                    );
                }
                "port" => {
                    out.port = v.parse().map_err(|_| Error::config("invalid port"))?;
                }
                "user" => {
                    out.user(v);
                }
                "dbname" | "database" => {
                    out.dbname(v);
                }
                "sslmode" => {
                    out.ssl = match v {
                        "disable" => SslMode::Disable,
                        "require" => SslMode::Require,
                        "verify-full" => SslMode::VerifyFull,
                        _ => {
                            return Err(Error::config(
                                "use disable for explicit local transport or verified require/verify-full TLS",
                            ));
                        }
                    }
                }
                "sslrootcert" => {
                    if v != "system" {
                        out.ca_file(v);
                    }
                }
                "channel_binding" => {
                    out.binding = match v {
                        "disable" => ChannelBinding::Disable,
                        "prefer" => ChannelBinding::Prefer,
                        "require" => ChannelBinding::Require,
                        _ => return Err(Error::config("invalid channel_binding")),
                    }
                }
                "connect_timeout" => {
                    let secs: u64 = v
                        .parse()
                        .map_err(|_| Error::config("invalid connect_timeout"))?;
                    if secs != 0 {
                        out.connect_timeout = Duration::from_secs(secs);
                    }
                }
                "application_name" => {
                    out.application_name(v);
                }
                "fallback_application_name" => {
                    if !has_application {
                        out.application_name(v);
                    }
                }
                "options" => {
                    out.options(v);
                }
                "passfile" => {
                    out.passfile(v);
                }
                "client_encoding" if v == "UTF8" || v == "UTF-8" => {}
                "target_session_attrs" => {
                    out.target = match v {
                        "any" => TargetSessionAttrs::Any,
                        "read-write" => TargetSessionAttrs::ReadWrite,
                        "read-only" => TargetSessionAttrs::ReadOnly,
                        "primary" => TargetSessionAttrs::Primary,
                        "standby" => TargetSessionAttrs::Standby,
                        _ => return Err(Error::config("unsupported target_session_attrs")),
                    }
                }
                "require_auth" => {
                    let parts: Vec<_> = v.split(',').collect();
                    let negative = parts[0].starts_with('!');
                    let mut methods = Vec::new();
                    for p in parts {
                        let method = p.strip_prefix('!').unwrap_or(p);
                        if p.starts_with('!') != negative
                            || !["none", "password", "md5", "scram-sha-256"].contains(&method)
                        {
                            return Err(Error::config("invalid require_auth"));
                        }
                        methods.push(method.to_string());
                    }
                    out.require_auth = Some((negative, methods));
                }
                "gssencmode" if v == "disable" => {}
                "sslnegotiation" if v == "postgres" => {}
                _ => {
                    return Err(Error::config(
                        "unknown or unsupported connection parameter; values omitted",
                    ));
                }
            }
        }
        Ok(out)
    }
    pub(crate) fn auth_permitted(&self, method: &str) -> bool {
        self.require_auth
            .as_ref()
            .is_none_or(|(neg, list)| list.iter().any(|x| x == method) != *neg)
    }
    pub(crate) fn load_password(&mut self) -> Result<()> {
        if self.password.is_some() {
            return Ok(());
        }
        let Some(path) = &self.passfile else {
            return Ok(());
        };
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_file() || meta.len() > 1024 * 1024 {
            return Err(Error::config(
                "password file must be a bounded regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
                return Err(Error::config("password file must be private and unlinked"));
            }
        }
        use std::io::Read;
        let file = std::fs::File::open(path)?;
        let opened = file.metadata()?;
        if !opened.is_file() {
            return Err(Error::config("password file is not regular"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if opened.dev() != meta.dev()
                || opened.ino() != meta.ino()
                || opened.mode() & 0o077 != 0
                || opened.nlink() != 1
            {
                return Err(Error::config("password file changed during open"));
            }
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err(Error::config("password file exceeds limit"));
        }
        let host = match &self.hosts[0] {
            Host::Tcp(h) => h.as_str(),
            Host::Unix(p) => {
                if ["/tmp", "/var/run/postgresql", "/run/postgresql"]
                    .iter()
                    .any(|x| p == Path::new(x))
                {
                    "localhost"
                } else {
                    p.to_str()
                        .ok_or_else(|| Error::config("non-UTF8 socket path"))?
                }
            }
        };
        let port = self.port.to_string();
        for line in bytes.split(|x| *x == b'\n') {
            if line.first() == Some(&b'#') || line.is_empty() {
                continue;
            }
            let mut fields = vec![Zeroizing::new(Vec::new())];
            let mut escape = false;
            for &b in line.strip_suffix(b"\r").unwrap_or(line) {
                if escape {
                    fields.last_mut().unwrap().push(b);
                    escape = false;
                } else if b == b'\\' {
                    escape = true;
                } else if b == b':' {
                    if fields.len() >= 5 {
                        escape = true;
                        break;
                    }
                    fields.push(Zeroizing::new(Vec::new()));
                } else {
                    fields.last_mut().unwrap().push(b);
                }
            }
            if escape || fields.len() != 5 {
                continue;
            }
            if fields[..4]
                .iter()
                .zip([
                    host,
                    port.as_str(),
                    self.database.as_deref().unwrap(),
                    self.user.as_deref().unwrap(),
                ])
                .all(|(a, b)| a.as_slice() == b"*" || a.as_slice() == b.as_bytes())
            {
                self.password = fields.pop();
                break;
            }
        }
        Ok(())
    }
}
fn pct(value: &str) -> Result<Vec<u8>> {
    let b = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let pair = b
                .get(i + 1..i + 3)
                .ok_or_else(|| Error::config("invalid percent escape"))?;
            let h = (pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| Error::config("invalid percent escape"))?;
            let l = (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| Error::config("invalid percent escape"))?;
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    if out.contains(&0) {
        return Err(Error::config("NUL in connection URI"));
    }
    Ok(out)
}
impl FromStr for Config {
    type Err = Error;
    fn from_str(raw: &str) -> Result<Self> {
        if raw.len() > 65536 || raw.contains('\0') {
            return Err(Error::config("invalid connection string length or NUL"));
        }
        let raw = raw.trim();
        let mut values = BTreeMap::new();
        if let Some(mut rest) = raw
            .strip_prefix("postgresql://")
            .or_else(|| raw.strip_prefix("postgres://"))
        {
            let first = rest.find('/').unwrap_or(rest.len());
            if let Some(at) = rest[..first].rfind('@') {
                let (user, pass) = rest[..at]
                    .split_once(':')
                    .map_or((&rest[..at], None), |(u, p)| (u, Some(p)));
                if !user.is_empty() {
                    values.insert("user".into(), pct(user)?);
                }
                if let Some(p) = pass {
                    values.insert("password".into(), pct(p)?);
                }
                rest = &rest[at + 1..];
            }
            let end = rest.find(['/', '?']).unwrap_or(rest.len());
            let authority = &rest[..end];
            rest = &rest[end..];
            if authority.contains(',') {
                return Err(Error::config("multiple hosts are unsupported"));
            }
            let (host, port) = if let Some(s) = authority.strip_prefix('[') {
                let (host, after) = s
                    .split_once(']')
                    .ok_or_else(|| Error::config("invalid bracketed host"))?;
                let port = if after.is_empty() {
                    None
                } else {
                    Some(
                        after
                            .strip_prefix(':')
                            .ok_or_else(|| Error::config("invalid bracketed port"))?,
                    )
                };
                (host, port)
            } else {
                authority
                    .split_once(':')
                    .map_or((authority, None), |(h, p)| (h, Some(p)))
            };
            if !host.is_empty() {
                values.insert("host".into(), pct(host)?);
            }
            if let Some(p) = port {
                values.insert("port".into(), pct(p)?);
            }
            let query = if let Some(path) = rest.strip_prefix('/') {
                let (db, q) = path.split_once('?').unwrap_or((path, ""));
                if !db.is_empty() {
                    values.insert("dbname".into(), pct(db)?);
                }
                q
            } else {
                rest.strip_prefix('?').unwrap_or("")
            };
            for item in query.split('&').filter(|s| !s.is_empty()) {
                let (k, v) = item
                    .split_once('=')
                    .ok_or_else(|| Error::config("invalid connection URI query"))?;
                let key =
                    String::from_utf8(pct(k)?).map_err(|_| Error::config("invalid URI key"))?;
                values.insert(key, pct(v)?);
            }
        } else {
            let b = raw.as_bytes();
            let mut i = 0;
            while i < b.len() {
                while i < b.len() && b[i].is_ascii_whitespace() {
                    i += 1;
                }
                if i == b.len() {
                    break;
                }
                let start = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'=' {
                    i += 1;
                }
                let key = std::str::from_utf8(&b[start..i])
                    .map_err(|_| Error::config("invalid connection key"))?;
                while i < b.len() && b[i].is_ascii_whitespace() {
                    i += 1;
                }
                if key.is_empty() || b.get(i) != Some(&b'=') {
                    return Err(Error::config("missing connection parameter separator"));
                }
                i += 1;
                while i < b.len() && b[i].is_ascii_whitespace() {
                    i += 1;
                }
                let quoted = b.get(i) == Some(&b'\'');
                if quoted {
                    i += 1;
                }
                let mut value = Vec::new();
                let mut closed = !quoted;
                while i < b.len() {
                    let ch = b[i];
                    if quoted && ch == b'\'' {
                        i += 1;
                        closed = true;
                        break;
                    }
                    if !quoted && ch.is_ascii_whitespace() {
                        break;
                    }
                    if ch == b'\\' {
                        i += 1;
                        if i == b.len() {
                            return Err(Error::config("trailing connection escape"));
                        }
                    }
                    value.push(b[i]);
                    i += 1;
                }
                if !closed || (quoted && i < b.len() && !b[i].is_ascii_whitespace()) {
                    return Err(Error::config("invalid quoted connection value"));
                }
                values.insert(key.to_string(), value);
            }
        }
        Self::from_values(values)
    }
}
