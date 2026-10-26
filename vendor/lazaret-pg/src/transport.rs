use crate::{Config, Error, Host, Result, SslMode};
use pratique::{
    tls::{ClientConfig, TlsStream},
    x509::{Certificate, SigAlg},
};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

fn bounded<T: Send + 'static>(
    timeout: Duration,
    work: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> Result<T> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static PENDING: AtomicUsize = AtomicUsize::new(0);
    if PENDING
        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < 8).then_some(n + 1)
        })
        .is_err()
    {
        return Err(Error::new(
            crate::ErrorKind::Connection,
            "local resolver/connect worker limit reached",
        ));
    }
    struct Permit;
    impl Drop for Permit {
        fn drop(&mut self) {
            PENDING.fetch_sub(1, Ordering::AcqRel);
        }
    }
    let permit = Permit;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("lazaret-pg-connect".into())
        .spawn(move || {
            let _permit = permit;
            let _ = tx.send(work());
        })?;
    rx.recv_timeout(timeout)
        .map_err(|_| {
            Error::new(
                crate::ErrorKind::Connection,
                "resolution/connect deadline exceeded",
            )
        })?
        .map_err(Error::from)
}

#[derive(Clone)]
enum Endpoint {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}
enum Socket {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}
struct DeadlineSocket {
    socket: Socket,
    deadline: Arc<Mutex<Instant>>,
}
impl DeadlineSocket {
    fn limit(&self) -> io::Result<()> {
        let timeout = self
            .deadline
            .lock()
            .map_err(|_| io::Error::other("deadline poisoned"))?
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "PostgreSQL operation deadline exceeded",
                )
            })?;
        match &self.socket {
            Socket::Tcp(s) => {
                s.set_read_timeout(Some(timeout))?;
                s.set_write_timeout(Some(timeout))
            }
            #[cfg(unix)]
            Socket::Unix(s) => {
                s.set_read_timeout(Some(timeout))?;
                s.set_write_timeout(Some(timeout))
            }
        }
    }
}
impl Read for DeadlineSocket {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.limit()?;
        match &mut self.socket {
            Socket::Tcp(s) => s.read(b),
            #[cfg(unix)]
            Socket::Unix(s) => s.read(b),
        }
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.limit()?;
        match &mut self.socket {
            Socket::Tcp(s) => s.write(b),
            #[cfg(unix)]
            Socket::Unix(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.limit()?;
        match &mut self.socket {
            Socket::Tcp(s) => s.flush(),
            #[cfg(unix)]
            Socket::Unix(s) => s.flush(),
        }
    }
}
enum Stream {
    Plain(DeadlineSocket),
    Tls(Box<TlsStream<DeadlineSocket>>),
}
pub(crate) struct Transport {
    stream: Stream,
    deadline: Arc<Mutex<Instant>>,
    endpoint: Endpoint,
    pub binding: Option<Vec<u8>>,
    pub secure: bool,
}
impl Transport {
    pub fn connect(config: &Config) -> Result<Self> {
        let until = Instant::now() + config.connect_timeout;
        let endpoints = match &config.hosts[0] {
            Host::Tcp(host) => {
                if let Some(ip) = config.hostaddrs.first() {
                    vec![Endpoint::Tcp(SocketAddr::new(*ip, config.port))]
                } else if let Ok(ip) = host.parse() {
                    vec![Endpoint::Tcp(SocketAddr::new(ip, config.port))]
                } else {
                    // std DNS lookup is blocking: isolate it behind a bounded receive.
                    let name = host.clone();
                    let port = config.port;
                    bounded(config.connect_timeout, move || {
                        (name.as_str(), port)
                            .to_socket_addrs()
                            .map(|a| a.take(16).map(Endpoint::Tcp).collect::<Vec<_>>())
                    })?
                }
            }
            #[cfg(unix)]
            Host::Unix(path) => vec![Endpoint::Unix(
                path.join(format!(".s.PGSQL.{}", config.port)),
            )],
            #[cfg(not(unix))]
            Host::Unix(_) => {
                return Err(Error::config(
                    "Unix sockets are unavailable on this platform",
                ));
            }
        };
        let mut last = Error::new(
            crate::ErrorKind::Connection,
            "no resolved PostgreSQL address",
        );
        for endpoint in endpoints {
            match Self::open(config, endpoint, until) {
                Ok(t) => return Ok(t),
                Err(e) => {
                    if e.kind != crate::ErrorKind::Connection {
                        return Err(e);
                    }
                    last = e;
                }
            }
        }
        Err(last)
    }
    fn open(config: &Config, endpoint: Endpoint, until: Instant) -> Result<Self> {
        let timeout = until
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                Error::new(crate::ErrorKind::Connection, "connection deadline exceeded")
            })?;
        let socket = match &endpoint {
            Endpoint::Tcp(a) => {
                let s = TcpStream::connect_timeout(a, timeout)?;
                s.set_nodelay(true)?;
                Socket::Tcp(s)
            }
            #[cfg(unix)]
            Endpoint::Unix(path) => {
                let path = path.clone();
                Socket::Unix(bounded(timeout, move || {
                    std::os::unix::net::UnixStream::connect(path)
                })?)
            }
        };
        let deadline = Arc::new(Mutex::new(until));
        let mut raw = DeadlineSocket {
            socket,
            deadline: deadline.clone(),
        };
        let mut binding = None;
        let (stream, secure) = if config.ssl == SslMode::Disable {
            let local = matches!(&config.hosts[0], Host::Unix(_));
            (Stream::Plain(raw), local)
        } else {
            let Host::Tcp(name) = &config.hosts[0] else {
                return Err(Error::config("Unix sockets require sslmode=disable"));
            };
            raw.write_all(&[0, 0, 0, 8, 4, 210, 22, 47])?;
            raw.flush()?;
            let mut answer = [0];
            raw.read_exact(&mut answer)?;
            if answer != *b"S" {
                return Err(Error::auth("PostgreSQL server refused TLS"));
            }
            let mut tls = if let Some(path) = &config.ca {
                ClientConfig::new(
                    pratique::sys::trust_store_from_pem_file(path)
                        .map_err(|_| Error::auth("cannot load PostgreSQL CA certificates"))?,
                )
            } else {
                ClientConfig::with_system_roots()
                    .map_err(|_| Error::auth("cannot load system CA certificates"))?
            };
            tls.alpn_protocols = vec![b"postgresql".to_vec()];
            let stream = TlsStream::connect(raw, name, &tls).map_err(|_| {
                Error::auth("PostgreSQL TLS certificate or handshake verification failed")
            })?;
            if let Some(der) = stream.peer_certificate() {
                binding = endpoint_hash(der);
            }
            (Stream::Tls(Box::new(stream)), true)
        };
        Ok(Self {
            stream,
            deadline,
            endpoint,
            binding,
            secure,
        })
    }
    pub fn deadline(&mut self, duration: Duration) {
        if let Ok(mut d) = self.deadline.lock() {
            *d = Instant::now() + duration;
        }
    }
    pub fn cancel_token(&self, config: &Config, pid: u32, key: u32) -> CancelToken {
        // Cancellation needs the verified endpoint, never credentials or a DNS re-resolution.
        let mut config = config.clone();
        config.password = None;
        config.passfile = None;
        CancelToken {
            config,
            endpoint: self.endpoint.clone(),
            pid,
            key,
        }
    }
}
impl Read for Transport {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match &mut self.stream {
            Stream::Plain(s) => s.read(b),
            Stream::Tls(s) => s.read(b),
        }
    }
}
impl Write for Transport {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match &mut self.stream {
            Stream::Plain(s) => s.write(b),
            Stream::Tls(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match &mut self.stream {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}
pub(crate) fn endpoint_hash(der: &[u8]) -> Option<Vec<u8>> {
    let cert = Certificate::from_der(der).ok()?;
    let hash = match cert.signature_algorithm()? {
        SigAlg::RsaPkcs1(h) | SigAlg::RsaPss(h) | SigAlg::Ecdsa(h) => h,
        _ => return None,
    };
    Some(hash.digest(der))
}
#[derive(Clone)]
pub struct CancelToken {
    config: Config,
    endpoint: Endpoint,
    pid: u32,
    key: u32,
}
impl std::fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelToken").finish_non_exhaustive()
    }
}
impl CancelToken {
    /// Send cancellation to the original peer. PostgreSQL supplies no acknowledgement.
    pub fn cancel_query(&self) -> Result<()> {
        let mut t = Transport::open(
            &self.config,
            self.endpoint.clone(),
            Instant::now() + self.config.connect_timeout,
        )?;
        let mut body = Vec::from(16u32.to_be_bytes());
        body.extend_from_slice(&80877102u32.to_be_bytes());
        body.extend_from_slice(&self.pid.to_be_bytes());
        body.extend_from_slice(&self.key.to_be_bytes());
        t.write_all(&body)?;
        t.flush()?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
