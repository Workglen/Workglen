use crate::error::{Result, ensure};
use pratique::{
    tls::{
        ClientConfig, TlsStream,
        server::{ServerConfig, ServerStream},
    },
    x509::TrustStore,
};
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

// Native open flags for our Linux/macOS targets; avoid introducing a libc dependency.
// Darwin bsd/sys/fcntl.h assigns O_NOFOLLOW=0x100; Linux uses 0x20000.
pub(crate) const OPEN_NOFOLLOW: i32 = if cfg!(target_os = "macos") {
    0x100
} else {
    0x20000
};

#[derive(Debug)]
pub struct LineTooLong;
impl std::fmt::Display for LineTooLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("line too long")
    }
}
impl std::error::Error for LineTooLong {}

pub struct Gate {
    n: AtomicUsize,
    max: usize,
}
pub struct Permit(Arc<Gate>);
impl Gate {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            n: AtomicUsize::new(0),
            max,
        })
    }
    pub fn enter(self: &Arc<Self>) -> Option<Permit> {
        self.n
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                if n < self.max { Some(n + 1) } else { None }
            })
            .ok()
            .map(|_| Permit(self.clone()))
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.n.fetch_sub(1, Ordering::SeqCst);
    }
}
#[derive(Clone)]
pub struct Deadline(Arc<Mutex<Instant>>);
impl Deadline {
    pub fn set(&self, d: Duration) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now() + d;
    }
    fn remaining(&self) -> io::Result<Duration> {
        let d = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .saturating_duration_since(Instant::now());
        if d.is_zero() {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(d)
        }
    }
}
pub struct Socket {
    tcp: TcpStream,
    deadline: Deadline,
}
impl Socket {
    fn new(tcp: TcpStream) -> Result<Self> {
        tcp.set_nodelay(true)?;
        Ok(Self {
            tcp,
            deadline: Deadline(Arc::new(Mutex::new(
                Instant::now() + Duration::from_secs(10),
            ))),
        })
    }
}
impl Read for Socket {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.tcp
            .set_read_timeout(Some(self.deadline.remaining()?))?;
        self.tcp.read(b)
    }
}
impl Write for Socket {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.tcp
            .set_write_timeout(Some(self.deadline.remaining()?))?;
        self.tcp.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}
pub enum Channel {
    Plain(Socket),
    Server(Box<ServerStream<Socket>>),
    Client(Box<TlsStream<Socket>>),
}
impl Read for Channel {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(b),
            Self::Server(s) => s.read(b),
            Self::Client(s) => s.read(b),
        }
    }
}
impl Write for Channel {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(b),
            Self::Server(s) => s.write(b),
            Self::Client(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Server(s) => s.flush(),
            Self::Client(s) => s.flush(),
        }
    }
}
pub struct Wire {
    io: Option<BufReader<Channel>>,
    pub deadline: Deadline,
    pending: Vec<u8>,
    pub secure: bool,
}
impl Wire {
    pub fn plain(tcp: TcpStream) -> Result<Self> {
        let s = Socket::new(tcp)?;
        let deadline = s.deadline.clone();
        Ok(Self {
            io: Some(BufReader::with_capacity(8192, Channel::Plain(s))),
            deadline,
            pending: Vec::new(),
            secure: false,
        })
    }
    pub fn accept(tcp: TcpStream, c: &Arc<ServerConfig>) -> Result<Self> {
        let mut w = Self::plain(tcp)?;
        w.starttls(c)?;
        Ok(w)
    }
    pub fn connect(addr: SocketAddr, name: &str, ca: &str) -> Result<Self> {
        let mut c = if ca.is_empty() {
            ClientConfig::with_system_roots()?
        } else {
            let mut roots = TrustStore::empty();
            ensure!(
                roots.add_pem(&std::fs::read_to_string(ca)?) > 0,
                "no CA certificates"
            );
            ClientConfig::new(roots)
        };
        c.alpn_protocols.clear();
        let s = Socket::new(TcpStream::connect_timeout(&addr, Duration::from_secs(5))?)?;
        let deadline = s.deadline.clone();
        let tls = TlsStream::connect(s, name, &c)?;
        Ok(Self {
            io: Some(BufReader::with_capacity(
                8192,
                Channel::Client(Box::new(tls)),
            )),
            deadline,
            pending: Vec::new(),
            secure: true,
        })
    }
    pub fn starttls(&mut self, c: &Arc<ServerConfig>) -> Result<()> {
        ensure!(
            !self.secure && self.pending.is_empty(),
            "invalid STARTTLS state"
        );
        let io = self.io.take().unwrap();
        ensure!(io.buffer().is_empty(), "pipelined bytes across STARTTLS");
        let Channel::Plain(s) = io.into_inner() else {
            crate::bail!("already TLS")
        };
        self.deadline.set(Duration::from_secs(10));
        let tls = ServerStream::accept(s, c)?;
        self.io = Some(BufReader::with_capacity(
            8192,
            Channel::Server(Box::new(tls)),
        ));
        self.secure = true;
        Ok(())
    }
    pub fn starttls_client(&mut self, name: &str, c: &ClientConfig) -> Result<()> {
        ensure!(
            !self.secure && self.pending.is_empty(),
            "invalid client STARTTLS state"
        );
        let io = self
            .io
            .take()
            .ok_or_else(|| crate::error!("closed TLS channel"))?;
        ensure!(io.buffer().is_empty(), "pipelined bytes across STARTTLS");
        let Channel::Plain(s) = io.into_inner() else {
            crate::bail!("already TLS")
        };
        let tls = TlsStream::connect(s, name, c)?;
        self.io = Some(BufReader::with_capacity(
            8192,
            Channel::Client(Box::new(tls)),
        ));
        self.secure = true;
        Ok(())
    }
    pub fn line(&mut self, max: usize) -> Result<Vec<u8>> {
        loop {
            let r = self.io.as_mut().unwrap();
            let b = r.fill_buf()?;
            ensure!(!b.is_empty(), "connection closed");
            let n = b
                .iter()
                .position(|x| *x == b'\n')
                .map(|n| n + 1)
                .unwrap_or(b.len());
            if self.pending.len() + n > max {
                return Err(LineTooLong.into());
            }
            self.pending.extend_from_slice(&b[..n]);
            r.consume(n);
            if self.pending.last() == Some(&b'\n') {
                let line = std::mem::take(&mut self.pending);
                ensure!(line.ends_with(b"\r\n"), "bare LF forbidden");
                return Ok(line);
            }
        }
    }
    pub fn text(&mut self, max: usize) -> Result<String> {
        let l = self.line(max)?;
        Ok(String::from_utf8(l[..l.len() - 2].to_vec())?)
    }
    pub fn send(&mut self, s: &str) -> Result<()> {
        self.bytes(s.as_bytes())
    }
    pub fn bytes(&mut self, b: &[u8]) -> Result<()> {
        let w = self.io.as_mut().unwrap().get_mut();
        w.write_all(b)?;
        w.flush()?;
        Ok(())
    }
    pub fn exact(&mut self, b: &mut [u8]) -> Result<()> {
        self.io.as_mut().unwrap().read_exact(b)?;
        Ok(())
    }
}
pub fn server_config(cert: &str, key: &str) -> Result<Arc<ServerConfig>> {
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        std::fs::metadata(key)?.permissions().mode() & 0o077 == 0,
        "TLS key permissions must be 0600"
    );
    Ok(Arc::new(
        ServerConfig::from_pem(
            &std::fs::read_to_string(cert)?,
            &std::fs::read_to_string(key)?,
        )?
        .with_alpn(&[]),
    ))
}
pub fn timeout(e: &crate::error::Error) -> bool {
    e.downcast_ref::<io::Error>().is_some_and(|e| {
        matches!(
            e.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        )
    })
}
