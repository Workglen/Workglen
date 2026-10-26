use std::{collections::BTreeMap, fmt, io};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Configuration,
    Authentication,
    Protocol,
    Connection,
    Database,
    Data,
    Transaction,
}

#[derive(Debug, Clone)]
pub struct Error {
    pub kind: ErrorKind,
    message: String,
    fields: BTreeMap<u8, String>,
}
impl Error {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            fields: BTreeMap::new(),
        }
    }
    pub(crate) fn config(message: &'static str) -> Self {
        Self::new(ErrorKind::Configuration, message)
    }
    pub(crate) fn protocol(message: &'static str) -> Self {
        Self::new(ErrorKind::Protocol, message)
    }
    pub(crate) fn auth(message: &'static str) -> Self {
        Self::new(ErrorKind::Authentication, message)
    }
    pub(crate) fn data(message: &'static str) -> Self {
        Self::new(ErrorKind::Data, message)
    }
    pub(crate) fn database(fields: BTreeMap<u8, String>) -> Result<Self> {
        let code = fields
            .get(&b'C')
            .ok_or_else(|| Self::protocol("missing SQLSTATE"))?;
        if code.len() != 5
            || !code
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            return Err(Self::protocol("invalid SQLSTATE"));
        }
        let message = fields
            .get(&b'M')
            .ok_or_else(|| Self::protocol("missing database error message"))?
            .clone();
        Ok(Self {
            kind: ErrorKind::Database,
            message,
            fields,
        })
    }
    pub fn code(&self) -> Option<&str> {
        self.fields.get(&b'C').map(String::as_str)
    }
    pub fn severity(&self) -> Option<&str> {
        self.fields
            .get(&b'V')
            .or_else(|| self.fields.get(&b'S'))
            .map(String::as_str)
    }
    pub fn message(&self) -> &str {
        &self.message
    }
    pub fn field(&self, code: u8) -> Option<&str> {
        self.fields.get(&code).map(String::as_str)
    }
    pub fn is_fatal(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::Protocol | ErrorKind::Connection | ErrorKind::Authentication
        ) || matches!(self.severity(), Some("FATAL" | "PANIC"))
            || self.code().is_some_and(|c| c.starts_with("08"))
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.code() {
            write!(f, "PostgreSQL {code}: {}", self.message)
        } else {
            write!(f, "PostgreSQL {:?}: {}", self.kind, self.message)
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::new(ErrorKind::Connection, e.to_string())
    }
}
