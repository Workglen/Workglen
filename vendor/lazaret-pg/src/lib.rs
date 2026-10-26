//! PostgreSQL protocol 3.0, translated from Lazaret's Python driver.
//! SQL and values travel separately through the extended query protocol.
#![forbid(unsafe_code)]

pub mod config;
mod connection;
mod error;
mod md5;
mod saslprep;
mod scram;
mod transport;
pub mod types;
mod wire;

pub use config::{ChannelBinding, Config, Host, IsolationLevel, SslMode, TargetSessionAttrs};
pub use connection::{
    Client, CommandResult, Notification, RowStream, Transaction, TransactionBuilder,
};
pub use error::{Error, ErrorKind, Result};
pub use transport::CancelToken;
pub use types::{Column, FromSql, Row, ToSql};
