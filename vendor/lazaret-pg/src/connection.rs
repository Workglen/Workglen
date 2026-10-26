use crate::{
    Config, Error, ErrorKind, Result, Row, ToSql,
    config::{ChannelBinding, IsolationLevel, TargetSessionAttrs},
    scram::Scram,
    transport::{CancelToken, Transport},
    types,
    wire::{self, Cursor},
};
use pratique::zeroize::Zeroizing;
use std::{
    collections::{BTreeMap, VecDeque},
    io::{Read, Write},
    sync::Arc,
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct Notification {
    pub process_id: u32,
    pub channel: String,
    pub payload: String,
}
#[derive(Clone, Debug, Default)]
pub struct CommandResult {
    pub tag: String,
    pub rows_affected: u64,
}
pub struct Client {
    transport: Option<Transport>,
    config: Config,
    status: u8,
    backend: Option<(u32, u32)>,
    parameters: BTreeMap<String, String>,
    notifications: VecDeque<Notification>,
    notices: VecDeque<Error>,
    savepoint: u64,
}
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}
impl Client {
    pub(crate) fn connect(mut config: Config) -> Result<Self> {
        config.validate()?;
        config.load_password()?;
        config.validate()?;
        let transport = Transport::connect(&config)?;
        let mut c = Self {
            transport: Some(transport),
            config,
            status: 0,
            backend: None,
            parameters: BTreeMap::new(),
            notifications: VecDeque::new(),
            notices: VecDeque::new(),
            savepoint: 0,
        };
        c.startup()?;
        c.config.password = None;
        c.config.passfile = None;
        let target = c.config.target;
        if matches!(
            target,
            TargetSessionAttrs::ReadWrite | TargetSessionAttrs::ReadOnly
        ) {
            let value: String = c.query_one("SHOW transaction_read_only", &[])?.try_get(0)?;
            if (value == "on") != (target == TargetSessionAttrs::ReadOnly) {
                return Err(Error::config(
                    "server does not satisfy target_session_attrs",
                ));
            }
        }
        if matches!(
            target,
            TargetSessionAttrs::Primary | TargetSessionAttrs::Standby
        ) {
            let recovery: bool = c
                .query_one("SELECT pg_catalog.pg_is_in_recovery()", &[])?
                .try_get(0)?;
            if recovery != (target == TargetSessionAttrs::Standby) {
                return Err(Error::config(
                    "server does not satisfy target_session_attrs",
                ));
            }
        }
        Ok(c)
    }
    fn transport(&mut self) -> Result<&mut Transport> {
        self.transport
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::Connection, "connection is closed"))
    }
    fn start_operation(&mut self) -> Result<()> {
        let timeout = self.config.timeout;
        self.transport()?.deadline(timeout);
        Ok(())
    }
    fn guard<T>(&mut self, result: Result<T>) -> Result<T> {
        if result.as_ref().is_err_and(Error::is_fatal) {
            self.transport = None;
        }
        result
    }
    fn send(&mut self, kind: u8, body: &[u8]) -> Result<()> {
        let frame = Zeroizing::new(wire::message(kind, body)?);
        let result = self.transport()?.write_all(&frame).map_err(Error::from);
        self.guard(result)
    }
    fn flush(&mut self) -> Result<()> {
        let result = self.transport()?.flush().map_err(Error::from);
        self.guard(result)
    }
    fn receive(&mut self) -> Result<(u8, Vec<u8>)> {
        let result = (|| {
            let t = self.transport()?;
            let mut header = [0; 5];
            t.read_exact(&mut header)?;
            let size = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
            if !(4..=wire::MAX_MESSAGE).contains(&size) {
                return Err(Error::protocol("invalid message size"));
            }
            let mut body = vec![0; size - 4];
            t.read_exact(&mut body)?;
            Ok((header[0], body))
        })();
        self.guard(result)
    }
    fn startup(&mut self) -> Result<()> {
        let mut body = Vec::from(196608u32.to_be_bytes());
        for (key, value) in [
            ("user", self.config.user.as_deref().unwrap()),
            ("database", self.config.database.as_deref().unwrap()),
            ("client_encoding", "UTF8"),
            ("application_name", self.config.application.as_str()),
        ] {
            wire::cstr(&mut body, key)?;
            wire::cstr(&mut body, value)?;
        }
        if let Some(options) = &self.config.options {
            wire::cstr(&mut body, "options")?;
            wire::cstr(&mut body, options)?;
        }
        body.push(0);
        self.transport()?
            .write_all(&((body.len() + 4) as u32).to_be_bytes())?;
        self.transport()?.write_all(&body)?;
        self.flush()?;
        let mut scram: Option<Scram> = None;
        let mut auth_method = None;
        let mut authenticated = false;
        let mut frames = 0;
        loop {
            frames += 1;
            if frames > 1024 {
                return Err(Error::protocol("startup message limit exceeded"));
            }
            let (kind, body) = self.receive()?;
            match kind {
                b'R' => {
                    if authenticated {
                        return Err(Error::auth("authentication message after completion"));
                    }
                    let mut r = Cursor::new(&body);
                    let code = r.u32()?;
                    match code {
                        0 => {
                            r.done()?;
                            if let Some(s) = &scram {
                                if !s.verified {
                                    return Err(Error::auth("SCRAM server proof missing"));
                                }
                            } else if self.config.binding == ChannelBinding::Require {
                                return Err(Error::auth("channel binding is required"));
                            }
                            if !self.config.auth_permitted(auth_method.unwrap_or("none")) {
                                return Err(Error::auth(
                                    "authentication method forbidden by policy",
                                ));
                            }
                            authenticated = true;
                        }
                        3 | 5 => {
                            if auth_method.is_some() {
                                return Err(Error::auth("repeated authentication challenge"));
                            }
                            let method = if code == 3 { "password" } else { "md5" };
                            if self.config.binding == ChannelBinding::Require
                                || !self.config.auth_permitted(method)
                            {
                                return Err(Error::auth(
                                    "authentication method forbidden by policy",
                                ));
                            }
                            if code == 3
                                && !self.transport()?.secure
                                && !self.config.allow_cleartext
                            {
                                return Err(Error::auth(
                                    "cleartext password requires verified TLS, Unix socket, or explicit opt-in",
                                ));
                            }
                            let password = self
                                .config
                                .password
                                .as_ref()
                                .ok_or_else(|| Error::auth("password is required"))?;
                            let mut response = if code == 3 {
                                r.done()?;
                                Zeroizing::new(password.to_vec())
                            } else {
                                let salt = r.take(4)?;
                                r.done()?;
                                let mut first = Zeroizing::new(password.to_vec());
                                first.extend_from_slice(
                                    self.config.user.as_ref().unwrap().as_bytes(),
                                );
                                let digest = crate::md5::digest(&first);
                                let mut second =
                                    Zeroizing::new(pratique::util::hex(&digest).into_bytes());
                                second.extend_from_slice(salt);
                                Zeroizing::new(
                                    format!(
                                        "md5{}",
                                        pratique::util::hex(&crate::md5::digest(&second))
                                    )
                                    .into_bytes(),
                                )
                            };
                            response.push(0);
                            auth_method = Some(method);
                            self.send(b'p', &response)?;
                            self.flush()?;
                        }
                        10 => {
                            if auth_method.is_some() || !self.config.auth_permitted("scram-sha-256")
                            {
                                return Err(Error::auth(
                                    "unexpected or forbidden SASL authentication",
                                ));
                            }
                            let mut mechanisms = Vec::new();
                            loop {
                                let s = r.string()?;
                                if s.is_empty() {
                                    break;
                                }
                                if mechanisms.contains(&s) || mechanisms.len() >= 16 {
                                    return Err(Error::auth("invalid SASL mechanism list"));
                                }
                                mechanisms.push(s);
                            }
                            r.done()?;
                            let binding = if self.config.binding != ChannelBinding::Disable {
                                self.transport()?.binding.clone()
                            } else {
                                None
                            };
                            let selected = if mechanisms.contains(&"SCRAM-SHA-256-PLUS")
                                && binding.is_some()
                            {
                                binding.as_deref()
                            } else {
                                None
                            };
                            if self.config.binding == ChannelBinding::Require && selected.is_none()
                            {
                                return Err(Error::auth("SCRAM channel binding unavailable"));
                            }
                            if selected.is_none() && !mechanisms.contains(&"SCRAM-SHA-256") {
                                return Err(Error::auth("no supported SASL mechanism"));
                            }
                            let password = self
                                .config
                                .password
                                .as_ref()
                                .ok_or_else(|| Error::auth("password is required"))?;
                            let s = Scram::new(password, selected, binding.is_some())?;
                            let first = s.first();
                            let mut response = Zeroizing::new(Vec::new());
                            wire::cstr(&mut response, s.mechanism())?;
                            response.extend_from_slice(&(first.len() as i32).to_be_bytes());
                            response.extend_from_slice(first.as_bytes());
                            self.send(b'p', &response)?;
                            self.flush()?;
                            scram = Some(s);
                            auth_method = Some("scram-sha-256");
                        }
                        11 => {
                            let final_message = Zeroizing::new(
                                scram
                                    .as_mut()
                                    .ok_or_else(|| {
                                        Error::auth("SASL continuation before challenge")
                                    })?
                                    .final_message(r.rest())?
                                    .into_bytes(),
                            );
                            self.send(b'p', &final_message)?;
                            self.flush()?;
                        }
                        12 => scram
                            .as_mut()
                            .ok_or_else(|| Error::auth("SASL final before challenge"))?
                            .verify(r.rest())?,
                        _ => {
                            return Err(Error::auth(
                                "unsupported PostgreSQL authentication mechanism",
                            ));
                        }
                    }
                }
                b'K' if authenticated => {
                    if self.backend.is_some() {
                        return Err(Error::protocol("duplicate backend key"));
                    }
                    let mut r = Cursor::new(&body);
                    self.backend = Some((r.u32()?, r.u32()?));
                    r.done()?;
                }
                b'S' | b'N' if authenticated => {
                    self.asynchronous(kind, &body)?;
                }
                b'E' => return Err(Error::database(wire::fields(&body)?)?),
                b'Z' if authenticated => {
                    self.ready(&body)?;
                    if self.status != b'I' {
                        return Err(Error::protocol("startup transaction is not idle"));
                    }
                    return Ok(());
                }
                _ => return Err(Error::protocol("unexpected startup message")),
            }
        }
    }
    fn ready(&mut self, body: &[u8]) -> Result<()> {
        if body.len() != 1 || !b"ITE".contains(&body[0]) {
            return Err(Error::protocol("invalid transaction status"));
        }
        self.status = body[0];
        Ok(())
    }
    fn asynchronous(&mut self, kind: u8, body: &[u8]) -> Result<bool> {
        match kind {
            b'S' => {
                let mut r = Cursor::new(body);
                let key = r.string()?;
                let value = r.string()?;
                r.done()?;
                if key == "client_encoding" && value != "UTF8" {
                    return Err(Error::protocol("server changed client encoding"));
                }
                if key.len() > 256
                    || value.len() > 16384
                    || self.parameters.len() >= 128 && !self.parameters.contains_key(key)
                {
                    return Err(Error::protocol("server parameter limit exceeded"));
                }
                self.parameters.insert(key.into(), value.into());
            }
            b'N' => {
                let notice = Error::database(wire::fields(body)?)?;
                if self.notices.len() == 64 {
                    self.notices.pop_front();
                }
                self.notices.push_back(notice);
            }
            b'A' => {
                let mut r = Cursor::new(body);
                let process_id = r.u32()?;
                let channel = r.string()?.into();
                let payload = r.string()?.into();
                r.done()?;
                if body.len() > 16384 || self.notifications.len() >= 256 {
                    return Err(Error::protocol("notification queue limit exceeded"));
                }
                self.notifications.push_back(Notification {
                    process_id,
                    channel,
                    payload,
                });
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
    pub fn is_closed(&self) -> bool {
        self.transport.is_none()
    }
    pub fn transaction_status(&self) -> u8 {
        self.status
    }
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameters.get(name).map(String::as_str)
    }
    pub fn pop_notification(&mut self) -> Option<Notification> {
        self.notifications.pop_front()
    }
    pub fn pop_notice(&mut self) -> Option<Error> {
        self.notices.pop_front()
    }
    pub fn cancel_token(&self) -> Result<CancelToken> {
        let (pid, key) = self.backend.ok_or_else(|| {
            Error::new(
                ErrorKind::Connection,
                "backend cancellation key unavailable",
            )
        })?;
        Ok(self
            .transport
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Connection, "connection is closed"))?
            .cancel_token(&self.config, pid, key))
    }
    pub fn close(mut self) -> Result<()> {
        self.start_operation()?;
        self.send(b'X', &[])?;
        self.flush()?;
        self.transport = None;
        Ok(())
    }
    fn extended(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)], batch: i32) -> Result<()> {
        if params.len() > 32767 || sql.len() > wire::MAX_MESSAGE / 2 {
            return Err(Error::data("query or parameter count exceeds limit"));
        }
        let parameters = params
            .iter()
            .map(|p| p.to_sql())
            .collect::<Result<Vec<_>>>()?;
        let mut parse = vec![0];
        wire::cstr(&mut parse, sql)?;
        parse.extend_from_slice(&(parameters.len() as u16).to_be_bytes());
        for p in &parameters {
            parse.extend_from_slice(&p.oid.to_be_bytes());
        }
        let mut bind = vec![0, 0];
        bind.extend_from_slice(&(parameters.len() as u16).to_be_bytes());
        for p in &parameters {
            bind.extend_from_slice(&p.format.to_be_bytes());
        }
        bind.extend_from_slice(&(parameters.len() as u16).to_be_bytes());
        for p in parameters {
            match p.value {
                None => bind.extend_from_slice(&(-1i32).to_be_bytes()),
                Some(bytes) => {
                    if bytes.len() > wire::MAX_MESSAGE
                        || bind.len() + bytes.len() > wire::MAX_MESSAGE - 4
                    {
                        return Err(Error::data("parameter data exceeds limit"));
                    }
                    bind.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                    bind.extend_from_slice(&bytes);
                }
            }
        }
        bind.extend_from_slice(&0u16.to_be_bytes());
        // Build and validate every frame before any query bytes leave the process.
        let mut packet = wire::message(b'P', &parse)?;
        packet.extend(wire::message(b'B', &bind)?);
        packet.extend(wire::message(b'D', &[b'P', 0])?);
        let mut execute = vec![0];
        execute.extend_from_slice(&batch.to_be_bytes());
        packet.extend(wire::message(b'E', &execute)?);
        packet.extend(wire::message(b'H', &[])?);
        self.start_operation()?;
        let result = self.transport()?.write_all(&packet).map_err(Error::from);
        self.guard(result)?;
        self.flush()
    }
    pub fn query_stream<'a>(
        &'a mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
        batch_size: u32,
    ) -> Result<RowStream<'a>> {
        if !(1..=10000).contains(&batch_size) {
            return Err(Error::data("stream batch size must be 1..10000"));
        }
        self.extended(sql, params, batch_size as i32)?;
        Ok(RowStream {
            client: self,
            columns: None,
            batch: batch_size,
            stage: 0,
            done: false,
            command: None,
            frames: 0,
            rows: 0,
        })
    }
    pub fn query(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Row>> {
        let mut stream = self.query_stream(sql, params, 256)?;
        let mut rows = Vec::new();
        let mut bytes = 0;
        for row in stream.by_ref() {
            let row = row?;
            bytes += row.values.iter().flatten().map(Vec::len).sum::<usize>();
            if rows.len() >= wire::MAX_ROWS || bytes > wire::MAX_RESULT {
                return Err(Error::data(
                    "result exceeds bounded query limit; use query_stream",
                ));
            }
            rows.push(row);
        }
        Ok(rows)
    }
    pub fn query_one(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Row> {
        let mut rows = self.query(sql, params)?;
        if rows.len() != 1 {
            return Err(Error::data("query must return exactly one row"));
        }
        Ok(rows.remove(0))
    }
    pub fn query_opt(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Option<Row>> {
        let mut rows = self.query(sql, params)?;
        if rows.len() > 1 {
            return Err(Error::data("query returned more than one row"));
        }
        Ok(rows.pop())
    }
    pub fn execute(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<u64> {
        let mut stream = self.query_stream(sql, params, 256)?;
        for row in stream.by_ref() {
            row?;
        }
        Ok(stream.command.as_ref().map_or(0, |r| r.rows_affected))
    }
    pub fn batch_execute(&mut self, sql: &str) -> Result<()> {
        let mut body = Vec::new();
        wire::cstr(&mut body, sql)?;
        self.start_operation()?;
        self.send(b'Q', &body)?;
        self.flush()?;
        let result = (|| {
            let mut error = None;
            let mut columns = None;
            let mut bytes = 0usize;
            let mut frames = 0;
            loop {
                let (kind, body) = self.receive()?;
                bytes += body.len();
                frames += 1;
                if bytes > wire::MAX_RESULT || frames > 200000 {
                    return Err(Error::protocol("batch response limit exceeded"));
                }
                if self.asynchronous(kind, &body)? {
                    continue;
                }
                match kind {
                    b'T' if error.is_none() && columns.is_none() => {
                        columns = Some(types::columns(&body)?)
                    }
                    b'D' if error.is_none() => {
                        types::row(
                            &body,
                            columns
                                .clone()
                                .ok_or_else(|| Error::protocol("row without description"))?,
                        )?;
                    }
                    b'C' if error.is_none() => {
                        command(&body)?;
                        columns = None;
                    }
                    b'I' if error.is_none() && body.is_empty() => {}
                    b'E' if error.is_none() => {
                        let e = Error::database(wire::fields(&body)?)?;
                        if e.is_fatal() {
                            return Err(e);
                        }
                        error = Some(e);
                    }
                    b'Z' => {
                        self.ready(&body)?;
                        return error.map_or(Ok(()), Err);
                    }
                    _ => return Err(Error::protocol("unexpected batch response")),
                }
            }
        })();
        self.guard(result)
    }
    pub fn transaction(&mut self) -> Result<Transaction<'_>> {
        self.build_transaction().start()
    }
    pub fn build_transaction(&mut self) -> TransactionBuilder<'_> {
        TransactionBuilder {
            client: self,
            isolation: IsolationLevel::ReadCommitted,
            read_only: false,
        }
    }
    /// Atomic repeated execution. Parameters stay separate from SQL; a failure rolls back the batch.
    pub fn execute_many(&mut self, sql: &str, sets: &[&[&(dyn ToSql + Sync)]]) -> Result<u64> {
        let mut tx = self.transaction()?;
        let mut total = 0u64;
        for params in sets {
            total = total
                .checked_add(tx.execute(sql, params)?)
                .ok_or_else(|| Error::data("affected row count overflow"))?;
        }
        tx.commit()?;
        Ok(total)
    }
    fn sync(&mut self, pending: Option<Error>) -> Result<()> {
        self.send(b'S', &[])?;
        self.flush()?;
        let mut error = pending;
        for _ in 0..1024 {
            let (kind, body) = self.receive()?;
            if self.asynchronous(kind, &body)? {
                continue;
            }
            match kind {
                b'Z' => {
                    self.ready(&body)?;
                    return error.map_or(Ok(()), Err);
                }
                b'E' if error.is_none() => {
                    let e = Error::database(wire::fields(&body)?)?;
                    if e.is_fatal() {
                        return Err(e);
                    }
                    error = Some(e);
                }
                _ => return Err(Error::protocol("unexpected synchronization response")),
            }
        }
        Err(Error::protocol("synchronization response limit exceeded"))
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        if let Some(t) = &mut self.transport {
            t.deadline(Duration::from_millis(50));
            if let Ok(message) = wire::message(b'X', &[]) {
                let _ = t.write_all(&message);
                let _ = t.flush();
            }
        }
    }
}
fn command(body: &[u8]) -> Result<CommandResult> {
    let mut r = Cursor::new(body);
    let tag = r.string()?.to_string();
    r.done()?;
    if tag.len() > 256 || tag.is_empty() {
        return Err(Error::protocol("invalid command tag"));
    }
    let words = tag.split(' ').collect::<Vec<_>>();
    let rows_affected = if [
        "INSERT", "UPDATE", "DELETE", "SELECT", "MOVE", "FETCH", "COPY", "MERGE",
    ]
    .contains(&words[0])
    {
        words
            .last()
            .unwrap()
            .parse()
            .map_err(|_| Error::protocol("invalid affected row count"))?
    } else {
        0
    };
    Ok(CommandResult { tag, rows_affected })
}

/// Incremental unnamed-portal results. Dropping an unfinished stream closes the connection,
/// so unread writes cannot be accidentally committed and pooled as an idle connection.
pub struct RowStream<'a> {
    client: &'a mut Client,
    columns: Option<Arc<Vec<types::Column>>>,
    batch: u32,
    stage: u8,
    done: bool,
    command: Option<CommandResult>,
    frames: usize,
    rows: u64,
}
impl RowStream<'_> {
    pub fn command(&self) -> Option<&CommandResult> {
        self.command.as_ref()
    }
    pub fn finish(mut self) -> Result<CommandResult> {
        for row in self.by_ref() {
            row?;
        }
        Ok(self.command.take().unwrap_or_default())
    }
    fn next_row(&mut self) -> Result<Option<Row>> {
        loop {
            let (kind, body) = self.client.receive()?;
            self.frames += 1;
            if self.frames > self.batch as usize + 2048 {
                return Err(Error::protocol("stream response limit exceeded"));
            }
            if self.client.asynchronous(kind, &body)? {
                continue;
            }
            match kind {
                b'1' if self.stage == 0 && body.is_empty() => self.stage = 1,
                b'2' if self.stage == 1 && body.is_empty() => self.stage = 2,
                b'T' if self.stage == 2 => {
                    self.columns = Some(types::columns(&body)?);
                    self.stage = 3;
                }
                b'n' if self.stage == 2 && body.is_empty() => self.stage = 3,
                b'D' if self.stage == 3 => {
                    self.rows = self
                        .rows
                        .checked_add(1)
                        .ok_or_else(|| Error::protocol("stream row count overflow"))?;
                    return Ok(Some(types::row(
                        &body,
                        self.columns
                            .clone()
                            .ok_or_else(|| Error::protocol("row without description"))?,
                    )?));
                }
                b's' if self.stage == 3 && self.columns.is_some() && body.is_empty() => {
                    self.frames = 0;
                    self.client.start_operation()?;
                    let mut execute = vec![0];
                    execute.extend_from_slice(&self.batch.to_be_bytes());
                    self.client.send(b'E', &execute)?;
                    self.client.send(b'H', &[])?;
                    self.client.flush()?;
                }
                b'C' if self.stage == 3 => {
                    let mut completed = command(&body)?;
                    completed.rows_affected = completed.rows_affected.max(self.rows);
                    self.command = Some(completed);
                    let result = self.client.sync(None);
                    self.done = true;
                    result?;
                    return Ok(None);
                }
                b'I' if self.stage == 3 && body.is_empty() => {
                    let result = self.client.sync(None);
                    self.done = true;
                    result?;
                    return Ok(None);
                }
                b'E' => {
                    let error = Error::database(wire::fields(&body)?)?;
                    if error.is_fatal() {
                        return Err(error);
                    }
                    let result = self.client.sync(Some(error));
                    self.done = true;
                    result?;
                    return Ok(None);
                }
                _ => return Err(Error::protocol("unexpected extended query response")),
            }
        }
    }
}
impl Iterator for RowStream<'_> {
    type Item = Result<Row>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.next_row() {
            Ok(Some(row)) => Some(Ok(row)),
            Ok(None) => None,
            Err(e) => {
                if e.is_fatal() || !self.done {
                    self.client.transport = None;
                }
                self.done = true;
                Some(Err(e))
            }
        }
    }
}
impl Drop for RowStream<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.client.transport = None;
        }
    }
}

pub struct TransactionBuilder<'a> {
    client: &'a mut Client,
    isolation: IsolationLevel,
    read_only: bool,
}
impl<'a> TransactionBuilder<'a> {
    pub fn isolation_level(mut self, value: IsolationLevel) -> Self {
        self.isolation = value;
        self
    }
    pub fn read_only(mut self, value: bool) -> Self {
        self.read_only = value;
        self
    }
    pub fn start(self) -> Result<Transaction<'a>> {
        if self.client.status != b'I' {
            return Err(Error::new(
                ErrorKind::Transaction,
                "use Transaction::transaction for a nested savepoint",
            ));
        }
        self.client.batch_execute(&format!(
            "BEGIN ISOLATION LEVEL {} {}",
            self.isolation.sql(),
            if self.read_only {
                "READ ONLY"
            } else {
                "READ WRITE"
            }
        ))?;
        Ok(Transaction {
            client: self.client,
            savepoint: None,
            finished: false,
        })
    }
}
pub struct Transaction<'a> {
    client: &'a mut Client,
    savepoint: Option<String>,
    finished: bool,
}
impl std::ops::Deref for Transaction<'_> {
    type Target = Client;
    fn deref(&self) -> &Client {
        self.client
    }
}
impl std::ops::DerefMut for Transaction<'_> {
    fn deref_mut(&mut self) -> &mut Client {
        self.client
    }
}
impl Transaction<'_> {
    pub fn transaction(&mut self) -> Result<Transaction<'_>> {
        self.client.savepoint = self
            .client
            .savepoint
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::Transaction, "savepoint counter exhausted"))?;
        let name = format!("lazaret_sp_{}", self.client.savepoint);
        self.client.batch_execute(&format!("SAVEPOINT {name}"))?;
        Ok(Transaction {
            client: self.client,
            savepoint: Some(name),
            finished: false,
        })
    }
    pub fn commit(mut self) -> Result<()> {
        if self.client.status == b'E' {
            return Err(Error::new(
                ErrorKind::Transaction,
                "transaction is aborted; rollback required",
            ));
        }
        let sql = self
            .savepoint
            .as_ref()
            .map_or_else(|| "COMMIT".into(), |n| format!("RELEASE SAVEPOINT {n}"));
        let stream = self.client.query_stream(&sql, &[], 1)?;
        let result = stream.finish();
        self.finished = true;
        match result {
            Ok(c) if c.tag == "ROLLBACK" => {
                Err(Error::new(ErrorKind::Transaction, "COMMIT rolled back"))
            }
            Ok(_) => Ok(()),
            Err(e) => {
                if self.client.status != b'I' && self.savepoint.is_none() {
                    self.client.transport = None;
                }
                Err(e)
            }
        }
    }
    pub fn rollback(mut self) -> Result<()> {
        let result = self.rollback_inner();
        self.finished = true;
        result
    }
    fn rollback_inner(&mut self) -> Result<()> {
        let sql = self.savepoint.as_ref().map_or_else(
            || "ROLLBACK".into(),
            |n| format!("ROLLBACK TO SAVEPOINT {n}; RELEASE SAVEPOINT {n}"),
        );
        let result = self.client.batch_execute(&sql);
        if result.is_err() {
            self.client.transport = None;
        }
        result
    }
}
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.rollback_inner();
        }
    }
}
