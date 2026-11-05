use crate::error::{Result, ensure};
use crate::{
    app::App,
    config::secret,
    net::Wire,
    store::{KV, META, Store},
    witness,
};
use pratique::crypto::sha2::{Hash, Sha256};
use redb::{ReadableDatabase, ReadableTable};
use std::{fs, net::TcpListener, sync::Arc, time::Duration};
const FRAME: usize = crate::replication_codec::MAX_ENCODED_BYTES;
fn frame(w: &mut Wire, b: &[u8]) -> Result<()> {
    ensure!(b.len() <= FRAME, "frame too large");
    w.bytes(&(b.len() as u32).to_be_bytes())?;
    w.bytes(b)
}
fn read_frame(w: &mut Wire) -> Result<Vec<u8>> {
    let mut n = [0; 4];
    w.exact(&mut n)?;
    let n = u32::from_be_bytes(n) as usize;
    ensure!(n <= FRAME, "frame too large");
    let mut b = vec![0; n];
    w.exact(&mut b)?;
    Ok(b)
}
fn authorized(app: &App, node: &str, term: u64) -> Result<()> {
    ensure!(!app.primary(), "cannot overwrite current primary");
    ensure!(
        witness::holder(&app.config)? == Some((node.into(), term)),
        "source no longer holds lease"
    );
    Ok(())
}
pub fn listen(app: Arc<App>) -> Result<()> {
    let listener = TcpListener::bind(&app.config.replication.listen)?;
    for tcp in listener.incoming() {
        let tcp = tcp?;
        let result = crate::resilience::boundary("replication receive", || -> Result<()> {
            let mut w = Wire::accept(tcp, &app.tls)?;
            w.deadline.set(Duration::from_secs(10));
            let line = w.text(2048)?;
            let p: Vec<_> = line.split_whitespace().collect();
            ensure!(
                p.len() == 5
                    && p[0] == "SYNC"
                    && witness::same(p[1], &secret(&app.config.replication.token_file)?)
                    && p[2] == app.config.replication.cluster_id,
                "unauthorized replication"
            );
            let term: u64 = p[4].parse()?;
            authorized(&app, p[3], term)?;
            {
                let s = app.read_store()?;
                w.send(&format!("STATE {} {}\r\n", s.meta("term")?, s.seq()?))?;
            }
            let command = w.text(128)?;
            let parts: Vec<_> = command.split_whitespace().collect();
            ensure!(parts.len() == 2, "bad sync command");
            let seq: u64 = parts[1].parse()?;
            let _lock = app.writes.lock().unwrap_or_else(|e| e.into_inner());
            authorized(&app, p[3], term)?;
            if parts[0] == "SNAPSHOT" {
                w.deadline.set(Duration::from_secs(120));
                let temp = std::path::Path::new(&app.config.data_dir).join("incoming.redb");
                if temp.exists() {
                    fs::remove_file(&temp)?;
                }
                let incoming = Store::open(&temp, &app.config.replication.cluster_id)?;
                let mut total = 0u64;
                let mut digest = Sha256::new();
                loop {
                    let k = read_frame(&mut w)?;
                    if k.is_empty() {
                        break;
                    }
                    ensure!(k.len() <= 1024, "key too long");
                    let key = std::str::from_utf8(&k)?;
                    let v = read_frame(&mut w)?;
                    total += k.len() as u64 + v.len() as u64;
                    ensure!(total <= 10 * 1024 * 1024 * 1024, "snapshot exceeds 10 GiB");
                    digest.update(&(k.len() as u32).to_be_bytes());
                    digest.update(&k);
                    digest.update(&(v.len() as u32).to_be_bytes());
                    digest.update(&v);
                    ensure!(
                        key != "cluster" || v == app.config.replication.cluster_id.as_bytes(),
                        "snapshot cluster mismatch"
                    );
                    let tx = incoming.db.begin_write()?;
                    {
                        tx.open_table(KV)?.insert(key, v.as_slice())?;
                    }
                    tx.commit()?;
                }
                let mut expected = [0; 32];
                w.exact(&mut expected)?;
                ensure!(
                    digest.finalize()[..] == expected,
                    "snapshot checksum mismatch"
                );
                authorized(&app, p[3], term)?;
                incoming.set_meta("deployment", 2)?;
                incoming.set_meta("term", term)?;
                incoming.set_meta("seq", seq)?;
                incoming.set_meta("ready", 1)?;
                let mut current = app.write_store()?;
                let path = std::path::Path::new(&app.config.data_dir).join("mail.redb");
                // Keep the previous database intact: an old primary can contain an unreplicated tail.
                let saved = std::path::Path::new(&app.config.data_dir)
                    .join(format!("recovery-{}.redb", crate::store::random_id()));
                fs::hard_link(&path, &saved)?;
                fs::rename(&temp, &path)?;
                fs::File::open(&app.config.data_dir)?.sync_all()?;
                *current = incoming;
                eprintln!(
                    "replica seeded at term={term} seq={seq}; previous database saved at {}",
                    saved.display()
                );
            } else if parts[0] == "ENTRY" {
                let bytes = read_frame(&mut w)?;
                authorized(&app, p[3], term)?;
                let s = app.read_store()?;
                ensure!(s.meta("term")? == term, "term mismatch");
                s.replay(seq, &bytes)?;
            } else if parts[0] != "PING" {
                crate::bail!("unknown sync command");
            }
            w.send(&format!("ACK {seq}\r\n"))?;
            *app.replication_status
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = crate::app::ReplicationStatus {
                last_contact: Some(crate::datetime::Utc::now()?.timestamp()),
                peer_sequence: Some(seq),
                term: Some(term),
                last_error: None,
                direction: Some("receiving".into()),
            };
            Ok(())
        });
        if let Err(e) = result {
            eprintln!("replication receive: {e}");
        }
    }
    Ok(())
}
fn sync_once(app: &App) -> Result<()> {
    app.require_primary()?;
    let term = app.current_lease().term;
    let c = &app.config;
    let mut w = Wire::connect(
        c.replication.peer_address.parse()?,
        &c.replication.peer_name,
        &c.replication.ca_file,
    )?;
    w.deadline.set(Duration::from_secs(10));
    w.send(&format!(
        "SYNC {} {} {} {term}\r\n",
        secret(&c.replication.token_file)?,
        c.replication.cluster_id,
        c.node_id()
    ))?;
    let line = w.text(128)?;
    let p: Vec<_> = line.split_whitespace().collect();
    ensure!(p.len() == 3 && p[0] == "STATE", "invalid replica state");
    let peer_term: u64 = p[1].parse()?;
    let peer_seq: u64 = p[2].parse()?;
    let s = app.read_store()?;
    let local_seq = s.seq()?;
    let next = if peer_seq < local_seq {
        s.log(peer_seq + 1)?
    } else {
        None
    };
    let sent;
    if peer_term != term || peer_seq > local_seq || (peer_seq < local_seq && next.is_none()) {
        w.deadline.set(Duration::from_secs(120));
        let tx = s.db.begin_read()?;
        let meta = tx.open_table(META)?;
        sent = meta.get("seq")?.unwrap().value();
        w.send(&format!("SNAPSHOT {sent}\r\n"))?;
        let mut digest = Sha256::new();
        for row in tx.open_table(KV)?.iter()? {
            app.require_primary()?;
            let (k, v) = row?;
            let kb = k.value().as_bytes();
            let vb = v.value();
            digest.update(&(kb.len() as u32).to_be_bytes());
            digest.update(kb);
            digest.update(&(vb.len() as u32).to_be_bytes());
            digest.update(vb);
            frame(&mut w, kb)?;
            frame(&mut w, vb)?;
        }
        frame(&mut w, &[])?;
        w.bytes(&digest.finalize())?;
    } else if let Some(bytes) = next {
        sent = peer_seq + 1;
        w.send(&format!("ENTRY {sent}\r\n"))?;
        frame(&mut w, &bytes)?;
    } else {
        sent = local_seq;
        w.send(&format!("PING {sent}\r\n"))?;
    }
    let ack = w.text(128)?;
    ensure!(
        ack == format!("ACK {sent}"),
        "invalid replication acknowledgment"
    );
    *app.replication_status
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = crate::app::ReplicationStatus {
        last_contact: Some(crate::datetime::Utc::now()?.timestamp()),
        peer_sequence: Some(sent),
        term: Some(term),
        last_error: None,
        direction: Some("sending".into()),
    };
    // Retain a small recent tail; missing history is recovered by a fresh consistent snapshot.
    if sent > 128 {
        s.prune(sent - 128)?;
    }
    Ok(())
}
pub fn send_loop(app: Arc<App>) {
    let mut failures = 0u32;
    loop {
        if app.primary() {
            if let Err(e) = crate::resilience::boundary("replication send", || sync_once(&app)) {
                app.replication_status
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .last_error = Some(e.to_string());
                failures = failures.saturating_add(1);
                if failures == 1 || failures.is_multiple_of(30) {
                    eprintln!("replica unavailable (local acceptance continues): {e}");
                }
            } else {
                failures = 0;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
