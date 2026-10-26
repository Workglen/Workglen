//! Integrated first-party bounded ZIP reader, hardened for complete email-attachment inspection.
use std::borrow::Cow;
use std::cell::RefCell;

use pratique::inflate::{Format, Limits, decode_all};

/// One entry of the central directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub crc: u32,
    pub attributes: u32,
    pub directory_start: u64,
    pub name: Vec<u8>,
    pub flags: u16,
    pub method: u16,
    pub csize: u64,
    pub size: u64,
    /// where its local header is
    pub local: u64,
    /// its extra field's length in the central directory (a local header's is most often the same, or a little more)
    pub xlen: u16,
}

/// Why bytes could not be had: not given yet (noted as needed), or why the archive cannot be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Miss {
    Need,
    Bad(String),
}

impl From<String> for Miss {
    fn from(s: String) -> Miss {
        Miss::Bad(s)
    }
}

impl From<&str> for Miss {
    fn from(s: &str) -> Miss {
        Miss::Bad(s.to_string())
    }
}

/// The bytes past a stored entry's local header the reader asks for with the header, beyond the central directory's
/// name and extra field: a local extra field may be longer (PyTorch's writer pads the data to 64 bytes there).
const LOCAL_SLACK: u64 = 1024;
/// An .npy member's stored bytes read for its header: enough for the first 64 KiB, stored or deflated.
pub const PREFIX_RAW: u64 = 1 << 17;

/// A file's bytes as a reading has them: the whole file, or pieces of it.
pub struct Bytes<'d> {
    pub size: u64,
    /// (offset, bytes), sorted, none overlapping or touching another
    pieces: Vec<(u64, Cow<'d, [u8]>)>,
    given: u64,
    /// the ranges a reading asked for that are not here
    need: RefCell<Vec<(u64, u64)>>,
    needed: RefCell<u64>,
    /// the most bytes, given and asked for, a reading reads of the file
    cap: u64,
}

impl<'d> Bytes<'d> {
    /// The whole file.
    pub fn whole(data: &'d [u8]) -> Bytes<'d> {
        Bytes {
            size: data.len() as u64,
            pieces: vec![(0, Cow::Borrowed(data))],
            given: data.len() as u64,
            need: RefCell::new(Vec::new()),
            needed: RefCell::new(0),
            cap: u64::MAX,
        }
    }

    /// Pieces of a file of `size` bytes ((offset, bytes), in any order, overlapping or not; a piece past the end is cut
    /// there), of which a reading reads at most `cap` bytes in all.
    pub fn pieces(size: u64, mut given: Vec<(u64, &'d [u8])>, cap: u64) -> Bytes<'d> {
        given.retain(|(off, b)| *off < size && !b.is_empty());
        given.sort_by_key(|&(off, b)| (off, std::cmp::Reverse(b.len())));
        let mut pieces: Vec<(u64, Cow<'d, [u8]>)> = Vec::new();
        for (off, b) in given {
            let b = &b[..b.len().min((size - off).min(usize::MAX as u64) as usize)];
            let end = off + b.len() as u64;
            match pieces.last_mut() {
                Some((lo, have)) if off <= *lo + have.len() as u64 => {
                    let have_end = *lo + have.len() as u64;
                    if end > have_end {
                        let mut v = have.to_vec();
                        v.extend_from_slice(&b[(have_end - off) as usize..]);
                        *have = Cow::Owned(v);
                    }
                }
                _ => pieces.push((off, Cow::Borrowed(b))),
            }
        }
        let total = pieces.iter().map(|(_, b)| b.len() as u64).sum();
        Bytes {
            size,
            pieces,
            given: total,
            need: RefCell::new(Vec::new()),
            needed: RefCell::new(0),
            cap,
        }
    }

    /// Bytes [off, off + len) when they are here (none past the file's end).
    pub fn peek(&self, off: u64, len: u64) -> Option<&[u8]> {
        let end = off.checked_add(len).filter(|&e| e <= self.size)?;
        let k = self
            .pieces
            .partition_point(|(o, _)| *o <= off)
            .checked_sub(1)?;
        let (o, b) = &self.pieces[k];
        if end > o + b.len() as u64 {
            return None;
        }
        let s = (off - o) as usize;
        Some(&b[s..s + len as usize])
    }

    /// Bytes [off, off + len): `past` (why the archive cannot be read) when they run past the file's end, Need when
    /// they are not here (noted), or the reading's bound when they would take it past what it reads.
    pub fn get(&self, off: u64, len: u64, past: &str) -> Result<&[u8], Miss> {
        if off.checked_add(len).is_none_or(|e| e > self.size) {
            return Err(Miss::Bad(past.to_string()));
        }
        if let Some(b) = self.peek(off, len) {
            return Ok(b);
        }
        self.note(off, len)?;
        Err(Miss::Need)
    }

    /// Ask for bytes [off, off + len) (cut at the file's end), within the reading's bound.
    pub fn note(&self, off: u64, len: u64) -> Result<(), Miss> {
        let len = len.min(self.size.saturating_sub(off));
        let mut needed = self.needed.borrow_mut();
        if self.given.saturating_add(*needed).saturating_add(len) > self.cap {
            return Err(Miss::Bad(format!(
                "it would take reading more than the {} bytes read of a model file",
                self.cap
            )));
        }
        *needed += len;
        self.need.borrow_mut().push((off, len));
        Ok(())
    }

    /// The ranges a reading asked for and was not given: (offset, length), sorted, merged.
    pub fn needs(&self) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self
            .need
            .borrow()
            .iter()
            .copied()
            .filter(|r| r.1 > 0)
            .collect();
        v.sort();
        let mut out: Vec<(u64, u64)> = Vec::new();
        for (off, len) in v {
            match out.last_mut() {
                Some((o, l)) if off <= *o + *l => *l = (*l).max(off + len - *o),
                _ => out.push((off, len)),
            }
        }
        out
    }
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?))
}

/// The name of the first member the local headers hold (the archive's first file as it was written; a few folder
/// entries before it, which a tool that zips a folder again writes, passed over), if the bytes start with one: what a
/// sniff of a file's first bytes can tell.
pub fn first_local_name(head: &[u8]) -> Option<&[u8]> {
    let mut at = 0usize;
    for _ in 0..8 {
        if head.get(at..at + 4) != Some(b"PK\x03\x04") {
            return None;
        }
        let n = u16_at(head, at + 26)? as usize;
        let x = u16_at(head, at + 28)? as usize;
        let name = head.get(at + 30..at + 30 + n)?;
        let size = u32_at(head, at + 18)?;
        let flags = u16_at(head, at + 6)?;
        if !(name.ends_with(b"/") && size == 0 && flags & 8 == 0) {
            return Some(name);
        }
        at += 30 + n + x;
    }
    None
}

/// The central directory's entries, in its order (at most `max`, in at most `max_dir` bytes; more is an error), or
/// why it cannot be read. Prefixed archives are refused. The archive has its
/// offsets moved by them. Its entries are read within the directory's declared size, within declared directory bounds.
pub fn entries(src: &Bytes, max: usize, max_dir: u64) -> Result<Vec<Entry>, Miss> {
    // the end of central directory record: within the last 65,535 + 22 bytes
    let lo = src.size.saturating_sub(65_535 + 22);
    let window = src.get(lo, src.size - lo, "")?;
    let mut eocd = None;
    let mut i = window.len().saturating_sub(22);
    loop {
        if window[i..].starts_with(b"PK\x05\x06") {
            eocd = Some(i);
            break;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    let e = eocd.ok_or("no end of central directory record")?;
    let bad = || "a truncated end of central directory record".to_string();
    let mut count = u16_at(window, e + 10).ok_or_else(bad)? as u64;
    let mut cd_size = u32_at(window, e + 12).ok_or_else(bad)? as u64;
    let mut cd_off = u32_at(window, e + 16).ok_or_else(bad)? as u64;
    if u16_at(window, e + 4) != Some(0)
        || u16_at(window, e + 6) != Some(0)
        || u16_at(window, e + 8) != Some(count as u16)
    {
        return Err("multi-disk ZIP is not supported".into());
    }
    let comment = u16_at(window, e + 20).ok_or_else(bad)? as usize;
    if e + 22 + comment != window.len() {
        return Err("trailing or truncated ZIP end record".into());
    }
    let e = lo + e as u64; // (where the record is in the file)
    let mut cd_end = e;
    if count == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_off == 0xFFFF_FFFF {
        // zip64: the locator just before the record names the zip64 end of central directory record
        let loc = e
            .checked_sub(20)
            .ok_or("a zip64 archive without its locator")?;
        let l = src.get(loc, 20, "a zip64 archive without its locator")?;
        if !l.starts_with(b"PK\x06\x07") {
            return Err("a zip64 archive without its locator".into());
        }
        if u32_at(l, 4) != Some(0) || u32_at(l, 16) != Some(1) {
            return Err("multi-disk ZIP64 archive".into());
        }
        let z = u64_at(l, 8).ok_or("a truncated zip64 locator")?;
        if z >= src.size {
            return Err("a zip64 record past the archive's end".into());
        }
        let r = src.get(z, 56.min(src.size - z), "a truncated zip64 record")?;
        if r.get(..4) != Some(b"PK\x06\x06") {
            return Err("a zip64 end of central directory record that is not one".into());
        }
        if u64_at(r, 4) != Some(44)
            || z.checked_add(56) != Some(loc)
            || u32_at(r, 16) != Some(0)
            || u32_at(r, 20) != Some(0)
            || u64_at(r, 24) != u64_at(r, 32)
        {
            return Err("unsupported or conflicting ZIP64 end record".into());
        }
        count = u64_at(r, 32).ok_or("a truncated zip64 record")?;
        cd_size = u64_at(r, 40).ok_or("a truncated zip64 record")?;
        cd_off = u64_at(r, 48).ok_or("a truncated zip64 record")?;
        cd_end = z;
    }
    if count > max as u64 {
        return Err(format!("{count} entries, more than the {max} read").into());
    }
    let start = cd_end
        .checked_sub(cd_size)
        .ok_or("a central directory larger than the archive")?;
    let concat = start
        .checked_sub(cd_off)
        .ok_or("a central directory before its offset")?;
    if concat != 0 {
        return Err("prefixed or self-extracting archive".into());
    }
    if cd_size > max_dir {
        return Err(format!(
            "a central directory of {} bytes, more than the {} read",
            cd_size, max_dir
        )
        .into());
    }
    let cd = src.get(
        start,
        cd_size,
        "a central directory larger than the archive",
    )?;
    let mut out = Vec::with_capacity(count.min(4096) as usize);
    let mut at = 0usize;
    for _ in 0..count {
        if cd.get(at..at + 4) != Some(b"PK\x01\x02") {
            return Err("a central directory entry that is not one".into());
        }
        let short = || "a truncated central directory entry".to_string();
        let flags = u16_at(cd, at + 8).ok_or_else(short)?;
        let method = u16_at(cd, at + 10).ok_or_else(short)?;
        let mut csize = u32_at(cd, at + 20).ok_or_else(short)? as u64;
        let mut size = u32_at(cd, at + 24).ok_or_else(short)? as u64;
        let nlen = u16_at(cd, at + 28).ok_or_else(short)? as usize;
        let xlen = u16_at(cd, at + 30).ok_or_else(short)?;
        let clen = u16_at(cd, at + 32).ok_or_else(short)? as usize;
        let mut local = u32_at(cd, at + 42).ok_or_else(short)? as u64;
        let name = cd.get(at + 46..at + 46 + nlen).ok_or_else(short)?.to_vec();
        let extra = cd
            .get(at + 46 + nlen..at + 46 + nlen + xlen as usize)
            .ok_or_else(short)?;
        // the zip64 extra field: the sizes and the offset that did not fit, in that order
        let mut x = 0;
        while x + 4 <= extra.len() {
            let id = u16_at(extra, x).unwrap_or(0);
            let len = u16_at(extra, x + 2).unwrap_or(0) as usize;
            let body = extra.get(x + 4..x + 4 + len).unwrap_or(&[]);
            if id == 1 {
                let mut k = 0;
                let mut take = |v: &mut u64| {
                    if *v == 0xFFFF_FFFF
                        && let Some(n) = u64_at(body, k)
                    {
                        *v = n;
                        k += 8;
                    }
                };
                take(&mut size);
                take(&mut csize);
                take(&mut local);
            }
            x += 4 + len;
        }
        if u16_at(cd, at + 34) != Some(0) {
            return Err("multi-disk entry".into());
        }
        let crc = u32_at(cd, at + 16).ok_or_else(short)?;
        let attributes = u32_at(cd, at + 38).ok_or_else(short)?;
        out.push(Entry {
            name,
            flags,
            method,
            csize,
            size,
            local: local.saturating_add(concat),
            xlen,
            crc,
            attributes,
            directory_start: start,
        });
        at += 46 + nlen + xlen as usize + clen;
    }
    if at != cd.len() {
        return Err("unread central-directory content".into());
    }
    Ok(out)
}

/// The first `want` of an entry's stored or compressed bytes (after its local header), or why they cannot be had.
/// `fetch`: the most of them asked for when they are not here (a reading's bound: more is an error).
fn raw<'a>(
    src: &'a Bytes,
    e: &Entry,
    want: u64,
    fetch: u64,
    too_many: impl Fn() -> String,
) -> Result<&'a [u8], Miss> {
    if e.flags & (1 | 64 | 8192) != 0 {
        return Err("it is encrypted".into());
    }
    let wrong = "its local header is not where the central directory says";
    if e.local >= src.size {
        return Err(wrong.into());
    }
    let room = src.size - e.local;
    let hdr = match src.peek(e.local, 30.min(room)) {
        Some(h) => h,
        None => {
            // the header and the bytes after it, in one range: the most often what it holds
            if want > fetch {
                return Err(Miss::Bad(too_many()));
            }
            src.note(
                e.local,
                (30 + e.name.len() as u64 + e.xlen as u64 + LOCAL_SLACK)
                    .saturating_add(want)
                    .min(room),
            )?;
            return Err(Miss::Need);
        }
    };
    if hdr.get(..4) != Some(b"PK\x03\x04") {
        return Err(wrong.into());
    }
    let nlen = u16_at(hdr, 26).ok_or("a truncated local header")? as u64;
    let xlen = u16_at(hdr, 28).ok_or("a truncated local header")? as u64;
    if u16_at(hdr, 6) != Some(e.flags) || u16_at(hdr, 8) != Some(e.method) {
        return Err("conflicting local ZIP flags or method".into());
    }
    let name = src.get(e.local + 30, nlen, "missing local member name")?;
    if name != e.name {
        return Err("conflicting ZIP member names".into());
    }
    if e.flags & 8 == 0
        && (u32_at(hdr, 14) != Some(e.crc)
            || (u32_at(hdr, 18) != Some(e.csize as u32) && e.csize <= u32::MAX as u64)
            || (u32_at(hdr, 22) != Some(e.size as u32) && e.size <= u32::MAX as u64))
    {
        return Err("conflicting local ZIP sizes or checksum".into());
    }
    let start = e.local + 30 + nlen + xlen;
    if start.saturating_add(e.csize) > e.directory_start {
        return Err("ZIP member overlaps directory".into());
    }
    if start > src.size || e.csize > src.size - start {
        return Err("an entry past the archive's end".into());
    }
    let want = want.min(e.csize);
    if src.peek(start, want).is_none() && want > fetch {
        return Err(Miss::Bad(too_many()));
    }
    src.get(start, want, "an entry past the archive's end")
}

/// An entry's first `n` bytes, decompressed (fewer when it is shorter). Its first PREFIX_RAW stored bytes are read
/// for them, and all of them (at most `fetch` asked for) when those hold fewer and the entry goes on: deflate's empty
/// blocks hold nothing.
pub fn read_prefix(src: &Bytes, e: &Entry, n: usize, fetch: u64) -> Result<Vec<u8>, Miss> {
    use pratique::inflate::{Inflater, Status};
    let first = PREFIX_RAW.max(n as u64);
    let more = || format!("its first {n} bytes are not in the {fetch} bytes of it read");
    match e.method {
        0 => {
            let raw = raw(src, e, first, u64::MAX, String::new)?;
            Ok(raw[..raw.len().min(n)].to_vec())
        }
        8 => {
            // (the bytes decompressed, and whether the stream ended)
            let inflate = |raw: &[u8]| -> Result<(Vec<u8>, bool), Miss> {
                let mut inf = Inflater::new(Format::Deflate, Limits::new(u64::MAX));
                let mut out = vec![0u8; n];
                let (mut got, mut pos, mut ended) = (0usize, 0usize, false);
                while got < n {
                    let pr = inf
                        .inflate(&raw[pos..], &mut out[got..])
                        .map_err(|err| err.to_string())?;
                    pos += pr.consumed;
                    got += pr.produced;
                    if pr.status == Status::Done {
                        ended = true;
                        break;
                    }
                    if pr.status == Status::NeedInput && pr.produced == 0 && pr.consumed == 0 {
                        break;
                    }
                }
                out.truncate(got);
                Ok((out, ended))
            };
            let raw1 = raw(src, e, first, u64::MAX, String::new)?;
            let (out, ended) = inflate(raw1)?;
            if out.len() < n && !ended && (raw1.len() as u64) < e.csize {
                return Ok(inflate(raw(src, e, e.csize, fetch, more)?)?.0);
            }
            Ok(out)
        }
        m => Err(format!(
            "it is compressed with {} (method {m}), which the reader cannot decompress",
            method_name(m)
        )
        .into()),
    }
}

/// An entry's bytes, decompressed (at most `limit` of them), or why they cannot be read.
pub fn read(src: &Bytes, e: &Entry, limit: u64) -> Result<Vec<u8>, Miss> {
    let more = || format!("it holds more than the {limit} bytes read");
    if e.size > limit {
        return Err(Miss::Bad(more()));
    }
    let result = match e.method {
        0 => {
            let raw = raw(src, e, e.csize, limit, more)?;
            if raw.len() as u64 > limit {
                return Err(Miss::Bad(more()));
            }
            Ok(raw.to_vec())
        }
        8 => {
            // (deflate's bytes are at most about twice what they hold: more than that holds more than `limit`)
            let fetch = limit.saturating_mul(2).saturating_add(1 << 20);
            let raw = raw(src, e, e.csize, fetch, more)?;
            decode_all(
                Format::Deflate,
                raw,
                Limits::new(limit).with_ratio(200, 1 << 20),
            )
            .map_err(|err| Miss::Bad(err.to_string()))
        }
        m => Err(format!(
            "it is compressed with {} (method {m}), which the reader cannot decompress",
            method_name(m)
        )
        .into()),
    }?;
    if result.len() as u64 != e.size || crc32(&result) != e.crc {
        return Err("member length or checksum mismatch".into());
    }
    Ok(result)
}

pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in bytes {
        crc ^= *b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    !crc
}

fn method_name(m: u16) -> &'static str {
    match m {
        9 => "deflate64",
        12 => "bzip2",
        14 => "LZMA",
        93 => "zstd",
        95 => "xz",
        98 => "PPMd",
        99 => "AES encryption",
        _ => "an unknown method",
    }
}
