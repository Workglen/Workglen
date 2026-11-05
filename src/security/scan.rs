//! Bounded, local policy inspection. No content is executed and no network is used.
use super::{archive_zip as zip, model::*};
use crate::error::{Result, ensure};
use lazaret_archive::{
    Archive, EntryKind as ArchiveEntryKind, Error as ArchiveError, Format as ArchiveFormat,
    Limits as ArchiveLimits,
};
use pratique::json_value::{Value, json};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};
use workglen_mime::{MessageParser, MimeHeaders, PartType};
const MEMBERS: usize = 256;
const DEPTH: usize = 8;
pub const ENGINE: &str = "workglen-native-2";
#[derive(Clone, Copy)]
pub struct ScanLimits {
    pub input_bytes: usize,
    pub decoded_bytes: usize,
    pub parts: usize,
}
pub fn scan_limits(settings: &Value) -> Result<ScanLimits> {
    Ok(ScanLimits {
        input_bytes: usize::try_from(n(settings, "scan_input_bytes")?)?,
        decoded_bytes: usize::try_from(n(settings, "scan_decoded_bytes")?)?,
        parts: usize::try_from(n(settings, "scan_parts")?)?,
    })
}
#[derive(Default)]
struct Budget {
    bytes: usize,
    expanded: usize,
    members: usize,
    start: Option<Instant>,
    names: BTreeSet<String>,
    formats: BTreeSet<String>,
    reasons: BTreeSet<String>,
    texts: Vec<String>,
}
impl Budget {
    fn deadline(&mut self) -> Result<()> {
        ensure!(
            self.start.get_or_insert_with(Instant::now).elapsed() < Duration::from_secs(5),
            "Attachment processing deadline exceeded"
        );
        Ok(())
    }

    fn charge(&mut self, n: usize, depth: usize) -> Result<()> {
        self.members += 1;
        self.bytes = self.bytes.saturating_add(n);
        ensure!(
            depth <= DEPTH && self.members <= MEMBERS && self.bytes <= self.expanded,
            "Attachment expansion budget exceeded"
        );
        self.deadline()
    }
    fn issue(&mut self, why: impl Into<String>) {
        if self.reasons.len() < 32 {
            self.reasons.insert(why.into());
        }
    }
}
fn cut(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}
pub fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let c = match c {
            '\u{ff01}'..='\u{ff5e}' => char::from_u32(c as u32 - 0xfee0).unwrap_or(c),
            '\u{00a0}' => ' ',
            '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}' => continue,
            _ => c,
        };
        out.extend(c.to_lowercase());
    }
    for (a, b) in [
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#39;", "'"),
        ("&nbsp;", " "),
        ("&amp;", "&"),
    ] {
        out = out.replace(a, b);
    }
    out
}
fn member_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 1024
            && !name.chars().any(char::is_control)
            && !name.starts_with(['/', '\\'])
            && !name.contains(['\\', ':'])
            && !name.split('/').any(|x| x == ".." || x == "."),
        "Unsafe archive member path"
    );
    Ok(())
}
fn dangerous_name(name: &str) -> bool {
    let n = normalize(name).trim_end_matches([' ', '.']).to_string();
    let ext = n.rsplit('.').next().unwrap_or("");
    [
        "exe", "com", "scr", "dll", "sys", "cpl", "msi", "msp", "mst", "bat", "cmd", "ps1", "psm1",
        "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "url", "scf", "reg", "chm",
        "jar", "class", "apk", "app", "dmg", "iso", "img", "vhd", "vhdx", "sh", "bash", "zsh",
        "command", "desktop", "service", "py", "pyc", "pyo", "pl", "pm", "rb", "php", "wasm",
        "docm", "dotm", "xlsm", "xltm", "xlam", "xlsb", "pptm", "potm", "ppam", "ppsm", "sldm",
        "html", "htm", "svg", "xsl", "xslt", "pkl", "pickle", "joblib", "pt", "pth",
    ]
    .contains(&ext)
        || n.ends_with("vbaproject.bin")
        || n.contains("/activex/")
        || n.contains("/embeddings/")
        || n.contains("/macros/")
}
fn executable(b: &[u8]) -> bool {
    b.starts_with(b"MZ")
        || b.starts_with(b"\x7fELF")
        || b.starts_with(b"#!")
        || b.starts_with(b"\0asm")
        || [
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
        ]
        .iter()
        .any(|sig| b.starts_with(*sig))
}
fn serialized_payload(b: &[u8]) -> bool {
    b.len() >= 2 && b[0] == 0x80 && (2..=5).contains(&b[1])
}
fn zip_error(e: zip::Miss) -> crate::error::Error {
    crate::error::Error::msg(match e {
        zip::Miss::Need => "Incomplete ZIP content".into(),
        zip::Miss::Bad(s) => s,
    })
}
fn u16le(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .ok_or_else(|| crate::error!("Truncated ZIP field"))?
            .try_into()?,
    ))
}
fn u32le(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or_else(|| crate::error!("Truncated ZIP field"))?
            .try_into()?,
    ))
}
fn inspect_zip(b: &[u8], depth: usize, q: &mut Budget) -> Result<()> {
    q.formats.insert("zip-store/deflate".into());
    let src = zip::Bytes::whole(b);
    let mut entries =
        zip::entries(&src, MEMBERS.saturating_sub(q.members), 1024 * 1024).map_err(zip_error)?;
    entries.sort_by_key(|e| e.local);
    let mut end = 0usize;
    let mut names = BTreeSet::new();
    for e in &entries {
        let name = std::str::from_utf8(&e.name)
            .map_err(|_| crate::error!("Unsupported ZIP member name encoding"))?;
        member_name(name)?;
        ensure!(names.insert(normalize(name)), "Duplicate ZIP member name");
        ensure!(
            e.flags & !(8 | 2048 | 2 | 4) == 0,
            "Encrypted or unsupported ZIP flags"
        );
        let mode = (e.attributes >> 16) & 0xf000;
        ensure!(
            matches!(mode, 0 | 0x8000 | 0x4000),
            "Archive links or special entries are blocked"
        );
        ensure!(
            e.local == end as u64,
            "Hidden, overlapping or prefixed ZIP content"
        );
        let start = end
            .checked_add(30 + u16le(b, end + 26)? as usize + u16le(b, end + 28)? as usize)
            .ok_or_else(|| crate::error!("ZIP offset overflow"))?;
        end = start
            .checked_add(usize::try_from(e.csize)?)
            .ok_or_else(|| crate::error!("ZIP size overflow"))?;
        let data =
            zip::read(&src, e, q.expanded.saturating_sub(q.bytes) as u64).map_err(zip_error)?;
        if e.flags & 8 != 0 {
            if b.get(end..end + 4) == Some(b"PK\x07\x08") {
                end += 4;
            }
            ensure!(
                u32le(b, end)? == e.crc
                    && u32le(b, end + 4)? as u64 == e.csize
                    && u32le(b, end + 8)? as u64 == e.size,
                "Invalid or unsupported ZIP data descriptor"
            );
            end += 12;
        }
        ensure!(
            end as u64 <= e.directory_start,
            "ZIP entry overlaps directory"
        );
        if name.ends_with('/') {
            ensure!(data.is_empty(), "Directory entry contains data");
            q.charge(0, depth + 1)?;
        } else {
            inspect_file(name, &data, depth + 1, q)?;
        }
    }
    if let Some(e) = entries.first() {
        ensure!(end as u64 == e.directory_start, "Unindexed ZIP content");
    } else {
        ensure!(b.starts_with(b"PK\x05\x06"), "Hidden content in empty ZIP");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ArchiveHint {
    Exact(ArchiveFormat),
    Rar,
}

fn archive_hint(name: &str) -> Option<ArchiveHint> {
    let lower = normalize(name);
    if lower.ends_with(".tar.gz") || lower.ends_with(".tar.gzip") || lower.ends_with(".tgz") {
        return Some(ArchiveHint::Exact(ArchiveFormat::TarGzip));
    }
    let ext = lower.rsplit('.').next().unwrap_or("");
    Some(match ext {
        "tar" => ArchiveHint::Exact(ArchiveFormat::Tar),
        "gz" | "gzip" => ArchiveHint::Exact(ArchiveFormat::Gzip),
        "rar" => ArchiveHint::Rar,
        "7z" => ArchiveHint::Exact(ArchiveFormat::SevenZip),
        "bz2" | "bzip2" | "tbz" | "tbz2" => ArchiveHint::Exact(ArchiveFormat::Bzip2),
        "xz" | "txz" => ArchiveHint::Exact(ArchiveFormat::Xz),
        "lzma" => ArchiveHint::Exact(ArchiveFormat::Lzma),
        _ => return None,
    })
}

fn archive_format_name(format: ArchiveFormat) -> &'static str {
    match format {
        ArchiveFormat::Rar4 => "rar4-store",
        ArchiveFormat::Rar5 => "rar5-store",
        ArchiveFormat::Tar => "tar",
        ArchiveFormat::Gzip => "gzip",
        ArchiveFormat::TarGzip => "tar-gzip",
        ArchiveFormat::Bzip2 => "bzip2",
        ArchiveFormat::Xz => "xz-lzma2",
        ArchiveFormat::Lzma => "lzma-alone",
        ArchiveFormat::SevenZip => "7z",
        _ => "archive",
    }
}

fn archive_error(error: ArchiveError) -> crate::error::Error {
    crate::error::Error::msg(format!("Lazaret archive inspection incomplete: {error}"))
}

fn inspect_name(name: &str, q: &mut Budget) {
    if name
        .chars()
        .any(|c| c.is_control() || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}'))
    {
        q.issue("Ambiguous attachment filename");
    }
    q.names.insert(cut(&normalize(name), 256));
    if dangerous_name(name) {
        q.issue("Executable, script or prohibited active attachment");
    }
}

fn inspect_archive_entries(archive: &Archive, depth: usize, q: &mut Budget) -> Result<()> {
    q.formats.insert(archive_format_name(archive.format).into());
    if archive.is_path_ambiguous() {
        q.issue("Archive member paths are ambiguous across extractors or filesystems");
    }
    for entry in &archive.entries {
        let mut aliases = BTreeSet::new();
        if let Some(name) = &entry.windows_name {
            aliases.insert(name.as_str());
        }
        if let Some(group) = entry.collision.and_then(|i| archive.collisions.get(i)) {
            for &index in &group.entries {
                if let Some(other) = archive.entries.get(index) {
                    aliases.insert(other.name.as_str());
                    if let Some(name) = &other.windows_name {
                        aliases.insert(name.as_str());
                    }
                }
            }
        }
        for alias in aliases {
            if alias != entry.name {
                inspect_name(alias, q);
            }
        }
        match entry.kind {
            ArchiveEntryKind::File => inspect_file(&entry.name, &entry.data, depth + 1, q)?,
            ArchiveEntryKind::Directory => q.charge(0, depth + 1)?,
        }
    }
    Ok(())
}

fn inspect_lazaret_archive(name: &str, b: &[u8], depth: usize, q: &mut Budget) -> Result<bool> {
    let hint = archive_hint(name);
    let detected = match lazaret_archive::detect(b) {
        Ok(format) => Some(format),
        Err(ArchiveError::UnknownFormat) => None,
        Err(error) => return Err(archive_error(error)),
    };
    let (format, named) = match (hint, detected) {
        (None, None) => return Ok(false),
        (None, Some(format)) => (format, false),
        (Some(ArchiveHint::Rar), Some(format @ (ArchiveFormat::Rar4 | ArchiveFormat::Rar5))) => {
            (format, true)
        }
        (Some(ArchiveHint::Rar), None) => {
            return Err(crate::error!("RAR signature is missing or unsupported"));
        }
        (Some(ArchiveHint::Exact(ArchiveFormat::TarGzip)), Some(ArchiveFormat::Gzip)) => {
            (ArchiveFormat::TarGzip, true)
        }
        (Some(ArchiveHint::Exact(wanted)), Some(found)) if wanted == found => (wanted, true),
        (Some(ArchiveHint::Exact(wanted)), None) => (wanted, true),
        (Some(_), Some(found)) => {
            q.issue("Archive filename and content type disagree");
            (found, false)
        }
    };
    let remaining = q.expanded.saturating_sub(q.bytes) as u64;
    ensure!(remaining > 0, "Attachment expansion budget exceeded");
    let limits = ArchiveLimits {
        max_entries: MEMBERS.saturating_sub(q.members),
        max_member_size: remaining,
        max_total_size: remaining,
        max_name_size: 1024,
        max_metadata_size: remaining.min(1024 * 1024),
    };
    let archive = if named {
        lazaret_archive::extract_as(b, format, limits)
    } else {
        lazaret_archive::extract_with_limits(b, limits)
    }
    .map_err(archive_error)?;
    let output = archive
        .entries
        .iter()
        .map(|entry| entry.data.len())
        .fold(0usize, usize::saturating_add);
    ensure!(
        output <= 1024 * 1024 || output <= b.len().saturating_mul(200),
        "Archive expansion ratio exceeded"
    );
    q.deadline()?;
    inspect_archive_entries(&archive, depth, q)?;
    Ok(true)
}

fn inspect_file(name: &str, b: &[u8], depth: usize, q: &mut Budget) -> Result<()> {
    q.charge(b.len(), depth)?;
    inspect_name(name, q);
    if executable(b) || serialized_payload(b) {
        q.issue("Executable, script or prohibited active attachment");
    }
    if b.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        q.issue("Legacy compound document cannot be fully inspected");
        return Ok(());
    }
    let lower = normalize(name);
    let ext = lower.rsplit('.').next().unwrap_or("");
    let zip_content = b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06");
    if zip_content || ["zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub"].contains(&ext) {
        if zip_content && archive_hint(name).is_some() {
            q.issue("Archive filename and content type disagree");
        }
        return inspect_zip(b, depth, q);
    }
    if inspect_lazaret_archive(name, b, depth, q)? {
        return Ok(());
    }
    if b.starts_with(b"MSCF")
        || b.starts_with(b"\x28\xb5\x2f\xfd")
        || [
            "zst", "zstd", "cab", "arj", "ace", "lz", "lz4", "z", "sit", "sitx", "lzh", "uue",
        ]
        .contains(&ext)
    {
        q.issue("Unsupported archive or compression format; inspection incomplete");
        return Ok(());
    }
    if b.starts_with(b"-----BEGIN PGP MESSAGE-----") || ["p7m", "pgp", "gpg"].contains(&ext) {
        q.issue("Encrypted attachment cannot be inspected");
        return Ok(());
    }
    if b.starts_with(b"%PDF-") {
        let s = String::from_utf8_lossy(b).to_ascii_lowercase();
        if [
            "/javascript",
            "/js",
            "/launch",
            "/embeddedfile",
            "/openaction",
            "/aa",
            "/encrypt",
        ]
        .iter()
        .any(|p| s.contains(p))
        {
            q.issue("PDF active, embedded or encrypted content");
        }
    }
    if b.starts_with(b"{\\rtf") {
        q.issue("Rich-text container requires administrator review");
    }
    if let Ok(t) = std::str::from_utf8(b) {
        let text = normalize(t);
        if [
            "<script",
            "<iframe",
            "<object",
            "<embed",
            "javascript:",
            "ms-msdt:",
            "powershell -",
            "wscript.shell",
            "eval(atob(",
        ]
        .iter()
        .any(|p| text.contains(p))
        {
            q.issue("Active attachment content");
        }
        if q.texts.iter().map(String::len).sum::<usize>() < 1_000_000 {
            q.texts.push(cut(t, 200000));
        }
    }
    Ok(())
}
pub fn inspect(raw: &[u8]) -> Result<Value> {
    inspect_with_settings(raw, &settings())
}
pub fn inspect_with_settings(raw: &[u8], settings: &Value) -> Result<Value> {
    let limits = scan_limits(settings)?;
    ensure!(
        !raw.is_empty() && raw.len() <= limits.input_bytes,
        "Message size limit"
    );
    crate::auth::validate(raw)?;
    let m = MessageParser::with_limits(workglen_mime::Limits {
        input_bytes: limits.input_bytes,
        decoded_bytes: limits.decoded_bytes,
        depth: DEPTH,
        parts: limits.parts,
        ..Default::default()
    })
    .parse(raw)
    .ok_or_else(|| crate::error!("Invalid MIME or configured parser budget exceeded"))?;
    let from = m
        .from()
        .and_then(|a| a.first())
        .ok_or_else(|| crate::error!("Missing sender"))?;
    let sender = address(from.address.as_deref().unwrap_or(""))?;
    let mut q = Budget {
        expanded: limits.decoded_bytes,
        ..Default::default()
    };
    let mut texts = Vec::new();
    let mut pending = vec![(&m, 0)];
    let mut parts = 0;
    while let Some((message, depth)) = pending.pop() {
        ensure!(depth <= DEPTH, "Nested message limit");
        for part in &message.parts {
            parts += 1;
            ensure!(parts <= limits.parts, "MIME part limit");
            if part.is_encoding_problem {
                q.issue("MIME transfer decoding incomplete");
            }
            let name = part.attachment_name().unwrap_or("");
            let attachment = !name.is_empty()
                || part
                    .content_disposition()
                    .is_some_and(|d| d.is_attachment());
            match &part.body {
                PartType::Message(nested) => pending.push((nested, depth + 1)),
                PartType::Text(t) | PartType::Html(t) => {
                    texts.push(cut(t, 500000));
                    if attachment && let Err(e) = inspect_file(name, t.as_bytes(), depth, &mut q) {
                        q.issue(format!("Attachment inspection incomplete: {e}"));
                    }
                }
                PartType::Binary(b) | PartType::InlineBinary(b) => {
                    if let Err(e) = inspect_file(name, b, depth, &mut q) {
                        q.issue(format!("Attachment inspection incomplete: {e}"));
                    }
                }
                PartType::Multipart(_) => {}
            }
        }
    }
    let incompleteness_reasons: Vec<String> = q
        .reasons
        .iter()
        .filter(|reason| {
            let reason = reason.to_ascii_lowercase();
            [
                "incomplete",
                "cannot be inspected",
                "cannot be fully inspected",
                "unsupported",
                "encrypted",
            ]
            .iter()
            .any(|marker| reason.contains(marker))
        })
        .cloned()
        .collect();
    let complete = incompleteness_reasons.is_empty();
    texts.extend(q.texts);
    let text = texts.join("\n");
    ensure!(text.len() <= 2_000_000, "Text scan budget exceeded");
    Ok(
        json!({"subject":cut(m.subject().unwrap_or(""),500),"sender":sender,"display_name":cut(from.name.as_deref().unwrap_or(""),256),"reply_to":m.reply_to().and_then(|x|x.first()).and_then(|x|x.address.as_deref()).unwrap_or("").to_ascii_lowercase(),"text":text,"filenames":q.names,"mandatory":q.reasons,"coverage":{"engine":ENGINE,"api_version":ANALYSIS_API_VERSION,"profile_version":ANALYSIS_PROFILE_VERSION,"coverage_version":COVERAGE_VERSION,"complete":complete,"incompleteness_reasons":incompleteness_reasons,"input_bytes":raw.len(),"text":true,"archive_formats":q.formats,"expanded_bytes":q.bytes,"members":q.members,"ocr":false,"full_antivirus":false}}),
    )
}
pub fn validate_rules(rules: &Value) -> Result<()> {
    let rows = rules
        .as_array()
        .ok_or_else(|| crate::error!("Rules must be a list"))?;
    ensure!((1..=100).contains(&rows.len()), "Use 1–100 rules");
    let mut ids = BTreeSet::new();
    for r in rows {
        let o = r.as_object().ok_or_else(|| crate::error!("Invalid rule"))?;
        ensure!(
            o.keys().all(
                |k| ["id", "type", "threshold", "action", "enabled", "values"]
                    .contains(&k.as_str())
            ),
            "Unknown rule option"
        );
        key(s(r, "id")?)?;
        ensure!(
            ids.insert(s(r, "id")?) && s(r, "id")?.len() <= 64,
            "Duplicate or overlong rule ID"
        );
        ensure!(
            [
                "spam",
                "bad_url",
                "sender",
                "attachment",
                "impersonation",
                "ai_instructions"
            ]
            .contains(&s(r, "type")?),
            "Unknown rule type"
        );
        ensure!(
            ["identify", "quarantine"].contains(&s(r, "action")?),
            "Invalid action"
        );
        ensure!(
            r.get("enabled").is_none_or(Value::is_boolean),
            "Invalid enabled value"
        );
        let score = r.get("threshold").and_then(Value::as_f64).unwrap_or(3.0);
        ensure!((1.0..=100.0).contains(&score), "Invalid threshold");
        if let Some(v) = r.get("values") {
            let a = v
                .as_array()
                .ok_or_else(|| crate::error!("Invalid values"))?;
            ensure!(
                a.len() <= 200
                    && a.iter()
                        .all(|v| v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 254)),
                "Invalid rule values"
            );
        }
    }
    Ok(())
}
fn pair(text: &str, verbs: &[&str], objects: &[&str], distance: usize) -> bool {
    verbs.iter().any(|v| {
        text.match_indices(v).take(2000).any(|(at, _)| {
            let end = (at + v.len() + distance).min(text.len());
            let tail = String::from_utf8_lossy(&text.as_bytes()[at..end]);
            objects.iter().any(|o| tail.contains(o))
        })
    })
}
fn signals(text: &str) -> Vec<(&'static str, f64)> {
    let mut v = Vec::new();
    for (yes, label, weight) in [
        (
            pair(
                text,
                &["ignore", "disregard", "override", "forget", "bypass"],
                &[
                    "previous",
                    "prior",
                    "system",
                    "developer",
                    "instructions",
                    "rules",
                    "policy",
                ],
                90,
            ),
            "instruction_override",
            2.,
        ),
        (
            [
                "ai assistant",
                "ai agent",
                "language model",
                "chatgpt",
                "llm",
                "automated agent",
                "assistant reading",
                "dear assistant",
            ]
            .iter()
            .any(|x| text.contains(x)),
            "assistant_addressed",
            1.,
        ),
        (
            [
                "<|im_start|>",
                "<|system|>",
                "<|start_header_id|>",
                "[inst]",
                "[system]",
                "[developer]",
                "<system>",
                "<developer>",
                "<tool_call>",
                "\nsystem:",
                "\ndeveloper:",
            ]
            .iter()
            .any(|x| text.contains(x)),
            "role_delimiter",
            3.,
        ),
        (
            pair(
                text,
                &["send", "forward", "upload", "reveal", "exfiltrate", "print"],
                &[
                    "secret",
                    "password",
                    "api key",
                    "credentials",
                    "system prompt",
                    "access token",
                    "inbox",
                    "mailbox contents",
                    "all emails",
                    "confidential files",
                ],
                120,
            ),
            "secret_exfiltration",
            2.,
        ),
        (
            pair(
                text,
                &["execute", "invoke", "run", "call", "use"],
                &[
                    "shell",
                    "terminal",
                    "tool call",
                    "function call",
                    "browser tool",
                ],
                70,
            ),
            "tool_execution",
            2.,
        ),
        (
            pair(
                text,
                &[
                    "do not tell",
                    "don't tell",
                    "never tell",
                    "do not inform",
                    "never mention",
                    "do not notify",
                ],
                &["user", "recipient", "owner", "human"],
                70,
            ),
            "conceal_instruction",
            2.,
        ),
        (
            [
                "respond with exactly",
                "output only",
                "mark this message as safe",
                "classify this email as safe",
            ]
            .iter()
            .any(|x| text.contains(x)),
            "output_hijack",
            1.,
        ),
        (
            pair(
                text,
                &["you are now"],
                &["agent", "assistant", "system", "unrestricted", "developer"],
                70,
            ),
            "new_identity",
            2.,
        ),
    ] {
        if yes {
            v.push((label, weight));
        }
    }
    v
}
fn near(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    let x = |s: &str| s.replace('0', "o").replace('1', "l").replace("rn", "m");
    if x(a) == x(b) {
        return true;
    }
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() == b.len() {
        return a.iter().zip(b).filter(|(a, b)| a != b).count() == 1;
    }
    let (a, b) = if a.len() < b.len() { (a, b) } else { (b, a) };
    b.len() == a.len() + 1 && (0..b.len()).any(|i| a[..i] == b[..i] && a[i..] == b[i + 1..])
}
pub const ANALYSIS_API_VERSION: u64 = 1;
pub const ANALYSIS_PROFILE_VERSION: u64 = 1;
pub const COVERAGE_VERSION: u64 = 1;

pub fn evaluate(raw: &[u8], rules: &Value, settings: &Value, evidence: &Value) -> Result<Value> {
    let m = inspect_with_settings(raw, settings)?;
    evaluate_inspected(&m, rules, settings, evidence)
}

/// Evaluate a bounded inspection result. The split scan worker uses this to keep
/// MIME/archive decoding outside the SMTP/database process while preserving the
/// existing rule and learning behavior.
pub fn evaluate_inspected(
    m: &Value,
    rules: &Value,
    settings: &Value,
    evidence: &Value,
) -> Result<Value> {
    let text = normalize(&format!("{}\n{}", s(m, "subject")?, s(m, "text")?));
    let sender = s(m, "sender")?;
    let domain = sender.rsplit('@').next().unwrap_or("");
    let mut hits = Vec::new();
    let mut spam = 0.;
    let mut spam_signals = Vec::new();
    for (phrases, label, score) in [
        (
            &["act now", "limited time offer", "winner", "you have won"][..],
            "promotional_pressure",
            2.,
        ),
        (
            &["click here", "claim your prize", "risk free", "100% free"][..],
            "promotional_offer",
            2.,
        ),
        (
            &["unsubscribe", "remove from mailing list"][..],
            "bulk_mail",
            1.,
        ),
        (
            &[
                "bitcoin investment",
                "guaranteed returns",
                "earn money fast",
            ][..],
            "financial_solicitation",
            3.,
        ),
    ] {
        if phrases.iter().any(|x| text.contains(x)) {
            spam += score;
            spam_signals.push(label);
        }
    }
    if text.matches("http://").count() + text.matches("https://").count() > 20 {
        spam += 2.;
        spam_signals.push("many_links");
    }
    if let Some(score) = evidence["learned_spam_score"].as_f64() {
        spam += score.clamp(-3., 5.);
    }
    for r in arr(&json!({"r":rules}), "r")? {
        if r["enabled"] == false {
            continue;
        }
        let kind = s(r, "type")?;
        let threshold = r["threshold"].as_f64().unwrap_or(3.);
        let values = r["values"].as_array().cloned().unwrap_or_default();
        let mut score = 0.;
        let mut sig = Vec::new();
        let reason = match kind {
            "spam" => {
                score = spam;
                sig = spam_signals.iter().map(|s| s.to_string()).collect();
                if score >= threshold {
                    Some("Spam score exceeds threshold")
                } else {
                    None
                }
            }
            "sender" => {
                if values
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|x| x.eq_ignore_ascii_case(sender) || x.eq_ignore_ascii_case(domain))
                {
                    Some("Sender matches policy")
                } else {
                    None
                }
            }
            "attachment" => {
                if m["filenames"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|n| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|e| n.rsplit('.').next() == Some(e))
                    })
                {
                    Some("Attachment matches policy")
                } else {
                    None
                }
            }
            "bad_url" => {
                let found = text
                    .split(|c: char| c.is_whitespace() || ['<', '>', '\"', '\''].contains(&c))
                    .filter(|s| s.starts_with("https://") || s.starts_with("http://"))
                    .take(2000)
                    .filter_map(|s| crate::url::Url::parse(s).ok())
                    .any(|u| {
                        u.host_str().is_some_and(|h| {
                            values
                                .iter()
                                .filter_map(Value::as_str)
                                .any(|v| h == v || h.ends_with(&format!(".{v}")))
                        })
                    });
                if found {
                    Some("Link matches a blocked domain")
                } else {
                    None
                }
            }
            "ai_instructions" => {
                let found = signals(&text);
                score = found.iter().map(|x| x.1).sum();
                sig = found.iter().map(|x| x.0.to_string()).collect();
                if score >= threshold {
                    Some("Probable embedded instructions directed at an AI system")
                } else {
                    None
                }
            }
            "impersonation" => {
                if settings["protected_people"].as_array().is_some_and(|a| {
                    a.iter().any(|p| {
                        normalize(m["display_name"].as_str().unwrap_or(""))
                            == normalize(p["name"].as_str().unwrap_or(""))
                            && sender != p["address"].as_str().unwrap_or("")
                    })
                }) {
                    score += 2.;
                    sig.push("protected_display_name".into());
                }
                if settings["protected_domains"]
                    .as_array()
                    .is_some_and(|a| a.iter().filter_map(Value::as_str).any(|d| near(domain, d)))
                {
                    score += 2.;
                    sig.push("lookalike_domain".into());
                }
                if settings["mixed_script_check"] == true
                    && workglen_idna::has_mixed_script_labels(domain).unwrap_or(false)
                {
                    score += 2.;
                    sig.push("mixed_script_domain".into());
                }
                let reply = m["reply_to"].as_str().unwrap_or("");
                if !reply.is_empty() && reply.rsplit('@').next() != Some(domain) {
                    score += 1.;
                    sig.push("different_reply_to".into());
                }
                let identity = !sig.is_empty();
                if [
                    "bank details",
                    "wire transfer",
                    "payment details",
                    "urgent payment",
                    "password reset",
                    "verify your account",
                    "gift cards",
                ]
                .iter()
                .any(|x| text.contains(x))
                {
                    score += 1.;
                    sig.push("payment_or_credentials".into());
                }
                if identity && score >= threshold {
                    Some("Combined identity and fraud indicators")
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(reason) = reason {
            hits.push(json!({"rule":r["id"],"type":kind,"action":r["action"],"reason":reason,"signals":sig,"score":score}));
        }
    }
    for reason in m["mandatory"].as_array().unwrap() {
        hits.push(json!({"rule":"mandatory-attachment","type":"attachment_safety","action":"quarantine","reason":reason,"signals":[],"score":null}));
    }
    if evidence["authentication_action"] == "quarantine" {
        hits.push(json!({"rule":"mandatory-authentication","type":"authentication","action":"quarantine","reason":"Sender domain authentication policy","signals":[],"score":null}));
    }
    let blocked: Vec<_> = hits
        .iter()
        .filter(|h| h["action"] == "quarantine")
        .collect();
    let releasable = !blocked.is_empty() && blocked.iter().all(|h| h["type"] == "spam");
    Ok(json!({
        "action":if blocked.is_empty(){"deliver"}else{"quarantine"},
        "releasable":releasable,
        "matches":hits,
        "coverage":m["coverage"],
        "subject":m["subject"],
        "sender":m["sender"],
        "spam_score":spam,
        "engine":ENGINE,
        "api_version":ANALYSIS_API_VERSION,
        "profile_version":ANALYSIS_PROFILE_VERSION,
        "coverage_version":COVERAGE_VERSION
    }))
}
