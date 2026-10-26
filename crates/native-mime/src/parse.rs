//! MIME tree construction with one shared budget across nested RFC 822 messages.
use crate::{Message, MessagePart, MimeHeaders, PartType};
use std::borrow::Cow;
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub input_bytes: usize,
    pub header_bytes: usize,
    pub header_fields: usize,
    pub depth: usize,
    pub parts: usize,
    pub decoded_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            input_bytes: 64 * 1024 * 1024,
            header_bytes: 64 * 1024,
            header_fields: 256,
            depth: 32,
            parts: 1024,
            decoded_bytes: 256 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct MessageParser {
    limits: Limits,
}
impl MessageParser {
    pub fn with_limits(limits: Limits) -> Self {
        Self { limits }
    }
    pub fn parse<'a>(&self, input: &'a [u8]) -> Option<Message<'a>> {
        if input.is_empty()
            || input.len() > self.limits.input_bytes
            || input.len() > u32::MAX as usize
        {
            return None;
        }
        let mut b = Budget {
            limits: self.limits,
            parts: 0,
            bytes: 0,
        };
        message(Cow::Borrowed(input), &mut b, 0, false)
    }
    pub fn parse_headers<'a>(&self, input: &'a [u8]) -> Option<Message<'a>> {
        if input.is_empty()
            || input.len() > self.limits.input_bytes
            || input.len() > u32::MAX as usize
        {
            return None;
        }
        let mut b = Budget {
            limits: self.limits,
            parts: 0,
            bytes: 0,
        };
        message(Cow::Borrowed(input), &mut b, 0, true)
    }
}
struct Budget {
    limits: Limits,
    parts: usize,
    bytes: usize,
}
impl Budget {
    fn charge(&mut self, n: usize) -> Option<()> {
        self.bytes = self.bytes.checked_add(n)?;
        if self.bytes > self.limits.decoded_bytes {
            None
        } else {
            Some(())
        }
    }
}
fn message<'a>(
    raw: Cow<'a, [u8]>,
    budget: &mut Budget,
    depth: usize,
    headers_only: bool,
) -> Option<Message<'a>> {
    let mut parts = Vec::new();
    part(
        &raw,
        0,
        raw.len(),
        &mut parts,
        budget,
        depth,
        false,
        headers_only,
    )?;
    let mut message = Message {
        raw_message: raw,
        parts,
        text_body: Vec::new(),
        html_body: Vec::new(),
        attachments: Vec::new(),
    };
    select(&mut message, 0, false, false);
    Some(message)
}
fn delimiters(
    raw: &[u8],
    start: usize,
    end: usize,
    boundary: &str,
    max_parts: usize,
) -> Option<(Vec<(usize, usize)>, bool)> {
    let marker = format!("--{boundary}");
    let marker = marker.as_bytes();
    let mut pos = start;
    let mut child = None;
    let mut spans = Vec::new();
    let mut closed = false;
    while pos < end {
        let next = raw[pos..end]
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| pos + n + 1)
            .unwrap_or(end);
        let line = raw[pos..next]
            .strip_suffix(b"\n")
            .unwrap_or(&raw[pos..next]);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(tail) = line.strip_prefix(marker) {
            let closing = tail.starts_with(b"--");
            let tail = if closing { &tail[2..] } else { tail };
            if tail.iter().all(|b| matches!(b, b' ' | b'\t')) {
                if let Some(a) = child.take() {
                    let mut b = pos;
                    if b > a && raw[b - 1] == b'\n' {
                        b -= 1;
                        if b > a && raw[b - 1] == b'\r' {
                            b -= 1;
                        }
                    }
                    spans.push((a, b));
                    if spans.len() > max_parts {
                        return None;
                    }
                }
                if closing {
                    closed = true;
                    break;
                }
                child = Some(next);
            }
        }
        pos = next;
    }
    if let Some(a) = child {
        spans.push((a, end));
    }
    if spans.len() > max_parts {
        return None;
    }
    Some((spans, closed))
}
#[allow(clippy::too_many_arguments)]
fn part(
    raw: &[u8],
    start: usize,
    end: usize,
    parts: &mut Vec<MessagePart<'static>>,
    budget: &mut Budget,
    depth: usize,
    digest: bool,
    headers_only: bool,
) -> Option<u32> {
    if depth > budget.limits.depth || budget.parts >= budget.limits.parts {
        return None;
    }
    budget.parts += 1;
    let (mut fields, header_len) = crate::header::parse(
        &raw[start..end],
        budget.limits.header_bytes,
        budget.limits.header_fields,
    )?;
    budget.charge(header_len.saturating_mul(3))?;
    let body_start = start + header_len;
    let id = parts.len() as u32;
    let (major, minor) = fields
        .content_type
        .as_ref()
        .map(|c| {
            (
                c.ctype().to_ascii_lowercase(),
                c.subtype().unwrap_or("").to_ascii_lowercase(),
            )
        })
        .unwrap_or_else(|| {
            if digest {
                ("message".into(), "rfc822".into())
            } else {
                ("text".into(), "plain".into())
            }
        });
    let boundary = fields
        .content_type
        .as_ref()
        .and_then(|c| c.attribute("boundary"))
        .map(str::to_owned);
    let encoding = fields.encoding.as_deref().unwrap_or("7bit").to_owned();
    parts.push(MessagePart {
        body: PartType::Text(Cow::Borrowed("")),
        offset_header: start as u32,
        offset_body: body_start as u32,
        offset_end: end as u32,
        is_encoding_problem: false,
        fields: Default::default(),
    });
    let body = if headers_only {
        PartType::Text(Cow::Borrowed(""))
    } else if major == "multipart" {
        if !matches!(encoding.as_str(), "7bit" | "8bit" | "binary") {
            fields.problem = true;
        }
        let valid = boundary.as_ref().is_some_and(|b| {
            !b.is_empty()
                && b.len() <= 70
                && b.is_ascii()
                && !b.ends_with(' ')
                && b.bytes()
                    .all(|v| v.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&v))
        });
        if valid {
            let (spans, closed) = delimiters(
                raw,
                body_start,
                end,
                boundary.as_deref().unwrap(),
                budget.limits.parts.saturating_sub(budget.parts),
            )?;
            fields.problem |= !closed || spans.is_empty();
            let mut ids = Vec::new();
            for (a, b) in spans {
                ids.push(part(
                    raw,
                    a,
                    b,
                    parts,
                    budget,
                    depth + 1,
                    minor == "digest",
                    false,
                )?);
            }
            PartType::Multipart(ids)
        } else {
            fields.problem = true;
            budget.charge(end - body_start)?;
            PartType::Binary(Cow::Owned(raw[body_start..end].to_vec()))
        }
    } else {
        // Bound allocations before transfer decoding and charge the decoded expansion.
        budget.charge(end - body_start)?;
        let (bytes, bad) = crate::transfer::decode(&raw[body_start..end], Some(&encoding));
        fields.problem |= bad;
        if major == "message" && matches!(minor.as_str(), "rfc822" | "global") {
            if bytes.is_empty() {
                fields.problem = true;
                PartType::Binary(Cow::Owned(bytes))
            } else {
                PartType::Message(Box::new(message(
                    Cow::Owned(bytes),
                    budget,
                    depth + 1,
                    false,
                )?))
            }
        } else if major == "text" {
            let charset = fields
                .content_type
                .as_ref()
                .and_then(|c| c.attribute("charset"));
            let (text, bad) = crate::charset::decode(&bytes, charset);
            budget.charge(text.len())?;
            fields.problem |= bad;
            if minor == "html" {
                PartType::Html(Cow::Owned(text))
            } else {
                PartType::Text(Cow::Owned(text))
            }
        } else if fields
            .disposition
            .as_ref()
            .is_some_and(|c| c.ctype() == "inline")
        {
            PartType::InlineBinary(Cow::Owned(bytes))
        } else {
            PartType::Binary(Cow::Owned(bytes))
        }
    };
    parts[id as usize].body = body;
    parts[id as usize].is_encoding_problem = fields.problem;
    parts[id as usize].fields = fields;
    Some(id)
}
fn select(message: &mut Message<'_>, id: u32, parent_attachment: bool, related_resource: bool) {
    let p = &message.parts[id as usize];
    let explicit =
        p.content_disposition().is_some_and(|c| c.is_attachment()) || p.attachment_name().is_some();
    let attached = parent_attachment || explicit || related_resource;
    if let PartType::Multipart(children) = &p.body {
        let related = p.is_content_type("multipart", "related");
        let start = p
            .content_type()
            .and_then(|c| c.attribute("start"))
            .map(|s| s.trim_matches(['<', '>']));
        let root = if related {
            start
                .and_then(|s| {
                    children
                        .iter()
                        .find(|i| message.parts[**i as usize].content_id() == Some(s))
                })
                .copied()
                .or_else(|| children.first().copied())
        } else {
            None
        };
        let children = children.clone();
        for child in children {
            select(message, child, attached, related && Some(child) != root);
        }
        return;
    }
    match &p.body {
        PartType::Text(_) if !attached => message.text_body.push(id),
        PartType::Html(_) if !attached => message.html_body.push(id),
        _ => message.attachments.push(id),
    }
}
