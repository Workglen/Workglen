//! Header grammar, encoded words and RFC 2231 parameters. Header limits are
//! enforced before allocation; MIME ambiguities remain visible to inspection.
use crate::{Attribute, ContentType, DateTime, Header, ParsedFields};
use std::borrow::Cow;

pub(crate) fn words(input: &str) -> (String, bool) {
    let mut out = String::new();
    let mut rest = input;
    let mut previous = false;
    let mut bad = false;
    while let Some(start) = rest.find("=?") {
        let prefix = &rest[..start];
        let candidate = &rest[start + 2..];
        let Some(q1) = candidate.find('?') else { break };
        let Some(q2) = candidate[q1 + 1..].find('?').map(|v| v + q1 + 1) else {
            break;
        };
        let Some(end) = candidate[q2 + 1..].find("?=").map(|v| v + q2 + 1) else {
            break;
        };
        let kind = &candidate[q1 + 1..q2];
        if !matches!(kind, "b" | "B" | "q" | "Q") {
            out.push_str(&rest[..start + 2]);
            rest = candidate;
            previous = false;
            continue;
        }
        if !previous
            || !prefix
                .bytes()
                .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            out.push_str(prefix);
        }
        let (bytes, err) = if kind.eq_ignore_ascii_case("b") {
            crate::transfer::base64(&candidate.as_bytes()[q2 + 1..end])
        } else {
            crate::transfer::quoted_printable(&candidate.as_bytes()[q2 + 1..end], true)
        };
        let charset = candidate[..q1].split('*').next().unwrap_or("");
        let (text, invalid) = crate::charset::decode(&bytes, Some(charset));
        out.push_str(&text);
        bad |= err || invalid;
        rest = &candidate[end + 2..];
        previous = true;
    }
    out.push_str(rest);
    (out, bad)
}
fn unquote(value: &str) -> (String, bool) {
    let value = value.trim();
    if !value.starts_with('"') {
        return (value.to_owned(), false);
    }
    let mut out = String::new();
    let mut escape = false;
    let mut closed = false;
    let mut bad = false;
    for c in value[1..].chars() {
        if closed {
            bad |= !c.is_ascii_whitespace();
        } else if escape {
            out.push(c);
            escape = false;
        } else if c == '\\' {
            escape = true;
        } else if c == '"' {
            closed = true;
        } else {
            out.push(c);
        }
    }
    (out, bad || !closed || escape)
}
fn percent(value: &str) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut i = 0;
    let b = value.as_bytes();
    let mut bad = false;
    while i < b.len() {
        if b[i] == b'%' {
            if let (Some(a), Some(c)) = (
                b.get(i + 1).and_then(|b| (*b as char).to_digit(16)),
                b.get(i + 2).and_then(|b| (*b as char).to_digit(16)),
            ) {
                out.push((a * 16 + c) as u8);
                i += 3;
                continue;
            }
            bad = true;
        }
        out.push(b[i]);
        i += 1;
    }
    (out, bad)
}
fn extended(value: &str) -> (String, bool) {
    let Some((charset, rest)) = value.split_once('\'') else {
        return (value.to_owned(), true);
    };
    let Some((_, value)) = rest.split_once('\'') else {
        return (value.to_owned(), true);
    };
    let (b, bad) = percent(value);
    let (t, e) = crate::charset::decode(&b, Some(charset));
    (t, bad || e)
}
pub(crate) fn content_type(input: &str, disposition: bool) -> (Option<ContentType<'static>>, bool) {
    let (clean, _, mut bad) = crate::address::comments(input);
    let mut sections = Vec::new();
    let mut start = 0;
    let mut quote = false;
    let mut escape = false;
    for (i, c) in clean.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if c == '\\' && quote {
            escape = true;
        } else if c == '"' {
            quote = !quote;
        } else if c == ';' && !quote {
            sections.push(&clean[start..i]);
            start = i + 1;
        }
    }
    sections.push(&clean[start..]);
    bad |= quote || escape;
    let main = sections[0].trim().to_ascii_lowercase();
    let (major, minor) = if disposition {
        (main.as_str(), None)
    } else {
        main.split_once('/')
            .map(|(a, b)| (a.trim(), Some(b.trim())))
            .unwrap_or((main.as_str(), None))
    };
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b > 32 && b < 127 && !b"()<>@,;:\\\"/[]?=".contains(&b))
    };
    if !token(major) || minor.is_some_and(|s| !token(s)) {
        return (None, true);
    }
    if !disposition && minor.is_none() {
        bad = true;
    }
    if sections.len() > 129 {
        return (None, true);
    }
    let mut params: Vec<(String, String)> = Vec::new();
    for s in sections.into_iter().skip(1) {
        if s.trim().is_empty() {
            continue;
        }
        let Some((k, v)) = s.split_once('=') else {
            bad = true;
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        if !token(&k) {
            bad = true;
            continue;
        }
        let (v, e) = unquote(v);
        bad |= e;
        if params.iter().any(|(name, _)| name == &k) {
            bad = true;
            continue;
        }
        params.push((k, v));
    }
    let mut names = Vec::new();
    for (k, _) in &params {
        let name = k.split('*').next().unwrap();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let mut attrs = Vec::new();
    for name in names {
        let get = |key: &str| {
            params
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        let single = get(&format!("{name}*"));
        let first = get(&format!("{name}*0*"));
        let plainfirst = get(&format!("{name}*0"));
        let value = if first.is_some() || plainfirst.is_some() {
            if single.is_some() {
                bad = true;
            }
            let mut bytes = Vec::new();
            let mut charset = None;
            let mut n = 0;
            loop {
                let enc = get(&format!("{name}*{n}*"));
                let plain = get(&format!("{name}*{n}"));
                if enc.is_some() && plain.is_some() {
                    bad = true;
                }
                let Some(mut value) = enc.or(plain) else {
                    break;
                };
                if n == 0 && enc.is_some() {
                    if let Some((cs, rest)) = value.split_once('\'') {
                        if let Some((_, v)) = rest.split_once('\'') {
                            charset = Some(cs);
                            value = v;
                        } else {
                            bad = true;
                        }
                    } else {
                        bad = true;
                    }
                }
                if enc.is_some() {
                    let (v, e) = percent(value);
                    bytes.extend(v);
                    bad |= e;
                } else {
                    bytes.extend_from_slice(value.as_bytes());
                }
                n += 1;
            }
            for (k, _) in &params {
                if let Some(tail) = k.strip_prefix(&format!("{name}*"))
                    && let Ok(i) = tail.trim_end_matches('*').parse::<usize>()
                    && i >= n
                {
                    bad = true;
                }
            }
            let (v, e) = crate::charset::decode(&bytes, charset);
            bad |= e;
            v
        } else if let Some(value) = single {
            let (v, e) = extended(value);
            bad |= e;
            v
        } else if let Some(value) = get(name) {
            let (v, e) = words(value);
            bad |= e;
            v
        } else {
            bad = true;
            continue;
        };
        attrs.push(Attribute {
            name: Cow::Owned(name.to_owned()),
            value: Cow::Owned(value),
        });
    }
    (
        Some(ContentType {
            c_type: Cow::Owned(major.to_owned()),
            c_subtype: minor.map(|s| Cow::Owned(s.to_owned())),
            attributes: if attrs.is_empty() { None } else { Some(attrs) },
        }),
        bad,
    )
}
fn date(input: &str) -> Option<DateTime> {
    let (clean, _, _) = crate::address::comments(input);
    let clean = clean.rsplit_once(',').map(|(_, s)| s).unwrap_or(&clean);
    let f: Vec<_> = clean.split_whitespace().collect();
    if f.len() < 5 {
        return None;
    }
    let day = f[0].parse::<u8>().ok()?;
    let month = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ]
    .iter()
    .position(|m| f[1].eq_ignore_ascii_case(m))? as u8
        + 1;
    let mut year = f[2].parse::<u16>().ok()?;
    if year < 50 {
        year += 2000;
    } else if year < 1000 {
        year += 1900;
    }
    let t: Vec<_> = f[3].split(':').collect();
    if !(2..=3).contains(&t.len()) {
        return None;
    }
    let hour = t[0].parse::<u8>().ok()?;
    let minute = t[1].parse::<u8>().ok()?;
    let second = if t.len() == 3 { t[2].parse().ok()? } else { 0 };
    let z = f[4].to_ascii_uppercase();
    let zone = match z.as_str() {
        "UT" | "GMT" | "Z" => "+0000",
        "EST" => "-0500",
        "EDT" | "AST" => "-0400",
        "CST" => "-0600",
        "CDT" => "-0500",
        "MST" => "-0700",
        "MDT" => "-0600",
        "PST" => "-0800",
        "PDT" => "-0700",
        _ => z.as_str(),
    };
    let (neg, zh, zm) = if zone.len() == 5
        && matches!(zone.as_bytes()[0], b'+' | b'-')
        && zone[1..].bytes().all(|b| b.is_ascii_digit())
    {
        (
            zone.starts_with('-'),
            zone[1..3].parse().ok()?,
            zone[3..].parse().ok()?,
        )
    } else if zone.len() == 1 && zone.as_bytes()[0].is_ascii_alphabetic() {
        (false, 0, 0)
    } else {
        return None;
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0
        || day > days[month as usize - 1]
        || hour > 23
        || minute > 59
        || second > 60
        || zh > 23
        || zm > 59
    {
        return None;
    }
    Some(DateTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        tz_before_gmt: neg,
        tz_hour: zh,
        tz_minute: zm,
    })
}
fn id(value: &str) -> Option<Cow<'static, str>> {
    let v = value.trim();
    let v = if let Some(start) = v.find('<') {
        let rest = &v[start + 1..];
        rest.split_once('>').map(|(s, _)| s).unwrap_or(rest)
    } else {
        v
    };
    if v.is_empty() {
        None
    } else {
        Some(Cow::Owned(v.to_owned()))
    }
}
fn add(fields: &mut ParsedFields<'static>, name: &str, raw: &[u8]) {
    let raw = String::from_utf8_lossy(raw);
    let mut value = String::new();
    for line in raw.lines() {
        if !value.is_empty() {
            value.push(' ');
        }
        value.push_str(line.trim());
    }
    let (decoded, bad) = words(&value);
    fields.problem |= bad;
    match name.to_ascii_lowercase().as_str() {
        "from" | "to" | "cc" | "bcc" | "sender" | "reply-to" => {
            let (_, _, bad) = crate::address::comments(&value);
            fields.problem |= bad;
            let a = crate::address::parse(&value);
            match name.to_ascii_lowercase().as_str() {
                "from" => fields.from = a,
                "to" => fields.to = a,
                "cc" => fields.cc = a,
                "bcc" => fields.bcc = a,
                "sender" => fields.sender = a,
                _ => fields.reply_to = a,
            }
        }
        "subject" => fields.subject = Some(Cow::Owned(decoded)),
        "date" => fields.date = date(&value),
        "message-id" => fields.message_id = id(&value),
        "content-id" => fields.content_id = id(&value),
        "content-description" => fields.description = Some(Cow::Owned(decoded)),
        "content-type" => {
            if fields.content_type.is_some() {
                fields.problem = true;
            }
            let (v, e) = content_type(&value, false);
            fields.content_type = v;
            fields.problem |= e;
        }
        "content-disposition" => {
            if fields.disposition.is_some() {
                fields.problem = true;
            }
            let (v, e) = content_type(&value, true);
            fields.disposition = v;
            fields.problem |= e;
        }
        "content-transfer-encoding" => {
            if fields.encoding.is_some() {
                fields.problem = true;
            }
            let (v, _, e) = crate::address::comments(&value);
            fields.encoding = Some(Cow::Owned(v.trim().to_ascii_lowercase()));
            fields.problem |= e;
        }
        _ => {}
    }
    fields.headers.push(Header {
        name: Cow::Owned(name.to_owned()),
        raw: Cow::Owned(raw.into_owned()),
        value: Cow::Owned(value),
    });
}
pub(crate) fn parse(
    raw: &[u8],
    max_bytes: usize,
    max_fields: usize,
) -> Option<(ParsedFields<'static>, usize)> {
    let mut fields = ParsedFields::default();
    let mut pos = 0;
    let mut current: Option<(String, usize)> = None;
    loop {
        let end = raw[pos..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| pos + n + 1)
            .unwrap_or(raw.len());
        if end > max_bytes {
            return None;
        }
        let line = raw[pos..end].strip_suffix(b"\n").unwrap_or(&raw[pos..end]);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let continuation = line.first().is_some_and(|b| matches!(b, b' ' | b'\t'));
        if (!continuation || line.is_empty())
            && let Some((name, start)) = current.take()
        {
            add(&mut fields, &name, &raw[start..pos]);
            if fields.headers.len() > max_fields {
                return None;
            }
        }
        if line.is_empty() {
            return Some((fields, end));
        }
        if continuation {
            if current.is_none() {
                fields.problem = true;
            }
        } else if let Some(colon) = line.iter().position(|b| *b == b':') {
            if colon == 0
                || !line[..colon]
                    .iter()
                    .all(|b| b.is_ascii_graphic() && *b != b':')
            {
                fields.problem = true;
            } else {
                current = Some((
                    String::from_utf8_lossy(&line[..colon]).into_owned(),
                    pos + colon + 1,
                ));
            }
        } else {
            fields.problem = true;
            return Some((fields, pos));
        }
        pos = end;
        if pos == raw.len() {
            if let Some((name, start)) = current.take() {
                add(&mut fields, &name, &raw[start..pos]);
            }
            return if fields.headers.len() > max_fields {
                None
            } else {
                Some((fields, pos))
            };
        }
    }
}
