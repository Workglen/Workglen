//! RFC 5322 delimiters are parsed before decoding display-name words, preventing
//! encoded display text from injecting an address or changing a mailbox boundary.
use crate::{Addr, Address};
use std::borrow::Cow;
pub(crate) fn comments(input: &str) -> (String, Vec<String>, bool) {
    let mut out = String::new();
    let mut found = Vec::new();
    let mut comment = String::new();
    let mut depth = 0usize;
    let mut quote = false;
    let mut escape = false;
    let mut bad = false;
    for c in input.chars() {
        if escape {
            if depth > 0 {
                comment.push(c);
            } else {
                out.push(c);
            }
            escape = false;
            continue;
        }
        if c == '\\' && (depth > 0 || quote) {
            if depth == 0 {
                out.push(c);
            }
            escape = true;
            continue;
        }
        if c == '"' && depth == 0 {
            quote = !quote;
            out.push(c);
            continue;
        }
        if !quote && c == '(' {
            depth += 1;
            if depth > 32 {
                bad = true;
            }
            if depth > 1 {
                comment.push('(');
            }
            continue;
        }
        if !quote && c == ')' && depth > 0 {
            depth -= 1;
            if depth == 0 {
                found.push(std::mem::take(&mut comment));
                out.push(' ');
            } else {
                comment.push(')');
            }
            continue;
        }
        if depth > 0 {
            comment.push(c);
        } else {
            out.push(c);
        }
    }
    (out, found, bad || quote || depth > 0 || escape)
}
fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        let mut out = String::new();
        let mut escape = false;
        for c in s[1..s.len() - 1].chars() {
            if escape {
                out.push(c);
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else {
                out.push(c);
            }
        }
        out
    } else {
        s.to_owned()
    }
}
fn mailbox(text: &str) -> Option<Addr<'static>> {
    let (clean, comments, _) = comments(text);
    let clean = clean.trim();
    if clean.is_empty() {
        return None;
    }
    let mut quote = false;
    let mut escape = false;
    let mut left = None;
    let mut right = None;
    let mut bad = false;
    for (i, c) in clean.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if c == '\\' && quote {
            escape = true;
            continue;
        }
        if c == '"' {
            quote = !quote;
        } else if !quote && c == '<' {
            bad |= left.is_some();
            left = Some(i);
        } else if !quote && c == '>' {
            bad |= right.is_some() || left.is_none();
            right = Some(i);
        }
    }
    if bad
        || quote
        || escape
        || left.is_some() != right.is_some()
        || right.is_some_and(|r| !clean[r + 1..].trim().is_empty())
    {
        return None;
    }
    let (display, address) = if let Some(l) = left {
        let r = right.filter(|r| *r > l).unwrap_or(clean.len());
        (&clean[..l], clean[l + 1..r].trim())
    } else {
        ("", clean)
    };
    let address = if address.starts_with('@') {
        address.rsplit_once(':').map(|(_, s)| s).unwrap_or(address)
    } else {
        address
    };
    let address = unquote(address.trim());
    let address = if address.is_empty() {
        None
    } else {
        Some(Cow::Owned(address))
    };
    let display = unquote(display);
    let display = if display.trim().is_empty() {
        comments.join(" ")
    } else {
        display
    };
    let (name, _) = crate::header::words(display.trim());
    Some(Addr {
        name: if name.is_empty() {
            None
        } else {
            Some(Cow::Owned(name))
        },
        address,
    })
}
pub(crate) fn parse(input: &str) -> Option<Address<'static>> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut comment = 0usize;
    let mut angle = 0usize;
    let mut quote = false;
    let mut escape = false;
    let mut bracket = false;
    for (i, c) in input.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if c == '\\' && (quote || comment > 0) {
            escape = true;
            continue;
        }
        if c == '"' && comment == 0 {
            quote = !quote;
            continue;
        }
        if quote {
            continue;
        }
        if c == '(' {
            comment += 1;
            continue;
        }
        if c == ')' && comment > 0 {
            comment -= 1;
            continue;
        }
        if comment > 0 {
            continue;
        }
        match c {
            '[' => bracket = true,
            ']' => bracket = false,
            '<' => angle += 1,
            '>' if angle > 0 => angle -= 1,
            ':' if angle == 0 && !bracket => {
                if input[start..i].contains('@') {
                    return None;
                }
                start = i + 1;
            }
            ',' | ';' if angle == 0 && !bracket => {
                if !input[start..i].trim().is_empty() {
                    result.push(mailbox(&input[start..i])?);
                }
                start = i + 1;
            }
            _ => {}
        }
        if result.len() > 1024 {
            return None;
        }
    }
    if comment > 0 || angle > 0 || quote || escape || bracket {
        return None;
    }
    if !input[start..].trim().is_empty() {
        result.push(mailbox(&input[start..])?);
    }
    if result.is_empty() {
        None
    } else {
        Some(Address(result))
    }
}
