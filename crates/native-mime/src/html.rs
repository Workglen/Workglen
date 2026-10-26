//! Text projection for mail previews. This is not an HTML sanitizer: rendered
//! HTML must still use the application's existing escaping/sandbox boundaries.
#[path = "html_entities.rs"]
mod entities;
fn entity(input: &str) -> Option<(String, usize)> {
    if let Some(rest) = input.strip_prefix('#') {
        let (digits, radix, prefix) = if rest.starts_with(['x', 'X']) {
            (&rest[1..], 16, 2)
        } else {
            (rest, 10, 1)
        };
        let n = digits
            .bytes()
            .take_while(|b| {
                if radix == 16 {
                    b.is_ascii_hexdigit()
                } else {
                    b.is_ascii_digit()
                }
            })
            .count();
        if n == 0 {
            return None;
        }
        let value = u32::from_str_radix(&digits[..n], radix).unwrap_or(0xfffd);
        let value = match value {
            0x80 => 0x20ac,
            0x82 => 0x201a,
            0x83 => 0x192,
            0x84 => 0x201e,
            0x85 => 0x2026,
            0x86 => 0x2020,
            0x87 => 0x2021,
            0x88 => 0x2c6,
            0x89 => 0x2030,
            0x8a => 0x160,
            0x8b => 0x2039,
            0x8c => 0x152,
            0x8e => 0x17d,
            0x91 => 0x2018,
            0x92 => 0x2019,
            0x93 => 0x201c,
            0x94 => 0x201d,
            0x95 => 0x2022,
            0x96 => 0x2013,
            0x97 => 0x2014,
            0x98 => 0x2dc,
            0x99 => 0x2122,
            0x9a => 0x161,
            0x9b => 0x203a,
            0x9c => 0x153,
            0x9e => 0x17e,
            0x9f => 0x178,
            0 => 0xfffd,
            n => n,
        };
        return Some((
            char::from_u32(value)
                .unwrap_or(char::REPLACEMENT_CHARACTER)
                .to_string(),
            prefix + n + usize::from(digits.as_bytes().get(n) == Some(&b';')),
        ));
    }
    let n = input
        .bytes()
        .take(33)
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b';')
        .count();
    for size in (1..=n).rev() {
        let name = &input[..size];
        if let Ok(i) = entities::ENTITIES.binary_search_by_key(&name, |v| v.0) {
            return Some((entities::ENTITIES[i].1.to_owned(), size));
        }
    }
    None
}
pub(crate) fn to_text(input: &str) -> String {
    let mut out = String::new();
    let mut i = 0;
    let mut hidden: Option<String> = None;
    let mut space = false;
    let mut pre = false;
    while i < input.len() {
        let rest = &input[i..];
        if rest.starts_with("<!--") {
            i += rest.find("-->").map(|n| n + 3).unwrap_or(rest.len());
            continue;
        }
        if let Some(stripped) = rest.strip_prefix('<') {
            let mut quote = None;
            let mut end = None;
            for (n, c) in stripped.char_indices() {
                if let Some(q) = quote {
                    if c == q {
                        quote = None;
                    }
                } else if matches!(c, '\'' | '"') {
                    quote = Some(c);
                } else if c == '>' {
                    end = Some(n + 2);
                    break;
                }
            }
            if let Some(end) = end {
                let tag = rest[1..end - 1].trim();
                let closing = tag.starts_with('/');
                let name = tag
                    .trim_start_matches('/')
                    .split(|c: char| c.is_ascii_whitespace() || c == '/')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if let Some(h) = &hidden {
                    if closing && h == &name {
                        hidden = None;
                    }
                } else if matches!(name.as_str(), "script" | "style" | "head") && !closing {
                    hidden = Some(name);
                } else {
                    if name == "pre" {
                        pre = !closing;
                    }
                    if matches!(
                        name.as_str(),
                        "br" | "p"
                            | "div"
                            | "li"
                            | "tr"
                            | "table"
                            | "blockquote"
                            | "h1"
                            | "h2"
                            | "h3"
                            | "h4"
                            | "hr"
                            | "pre"
                    ) && !out.is_empty()
                        && !out.ends_with('\n')
                    {
                        out.push('\n');
                        space = false;
                    }
                }
                i += end;
                continue;
            }
        }
        let c = rest.chars().next().unwrap();
        i += c.len_utf8();
        if hidden.is_some() {
            continue;
        }
        if c == '&'
            && let Some((text, n)) = entity(&input[i..])
        {
            if space && !out.is_empty() && !out.ends_with('\n') {
                out.push(' ');
            }
            space = false;
            out.push_str(&text);
            i += n;
            continue;
        }
        if c.is_ascii_whitespace() && !pre {
            space = true;
        } else {
            if space && !out.is_empty() && !out.ends_with('\n') {
                out.push(' ');
            }
            space = false;
            out.push(c);
        }
    }
    out.trim_start_matches(|c: char| c.is_ascii_whitespace())
        .to_owned()
}
