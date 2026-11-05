//! Small bounded XML subset for mailbox responses. No DTD, external entities or processing instructions.
use crate::error::{Result, bail, ensure};
use std::collections::BTreeMap;
#[derive(Debug)]
pub struct Node {
    pub name: String,
    pub namespace: String,
    pub attrs: BTreeMap<String, String>,
    pub text: String,
}
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn unescape(s: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let end = rest[i..]
            .find(';')
            .ok_or_else(|| crate::error!("Invalid XML entity"))?
            + i;
        let entity = &rest[i + 1..end];
        match entity {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => {
                let n = if let Some(h) = entity.strip_prefix("#x") {
                    u32::from_str_radix(h, 16)?
                } else if let Some(d) = entity.strip_prefix('#') {
                    d.parse()?
                } else {
                    bail!("Unknown XML entity")
                };
                let c = char::from_u32(n).ok_or_else(|| crate::error!("Invalid XML character"))?;
                ensure!(
                    !c.is_control() || ['\t', '\r', '\n'].contains(&c),
                    "Invalid XML control"
                );
                out.push(c);
            }
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}
pub fn parse(raw: &[u8]) -> Result<Vec<Node>> {
    ensure!(
        raw.len() <= super::model::MAX_BODY,
        "XML response too large"
    );
    let text = std::str::from_utf8(raw)?;
    let mut rest = text.trim_start_matches('\u{feff}').trim_start();
    if rest.starts_with("<?xml ") {
        let end = rest
            .find("?>")
            .ok_or_else(|| crate::error!("Invalid XML declaration"))?;
        rest = &rest[end + 2..];
    }
    let mut nodes: Vec<Node> = Vec::new();
    let mut stack: Vec<(String, usize, BTreeMap<String, String>)> = Vec::new();
    let mut roots = 0;
    while !rest.is_empty() {
        if !rest.starts_with('<') {
            let end = rest.find('<').unwrap_or(rest.len());
            let s = unescape(&rest[..end])?;
            if let Some((_, index, _)) = stack.last() {
                nodes[*index].text.push_str(&s);
            } else {
                ensure!(s.trim().is_empty(), "Text outside XML root");
            }
            rest = &rest[end..];
            continue;
        }
        if rest.starts_with("<!--") {
            let end = rest
                .find("-->")
                .ok_or_else(|| crate::error!("Invalid XML comment"))?;
            ensure!(!rest[4..end].contains("--"), "Invalid XML comment");
            rest = &rest[end + 3..];
            continue;
        }
        ensure!(
            !rest.starts_with("<!") && !rest.starts_with("<?"),
            "DTD, entities, CDATA and processing instructions refused"
        );
        let mut quote = None;
        let mut end = None;
        for (i, c) in rest.char_indices().skip(1) {
            if let Some(q) = quote {
                if c == q {
                    quote = None
                }
            } else if c == '\'' || c == '"' {
                quote = Some(c)
            } else if c == '>' {
                end = Some(i);
                break;
            }
        }
        let end = end.ok_or_else(|| crate::error!("Unclosed XML tag"))?;
        let tag = &rest[1..end];
        rest = &rest[end + 1..];
        if let Some(name) = tag.strip_prefix('/') {
            let (open, _, _) = stack
                .pop()
                .ok_or_else(|| crate::error!("Unexpected XML close"))?;
            ensure!(name.trim() == open, "Mismatched XML close");
            continue;
        }
        let single = tag.ends_with('/');
        let tag = if single { &tag[..tag.len() - 1] } else { tag };
        let i = tag.find(char::is_whitespace).unwrap_or(tag.len());
        let qname = &tag[..i];
        ensure!(
            !qname.is_empty()
                && qname
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_:.-".contains(&b)),
            "Invalid XML name"
        );
        let mut attributes = BTreeMap::new();
        let mut tail = &tag[i..];
        while !tail.trim().is_empty() {
            tail = tail.trim_start();
            let at = tail
                .find('=')
                .ok_or_else(|| crate::error!("Invalid XML attribute"))?;
            let key = tail[..at].trim();
            ensure!(
                !key.is_empty()
                    && key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_:.-".contains(&b)),
                "Invalid XML attribute name"
            );
            tail = tail[at + 1..].trim_start();
            let q = tail
                .chars()
                .next()
                .ok_or_else(|| crate::error!("Missing XML value"))?;
            ensure!(q == '\'' || q == '"', "Unquoted XML value");
            tail = &tail[1..];
            let end = tail
                .find(q)
                .ok_or_else(|| crate::error!("Unclosed XML attribute"))?;
            ensure!(!tail[..end].contains('<'), "Invalid XML attribute content");
            ensure!(
                attributes
                    .insert(key.to_string(), unescape(&tail[..end])?)
                    .is_none(),
                "Duplicate XML attribute"
            );
            ensure!(attributes.len() <= 64, "XML attribute limit");
            tail = &tail[end + 1..];
        }
        let mut ns = stack.last().map(|(_, _, n)| n.clone()).unwrap_or_default();
        for (k, v) in &attributes {
            if k == "xmlns" {
                ns.insert(String::new(), v.clone());
            } else if let Some(k) = k.strip_prefix("xmlns:") {
                ns.insert(k.to_string(), v.clone());
            }
        }
        let (prefix, name) = qname.split_once(':').unwrap_or(("", qname));
        ensure!(!name.contains(':'), "Invalid XML qualified name");
        let namespace = ns.get(prefix).cloned().unwrap_or_default();
        ensure!(
            prefix.is_empty() || !namespace.is_empty(),
            "Unbound XML namespace"
        );
        if stack.is_empty() {
            roots += 1;
            ensure!(roots == 1, "Multiple XML roots");
        }
        let index = nodes.len();
        nodes.push(Node {
            name: name.into(),
            namespace,
            attrs: attributes,
            text: String::new(),
        });
        ensure!(
            nodes.len() <= 20000 && stack.len() < 32,
            "XML structural limit"
        );
        if !single {
            stack.push((qname.into(), index, ns));
        }
    }
    ensure!(stack.is_empty() && roots == 1, "Incomplete XML document");
    Ok(nodes)
}
