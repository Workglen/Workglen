//! Bounded first-party email, MIME and legacy charset decoding.
//! Official Unicode/WHATWG mapping data retains its attribution; no external crates.
use std::borrow::Cow;
mod address;
mod charset;
mod header;
mod html;
mod parse;
mod transfer;
pub use parse::{Limits, MessageParser};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Addr<'a> {
    pub name: Option<Cow<'a, str>>,
    pub address: Option<Cow<'a, str>>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Address<'a>(pub Vec<Addr<'a>>);
impl<'a> Address<'a> {
    pub fn iter(&self) -> std::slice::Iter<'_, Addr<'a>> {
        self.0.iter()
    }
    pub fn first(&self) -> Option<&Addr<'a>> {
        self.0.first()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute<'a> {
    pub name: Cow<'a, str>,
    pub value: Cow<'a, str>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentType<'a> {
    pub c_type: Cow<'a, str>,
    pub c_subtype: Option<Cow<'a, str>>,
    pub attributes: Option<Vec<Attribute<'a>>>,
}
impl ContentType<'_> {
    pub fn ctype(&self) -> &str {
        &self.c_type
    }
    pub fn subtype(&self) -> Option<&str> {
        self.c_subtype.as_deref()
    }
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .as_ref()?
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(name))
            .map(|a| a.value.as_ref())
    }
    pub fn is_attachment(&self) -> bool {
        self.c_type.eq_ignore_ascii_case("attachment")
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub tz_before_gmt: bool,
    pub tz_hour: u8,
    pub tz_minute: u8,
}
#[derive(Clone, Debug)]
pub struct Header<'a> {
    pub name: Cow<'a, str>,
    pub raw: Cow<'a, str>,
    pub value: Cow<'a, str>,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct ParsedFields<'a> {
    pub headers: Vec<Header<'a>>,
    pub from: Option<Address<'a>>,
    pub to: Option<Address<'a>>,
    pub cc: Option<Address<'a>>,
    pub bcc: Option<Address<'a>>,
    pub sender: Option<Address<'a>>,
    pub reply_to: Option<Address<'a>>,
    pub subject: Option<Cow<'a, str>>,
    pub date: Option<DateTime>,
    pub message_id: Option<Cow<'a, str>>,
    pub content_type: Option<ContentType<'a>>,
    pub disposition: Option<ContentType<'a>>,
    pub content_id: Option<Cow<'a, str>>,
    pub description: Option<Cow<'a, str>>,
    pub encoding: Option<Cow<'a, str>>,
    pub problem: bool,
}
#[derive(Clone, Debug)]
pub enum PartType<'a> {
    Text(Cow<'a, str>),
    Html(Cow<'a, str>),
    Binary(Cow<'a, [u8]>),
    InlineBinary(Cow<'a, [u8]>),
    Message(Box<Message<'a>>),
    Multipart(Vec<u32>),
}
#[derive(Clone, Debug)]
pub struct MessagePart<'a> {
    pub body: PartType<'a>,
    pub offset_header: u32,
    pub offset_body: u32,
    pub offset_end: u32,
    pub is_encoding_problem: bool,
    pub(crate) fields: ParsedFields<'a>,
}
#[derive(Clone, Debug)]
pub struct Message<'a> {
    pub raw_message: Cow<'a, [u8]>,
    pub parts: Vec<MessagePart<'a>>,
    pub(crate) text_body: Vec<u32>,
    pub(crate) html_body: Vec<u32>,
    pub(crate) attachments: Vec<u32>,
}
pub trait MimeHeaders {
    fn content_type(&self) -> Option<&ContentType<'_>>;
    fn content_disposition(&self) -> Option<&ContentType<'_>>;
    fn content_id(&self) -> Option<&str>;
    fn content_description(&self) -> Option<&str>;
    fn content_transfer_encoding(&self) -> Option<&str>;
    fn is_content_type(&self, major: &str, minor: &str) -> bool {
        self.content_type().is_some_and(|c| {
            c.ctype().eq_ignore_ascii_case(major)
                && c.subtype().is_some_and(|s| s.eq_ignore_ascii_case(minor))
        })
    }
    fn attachment_name(&self) -> Option<&str> {
        self.content_disposition()
            .and_then(|c| c.attribute("filename"))
            .or_else(|| self.content_type().and_then(|c| c.attribute("name")))
    }
}
impl MimeHeaders for MessagePart<'_> {
    fn content_type(&self) -> Option<&ContentType<'_>> {
        self.fields.content_type.as_ref()
    }
    fn content_disposition(&self) -> Option<&ContentType<'_>> {
        self.fields.disposition.as_ref()
    }
    fn content_id(&self) -> Option<&str> {
        self.fields.content_id.as_deref()
    }
    fn content_description(&self) -> Option<&str> {
        self.fields.description.as_deref()
    }
    fn content_transfer_encoding(&self) -> Option<&str> {
        self.fields.encoding.as_deref()
    }
}
impl MessagePart<'_> {
    pub fn contents(&self) -> &[u8] {
        match &self.body {
            PartType::Text(v) | PartType::Html(v) => v.as_bytes(),
            PartType::Binary(v) | PartType::InlineBinary(v) => v,
            PartType::Message(m) => &m.raw_message,
            PartType::Multipart(_) => &[],
        }
    }
    pub fn text_contents(&self) -> Option<&str> {
        match &self.body {
            PartType::Text(v) | PartType::Html(v) => Some(v),
            _ => None,
        }
    }
}
impl<'a> Message<'a> {
    pub fn root_part(&self) -> &MessagePart<'a> {
        &self.parts[0]
    }
    pub fn header_raw(&self, name: &str) -> Option<&str> {
        self.parts[0]
            .fields
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.raw.as_ref())
    }
    pub fn headers_raw(&self) -> impl Iterator<Item = (&str, &str)> {
        self.parts[0]
            .fields
            .headers
            .iter()
            .map(|h| (h.name.as_ref(), h.raw.as_ref()))
    }
    pub fn from(&self) -> Option<&Address<'a>> {
        self.parts[0].fields.from.as_ref()
    }
    pub fn to(&self) -> Option<&Address<'a>> {
        self.parts[0].fields.to.as_ref()
    }
    pub fn cc(&self) -> Option<&Address<'a>> {
        self.parts[0].fields.cc.as_ref()
    }
    pub fn bcc(&self) -> Option<&Address<'a>> {
        self.parts[0].fields.bcc.as_ref()
    }
    pub fn sender(&self) -> Option<&Address<'a>> {
        self.parts[0].fields.sender.as_ref()
    }
    pub fn reply_to(&self) -> Option<&Address<'a>> {
        self.parts[0].fields.reply_to.as_ref()
    }
    pub fn subject(&self) -> Option<&str> {
        self.parts[0].fields.subject.as_deref()
    }
    pub fn date(&self) -> Option<&DateTime> {
        self.parts[0].fields.date.as_ref()
    }
    pub fn message_id(&self) -> Option<&str> {
        self.parts[0].fields.message_id.as_deref()
    }
    pub fn body_text(&self, index: usize) -> Option<Cow<'_, str>> {
        if let Some(id) = self.text_body.get(index) {
            return self.parts[*id as usize].text_contents().map(Cow::Borrowed);
        }
        let id = *self.html_body.get(index)?;
        self.parts[id as usize]
            .text_contents()
            .map(|s| Cow::Owned(html::to_text(s)))
    }
    pub fn body_html(&self, index: usize) -> Option<Cow<'_, str>> {
        let id = *self.html_body.get(index)?;
        self.parts[id as usize].text_contents().map(Cow::Borrowed)
    }
    pub fn attachment(&self, index: u32) -> Option<&MessagePart<'a>> {
        self.attachments
            .get(index as usize)
            .map(|i| &self.parts[*i as usize])
    }
    pub fn attachments(&self) -> impl Iterator<Item = &MessagePart<'a>> {
        self.attachments.iter().map(|i| &self.parts[*i as usize])
    }
    pub fn attachment_count(&self) -> usize {
        self.attachments.len()
    }
}
