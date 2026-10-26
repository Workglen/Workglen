//! First-party, bounded comma-separated records for accounting imports.
//! Preserves existing comma/double-quote, CR/LF, BOM, Unicode trimming and
//! equal-width record behavior. This is not a general CSV/Serde framework.
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(&'static str);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}

pub struct Reader<'a> {
    input: &'a [u8],
    at: usize,
    headers: Vec<String>,
    rows: usize,
    max_rows: usize,
}
impl<'a> Reader<'a> {
    pub fn new(text: &'a str, max_bytes: usize, max_rows: usize) -> Result<Self, Error> {
        if text.len() > max_bytes {
            return Err(Error("CSV exceeds input size limit"));
        }
        let mut reader = Self {
            input: text.strip_prefix('\u{feff}').unwrap_or(text).as_bytes(),
            at: 0,
            headers: Vec::new(),
            rows: 0,
            max_rows,
        };
        reader.headers = reader.record()?.unwrap_or_default();
        Ok(reader)
    }
    pub fn headers(&self) -> &[String] {
        &self.headers
    }
    fn record(&mut self) -> Result<Option<Vec<String>>, Error> {
        while self.at < self.input.len() && matches!(self.input[self.at], b'\r' | b'\n') {
            self.at += 1;
        }
        if self.at == self.input.len() {
            return Ok(None);
        }
        let mut fields = Vec::new();
        let mut field = Vec::new();
        let mut quoted = false;
        let mut start = true;
        loop {
            if self.at == self.input.len() {
                push(&mut fields, field)?;
                return Ok(Some(fields));
            }
            let b = self.input[self.at];
            self.at += 1;
            if quoted {
                if b == b'"' {
                    if self.input.get(self.at) == Some(&b'"') {
                        field.push(b'"');
                        self.at += 1;
                    } else {
                        quoted = false;
                    }
                } else {
                    field.push(b);
                }
                continue;
            }
            if start && b == b'"' {
                quoted = true;
                start = false;
                continue;
            }
            if b == b',' {
                push(&mut fields, std::mem::take(&mut field))?;
                start = true;
            } else if b == b'\r' || b == b'\n' {
                push(&mut fields, field)?;
                return Ok(Some(fields));
            } else {
                field.push(b);
                start = false;
            }
        }
    }
}
fn push(fields: &mut Vec<String>, bytes: Vec<u8>) -> Result<(), Error> {
    // One million short columns could otherwise amplify a small hostile input.
    if fields.len() >= 4096 {
        return Err(Error("CSV exceeds 4096 columns"));
    }
    let text = String::from_utf8(bytes).map_err(|_| Error("Invalid UTF-8 CSV field"))?;
    fields.push(text.trim().to_string());
    Ok(())
}
impl Iterator for Reader<'_> {
    type Item = Result<Vec<String>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.record() {
            Ok(None) => None,
            Err(e) => {
                self.at = self.input.len();
                Some(Err(e))
            }
            Ok(Some(row)) => {
                self.rows += 1;
                if self.rows > self.max_rows {
                    self.at = self.input.len();
                    Some(Err(Error("CSV exceeds record limit")))
                } else if row.len() != self.headers.len() {
                    self.at = self.input.len();
                    Some(Err(Error(
                        "CSV record has a different number of columns than its header",
                    )))
                } else {
                    Some(Ok(row))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multiline_quotes_empty_fields_and_unicode_whitespace() {
        let text = "\u{feff} name , note, amount\r\n\"  A, B  \",\"line 1\r\nline \"\"two\"\"\",12.30\r\n\u{a0}C\u{2003},,0\n";
        let mut r = Reader::new(text, 4096, 10).unwrap();
        assert_eq!(r.headers(), ["name", "note", "amount"]);
        assert_eq!(
            r.next().unwrap().unwrap(),
            ["A, B", "line 1\r\nline \"two\"", "12.30"]
        );
        assert_eq!(r.next().unwrap().unwrap(), ["C", "", "0"]);
        assert!(r.next().is_none());
    }
    #[test]
    fn widths_and_resource_limits_are_checked() {
        assert!(Reader::new("abc", 2, 10).is_err());
        let mut r = Reader::new("a,b\n1\n", 100, 10).unwrap();
        assert!(r.next().unwrap().is_err());
        assert!(r.next().is_none());
        let mut r = Reader::new("a\n1\n2", 100, 1).unwrap();
        assert!(r.next().unwrap().is_ok());
        assert!(r.next().unwrap().is_err());
        assert!(Reader::new(&",".repeat(4096), 10000, 10).is_err());
    }
    #[test]
    fn inherited_permissive_quote_and_empty_line_behavior() {
        let mut r = Reader::new("\r\nA,B\n\n\"x\"tail,z\r\n\"open,field", 100, 10).unwrap();
        assert_eq!(r.next().unwrap().unwrap(), ["xtail", "z"]);
        assert!(r.next().unwrap().is_err());
        assert_eq!(
            Reader::new("x\n\"open", 100, 10)
                .unwrap()
                .next()
                .unwrap()
                .unwrap(),
            ["open"]
        );
        assert_eq!(
            Reader::new("a,b\n,", 100, 10)
                .unwrap()
                .next()
                .unwrap()
                .unwrap(),
            ["", ""]
        );
    }
}
