//! Workglen replication operations, preserving the existing bincode 1.3
//! fixed-integer/little-endian byte format. This is a codec for `Vec<Op>` only.
//! It is not a general-purpose serializer or a database migration format.
use crate::store::Op;

pub const MAX_ENCODED_BYTES: usize = 24 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Truncated,
    InvalidLength,
    InvalidOption,
    InvalidUtf8,
    TrailingBytes,
    Allocation,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "replication transaction exceeds 24 MiB",
            Self::Truncated => "truncated replication transaction",
            Self::InvalidLength => "invalid replication length",
            Self::InvalidOption => "invalid replication option tag",
            Self::InvalidUtf8 => "replication key is not UTF-8",
            Self::TrailingBytes => "trailing replication bytes",
            Self::Allocation => "cannot allocate replication transaction",
        })
    }
}
impl std::error::Error for Error {}

/// Encode exactly the historical format, validating the size before allocating.
pub fn encode(operations: &[Op]) -> Result<Vec<u8>, Error> {
    let mut size = 8usize;
    for op in operations {
        for part in [8, op.key.len(), 1] {
            size = size
                .checked_add(part)
                .filter(|n| *n <= MAX_ENCODED_BYTES)
                .ok_or(Error::TooLarge)?;
        }
        if let Some(value) = &op.value {
            size = size
                .checked_add(8)
                .and_then(|n| n.checked_add(value.len()))
                .filter(|n| *n <= MAX_ENCODED_BYTES)
                .ok_or(Error::TooLarge)?;
        }
    }
    let mut out = Vec::new();
    out.try_reserve_exact(size).map_err(|_| Error::Allocation)?;
    put_length(&mut out, operations.len())?;
    for op in operations {
        put_length(&mut out, op.key.len())?;
        out.extend_from_slice(op.key.as_bytes());
        match &op.value {
            None => out.push(0),
            Some(value) => {
                out.push(1);
                put_length(&mut out, value.len())?;
                out.extend_from_slice(value);
            }
        }
    }
    Ok(out)
}

fn put_length(out: &mut Vec<u8>, length: usize) -> Result<(), Error> {
    out.extend_from_slice(
        &u64::try_from(length)
            .map_err(|_| Error::InvalidLength)?
            .to_le_bytes(),
    );
    Ok(())
}

struct Reader<'a> {
    remaining: &'a [u8],
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let (value, rest) = self
            .remaining
            .split_at_checked(length)
            .ok_or(Error::Truncated)?;
        self.remaining = rest;
        Ok(value)
    }
    fn length(&mut self) -> Result<usize, Error> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| Error::Truncated)?;
        usize::try_from(u64::from_le_bytes(bytes)).map_err(|_| Error::InvalidLength)
    }
    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let length = self.length()?;
        self.take(length)
    }
    fn operation(&mut self) -> Result<(&'a str, Option<&'a [u8]>), Error> {
        let key = std::str::from_utf8(self.bytes()?).map_err(|_| Error::InvalidUtf8)?;
        let value = match self.take(1)?[0] {
            0 => None,
            1 => Some(self.bytes()?),
            _ => return Err(Error::InvalidOption),
        };
        Ok((key, value))
    }
}

/// Validate the entire bounded frame before allocating decoded operations.
/// Lengths are checked against available bytes before any reserve or copy.
pub fn decode(bytes: &[u8]) -> Result<Vec<Op>, Error> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(Error::TooLarge);
    }
    let mut reader = Reader { remaining: bytes };
    let count = reader.length()?;
    // Every operation requires an eight-byte key length and one option tag.
    if count > reader.remaining.len() / 9 {
        return Err(Error::InvalidLength);
    }
    let payload = reader.remaining;
    for _ in 0..count {
        reader.operation()?;
    }
    if !reader.remaining.is_empty() {
        return Err(Error::TrailingBytes);
    }

    let mut out = Vec::new();
    out.try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    let mut reader = Reader { remaining: payload };
    for _ in 0..count {
        let (key, value) = reader.operation()?;
        let mut owned_key = String::new();
        owned_key
            .try_reserve_exact(key.len())
            .map_err(|_| Error::Allocation)?;
        owned_key.push_str(key);
        let owned_value = if let Some(value) = value {
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(value.len())
                .map_err(|_| Error::Allocation)?;
            owned.extend_from_slice(value);
            Some(owned)
        } else {
            None
        };
        out.push(Op {
            key: owned_key,
            value: owned_value,
        });
    }
    Ok(out)
}
