use std::{fmt::Display, io::Write};

use crate::{Bitmask, Error, Tag, Type};

use super::{Encodable, Encoder};
use chrono::Duration;
use task_local_extensions::Extensions;

#[derive(Default)]
pub struct TextEncoder {
    buf: Vec<u8>,
    ext: Extensions,
    indent: usize,
    no_type: bool,
}

impl TextEncoder {
    pub fn encode_to_string(v: &impl Encodable) -> crate::Result<String> {
        let mut enc = Self::new();
        enc.encode(v)?;
        Ok(enc.into_string())
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn without_type(mut self, b: bool) -> Self {
        self.no_type = b;
        self
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    pub fn into_string(self) -> String {
        // Unwrapping here as the buffer is internal and must
        // always hold valid UTF8 encoded data.
        String::from_utf8(self.into_inner()).unwrap()
    }

    fn write_indent(&mut self) {
        for _ in 0..self.indent {
            write!(self.buf, "    ").unwrap();
        }
    }

    fn start_elem(&mut self, ty: Type, tag: impl Tag) -> crate::Result<()> {
        if !self.buf.is_empty() {
            writeln!(self.buf).unwrap();
        }
        self.write_indent();
        let tg = match tag.name() {
            Some(name) => name.to_string(),
            None => format!("{:#08X}", tag.numeric_or_err()?),
        };
        write!(self.buf, "{tg}").unwrap();
        if !self.no_type {
            write!(self.buf, " ({ty})").unwrap();
        }
        write!(self.buf, ": ").unwrap();
        Ok(())
    }

    fn end_elem(&mut self) {
        // writeln!(self.buf).unwrap();
    }

    fn encode_raw_fn(
        &mut self,
        ty: Type,
        tag: impl Tag,
        value: impl FnOnce(&mut Vec<u8>),
    ) -> crate::Result<()> {
        self.start_elem(ty, tag)?;
        value(&mut self.buf);
        self.end_elem();
        Ok(())
    }

    fn encode_raw(&mut self, ty: Type, tag: impl Tag, value: impl Display) -> crate::Result<()> {
        self.encode_raw_fn(ty, tag, |buf| write!(buf, "{value}").unwrap())
    }
}

impl Encoder for TextEncoder {
    type StructEncoder<'b> = Self;

    fn extensions(&mut self) -> &mut Extensions {
        &mut self.ext
    }

    fn write_struct(
        &mut self,
        tag: impl Tag,
        f: impl FnOnce(&mut Self::StructEncoder<'_>) -> crate::Result<()>,
    ) -> crate::Result<()> {
        self.start_elem(Type::Structure, tag)?;
        self.indent += 1;
        let olen = self.buf.len();
        f(self)?;
        if olen == self.buf.len() {
            writeln!(self.buf).unwrap();
            self.write_indent();
            write!(self.buf, "... empty ...").unwrap();
        }
        self.indent -= 1;
        Ok(())
    }

    fn write_integer(&mut self, tag: impl Tag, value: i32) -> crate::Result<()> {
        self.encode_raw(Type::Integer, tag, value)
    }

    fn write_long(&mut self, tag: impl Tag, value: i64) -> crate::Result<()> {
        self.encode_raw(Type::LongInteger, tag, value)
    }

    fn write_bigint(&mut self, tag: impl Tag, num: impl AsRef<[u8]>) -> crate::Result<()> {
        let hex_data = data_encoding::HEXUPPER.encode(num.as_ref());
        self.encode_raw(Type::BigInteger, tag, hex_data)
    }

    fn write_enum(&mut self, tag: impl Tag, value: impl Tag) -> crate::Result<()> {
        if let Some(s) = value.name() {
            self.encode_raw(Type::Enumeration, tag, s)
        } else {
            let v = value.numeric_or_err()?;
            self.encode_raw_fn(Type::Enumeration, tag, |buf| {
                write!(buf, "{v:#010X}").unwrap()
            })
        }
    }

    fn write_bool(&mut self, tag: impl Tag, value: bool) -> crate::Result<()> {
        self.encode_raw(Type::Boolean, tag, value)
    }

    fn write_string(&mut self, tag: impl Tag, s: impl AsRef<str>) -> crate::Result<()> {
        self.encode_raw(Type::TextString, tag, s.as_ref())
    }

    fn write_bytes(&mut self, tag: impl Tag, s: impl AsRef<[u8]>) -> crate::Result<()> {
        let hex_data = data_encoding::HEXUPPER.encode(s.as_ref());
        self.encode_raw(Type::ByteString, tag, hex_data)
    }

    fn write_datetime(&mut self, tag: impl Tag, date: i64) -> crate::Result<()> {
        let dt =
            chrono::DateTime::from_timestamp(date, 0).ok_or(Error::DateTimeOutOfRange(date))?;
        self.encode_raw(
            Type::DateTime,
            tag,
            dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        )
    }

    fn write_interval(&mut self, tag: impl Tag, seconds: u32) -> crate::Result<()> {
        let dur = Duration::seconds(seconds.into());
        let mut sdur = Vec::new();

        if dur.num_days() > 0 {
            write!(sdur, "{}d", dur.num_days()).unwrap();
        }
        if dur.num_hours() % 24 > 0 {
            write!(sdur, "{}h", dur.num_hours() % 24).unwrap();
        }
        if dur.num_minutes() % 60 > 0 {
            write!(sdur, "{}m", dur.num_minutes() % 60).unwrap();
        }
        if sdur.is_empty() || dur.num_seconds() % 60 > 0 {
            write!(sdur, "{}s", dur.num_seconds() % 60).unwrap();
        }
        self.encode_raw(Type::Interval, tag, String::from_utf8(sdur).unwrap())
    }

    fn write_bitmask(&mut self, tag: impl Tag, value: impl Bitmask) -> crate::Result<()> {
        self.encode_raw(Type::Integer, tag, value.format(" | "))
    }
}

#[cfg(test)]
mod tests {
    use crate::BigInteger;

    use super::*;

    crate::bitmask! {
        #[derive(Clone, Copy)]
        struct MyBitmask: u32 {
            const Foo = 1;
            const Bar = 2;
        }
    }

    #[test]
    fn test_text_encoder() -> crate::Result<()> {
        let dt = chrono::NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(2024, 9, 16).unwrap(),
            chrono::NaiveTime::from_hms_opt(15, 7, 42).unwrap(),
        );
        let mut enc = TextEncoder::new();
        enc.write_struct("Toto", |enc| {
            enc.write_integer(0x2341, 12)?;
            enc.write_long(0x7634, 1234567890)?;
            enc.write_bool(0x7777, true)?;
            enc.write_struct(0x3333, |_| Ok(()))?;
            enc.write_string(0x8888, "hello world")?;
            enc.write_bytes(0x9999, [1, 2, 3, 4])?;
            enc.write_datetime(0x3456, dt.and_utc().timestamp())?;
            enc.write_interval(0x8724, 3 * 60 + 42)?;
            enc.write_bigint(
                0x872573,
                BigInteger::unsigned(0xdeadbeefu64.to_be_bytes().into()).0,
            )?;
            enc.write_bigint(
                0x872574,
                BigInteger::signed((-0xdeadbeefi64).to_be_bytes().into()).0,
            )?;
            enc.write_bitmask(0x5642, 1 | 2)?;
            enc.write_bitmask(0x5643, MyBitmask::all() | MyBitmask::from_bits_retain(4))?;
            enc.write_enum(0x67342, 12)?;
            Ok(())
        })?;

        let expect = "Toto (Structure): 
    0x002341 (Integer): 12
    0x007634 (LongInteger): 1234567890
    0x007777 (Boolean): true
    0x003333 (Structure): 
        ... empty ...
    0x008888 (TextString): hello world
    0x009999 (ByteString): 01020304
    0x003456 (DateTime): 2024-09-16T15:07:42Z
    0x008724 (Interval): 3m42s
    0x872573 (BigInteger): 00000000DEADBEEF
    0x872574 (BigInteger): FFFFFFFF21524111
    0x005642 (Integer): 0x00000001 | 0x00000002
    0x005643 (Integer): Foo | Bar | 0x00000004
    0x067342 (Enumeration): 0x0000000C";
        assert_eq!(expect, enc.into_string());
        Ok(())
    }

    #[test]
    fn test_datetime_out_of_range_errors() {
        let mut enc = TextEncoder::new();
        let err = enc.write_datetime(0x420020, i64::MAX).unwrap_err();
        assert!(matches!(err, Error::DateTimeOutOfRange(_)));
    }
}
