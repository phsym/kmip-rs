use std::{borrow::BorrowMut, slice::SliceIndex};

use task_local_extensions::Extensions;

use crate::{Decoder, Error, Expected, Result, Tag, Type};

pub struct TtlvDecoder<'a, E: BorrowMut<Extensions>> {
    buf: &'a [u8],
    ext: E,
}

impl<'a> TtlvDecoder<'a, Extensions> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            ext: Extensions::new(),
        }
    }
}

impl<E: BorrowMut<Extensions>> TtlvDecoder<'_, E> {
    fn get<I: SliceIndex<[u8]>>(&self, index: I) -> Result<&I::Output> {
        self.buf.get(index).ok_or(Error::EOF)
    }

    fn next(&mut self) -> Result<()> {
        self.buf = self.buf.get(8 + self.padded_len()?..).ok_or(Error::EOF)?;
        // self.validate()
        Ok(())
    }

    pub fn padded_len(&self) -> Result<usize> {
        let l = self.len()?;
        Ok(l + crate::pad_for_len(l))
    }

    fn raw_tag(&self) -> Result<u32> {
        // self.assert_not_eof()?;
        let bytes = self.get(0..3)?;
        let raw = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);

        //TODO: Validate in the Tag constructor instead
        let th = (raw >> 16) & 0xFF;
        if th != 0x42 && th != 0x54 {
            return Err(Error::InvalidTag(raw.into()));
        }
        Ok(raw)
    }

    fn len(&self) -> Result<usize> {
        // self.assert_not_eof()?;
        Ok(u32::from_be_bytes(self.get(4..8)?.try_into()?) as usize)
    }

    fn value(&self) -> Result<&[u8]> {
        // self.assert_not_eof()?;
        self.get(8..8 + self.len()?)
    }

    fn assert_type(&self, ty: Type, tag: &impl Tag) -> Result<()> {
        if !self.tag()?.matches(tag) {
            return Err(Error::UnexpectedTag {
                got: self.tag()?.into(),
                expected: Expected::Only(tag.raw().to_owned()),
            });
        }
        if self.get_type()? != ty {
            return Err(Error::UnexpectedType {
                got: self.get_type()?,
                expected: Expected::Only(ty),
                tag: tag.raw().to_owned(),
            });
        }
        // TODO: Ensure the length match the type's expected length if applicable
        Ok(())
    }
}

impl<E: BorrowMut<Extensions>> Decoder for TtlvDecoder<'_, E> {
    type StructDecoder<'b> = TtlvDecoder<'b, &'b mut Extensions>;

    type Tag = u32;

    fn extensions(&mut self) -> &mut Extensions {
        self.ext.borrow_mut()
    }

    fn tag(&self) -> Result<Self::Tag> {
        self.raw_tag()
    }

    fn get_type(&self) -> Result<Type> {
        Type::try_from(*self.get(3)?)
    }

    fn read_struct<T>(
        &mut self,
        tag: impl Tag,
        f: impl FnOnce(&mut Self::StructDecoder<'_>) -> Result<T>,
    ) -> Result<T> {
        self.assert_type(Type::Structure, &tag)?;
        let v = match f(&mut TtlvDecoder {
            buf: self.buf.get(8..8 + self.len()?).ok_or(Error::EOF)?, // TODO: Use value() method
            ext: self.ext.borrow_mut(),
        }) {
            Ok(v) => v,
            e @ Err(Error::InvalidStruct(..)) => return e,
            Err(e) => return Err(Error::InvalidStruct(tag.raw().to_owned(), Box::new(e))),
        };
        self.next()?;
        Ok(v)
    }

    fn read_integer(&mut self, tag: impl Tag) -> Result<i32> {
        self.assert_type(Type::Integer, &tag)?;
        let v = i32::from_be_bytes(self.value()?.try_into()?);
        self.next()?;
        Ok(v)
    }

    fn read_long(&mut self, tag: impl Tag) -> Result<i64> {
        self.assert_type(Type::LongInteger, &tag)?;
        let v = i64::from_be_bytes(self.value()?.try_into()?);
        self.next()?;
        Ok(v)
    }

    fn read_bigint(&mut self, tag: impl Tag) -> Result<Vec<u8>> {
        self.assert_type(Type::BigInteger, &tag)?;
        let v = self.value()?.to_vec();
        //TODO: Strip padding ?
        self.next()?;
        Ok(v)
    }

    fn read_enum(&mut self, tag: impl Tag) -> Result<u32> {
        self.assert_type(Type::Enumeration, &tag)?;
        let v = u32::from_be_bytes(self.value()?.try_into()?);
        self.next()?;
        Ok(v)
    }

    fn read_bool(&mut self, tag: impl Tag) -> Result<bool> {
        self.assert_type(Type::Boolean, &tag)?;
        let bytes: [u8; 8] = self.value()?.try_into()?;
        let v = bytes[7] != 0;
        self.next()?;
        Ok(v)
    }

    fn read_string(&mut self, tag: impl Tag) -> Result<String> {
        self.assert_type(Type::TextString, &tag)?;
        let v = String::from_utf8(self.value()?.to_vec())?;
        self.next()?;
        Ok(v)
    }

    fn read_bytes(&mut self, tag: impl Tag) -> Result<Vec<u8>> {
        self.assert_type(Type::ByteString, &tag)?;
        let v = self.value()?.to_vec();
        self.next()?;
        Ok(v)
    }

    fn read_datetime(&mut self, tag: impl Tag) -> Result<i64> {
        self.assert_type(Type::DateTime, &tag)?;
        let v = i64::from_be_bytes(self.value()?.try_into()?);
        self.next()?;
        Ok(v)
    }

    fn read_interval(&mut self, tag: impl Tag) -> Result<u32> {
        self.assert_type(Type::Interval, &tag)?;
        let v = u32::from_be_bytes(self.value()?.try_into()?);
        self.next()?;
        Ok(v)
    }

    fn read_bitmask<B: crate::Bitmask>(&mut self, tag: impl Tag) -> Result<B> {
        let n = self.read_integer(tag)?;
        B::from_units(std::iter::once(crate::BitmaskUnit::Unnamed(n as u32)))
    }
}

#[cfg(test)]
mod tests {
    use std::time;

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        data_encoding::HEXUPPER
            .decode(s.replace([' ', '|'], "").to_uppercase().as_bytes())
            .unwrap()
    }

    #[test]
    fn test_decode_integer() {
        let input = hex("42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00");
        let mut dec = TtlvDecoder::new(&input);
        let v = dec.read_integer(0x420020).unwrap();
        assert_eq!(8, v);
        // let e = dec.read_integer(0x420020).unwrap_err();
        // assert!(matches!(e, Error::EOF));
    }

    #[test]
    fn test_decode_long() {
        let input = hex("42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00");
        let mut dec = TtlvDecoder::new(&input);
        let v = dec.read_long(0x420020).unwrap();
        assert_eq!(123456789000000000, v);
        // let e = dec.read_integer(0x420020).unwrap_err();
        // assert!(matches!(e, Error::EOF));
    }

    #[test]
    fn test_decode_enum() {
        let input = hex("42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00");
        let mut dec = TtlvDecoder::new(&input);
        let v = dec.read_enum(0x420020).unwrap();
        assert_eq!(255, v);
        // let e = dec.read_integer(0x420020).unwrap_err();
        // assert!(matches!(e, Error::EOF));
    }

    #[test]
    fn test_decode_boolean() {
        let input = hex("42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 01");
        let mut dec = TtlvDecoder::new(&input);
        let v = dec.read_bool(0x420020).unwrap();
        assert!(v);
        // let e = dec.read_integer(0x420020).unwrap_err();
        // assert!(matches!(e, Error::EOF));

        let input = hex("42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 00");
        let mut dec = TtlvDecoder::new(&input);
        let v = dec.read_bool(0x420020).unwrap();
        assert!(!v);
        // let e = dec.read_integer(0x420020).unwrap_err();
        // assert!(matches!(e, Error::EOF));
    }

    #[test]
    fn test_decode_boolean_malformed_short_value() {
        // Boolean type (0x06) with length 3 instead of the required 8.
        // Tag=0x420020, Type=Boolean(0x06), Length=3, Value=0x01 0x02 0x03 + 5 pad bytes
        let input = hex("42 00 20 | 06 | 00 00 00 03 | 01 02 03 00 00 00 00 00");
        let mut dec = TtlvDecoder::new(&input);
        let err = dec.read_bool(0x420020).unwrap_err();
        assert!(matches!(err, Error::ValueTooShort(_)));
    }

    #[test]
    fn test_decode_string() {
        let input =
            hex("42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00 00 00");
        let mut dec = TtlvDecoder::new(&input);
        let v = dec.read_string(0x420020).unwrap();
        assert_eq!("Hello World", v);
        // let e = dec.read_integer(0x420020).unwrap_err();
        // assert!(matches!(e, Error::EOF));
    }

    #[test]
    fn test_decode_byte_string() {
        let input = hex("42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00");
        let mut dec = TtlvDecoder::new(&input);
        let v = dec.read_bytes(0x420020).unwrap();
        assert_eq!(&[0x01, 0x02, 0x03], &v[..]);
        // let e = dec.read_integer(0x420020).unwrap_err();
        // assert!(matches!(e, Error::EOF));
    }

    #[test]
    fn test_decode_interval() {
        let input = hex("42 00 20 | 0A | 00 00 00 04 | 00 0D 2F 00 00 00 00 00");
        let mut dec = TtlvDecoder::new(&input);
        let v = dec.read_interval(0x420020).unwrap();
        assert_eq!(chrono::Duration::days(10).num_seconds() as u32, v);
        // let e = dec.read_integer(0x420020).unwrap_err();
        // assert!(matches!(e, Error::EOF));

        let mut dec = TtlvDecoder::new(&input);
        let v = dec.tag_decode::<time::Duration>(0x420020).unwrap();
        assert_eq!(time::Duration::from_secs(10 * 24 * 60 * 60), v);
        // let e = dec.read_integer(0x420020).unwrap_err();
        // assert!(matches!(e, Error::EOF));

        #[cfg(feature = "chrono")]
        {
            let mut dec = TtlvDecoder::new(&input);
            let v = dec.tag_decode::<chrono::Duration>(0x420020).unwrap();
            assert_eq!(chrono::Duration::days(10), v);
            // let e = dec.read_integer(0x420020).unwrap_err();
            // assert!(matches!(e, Error::EOF));
        }
    }

    #[test]
    fn test_decode_datetime() {
        let input = hex("42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8");
        let dt = chrono::NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(2008, 3, 14).unwrap(),
            chrono::NaiveTime::from_hms_opt(11, 56, 40).unwrap(),
        );

        let mut dec = TtlvDecoder::new(&input);
        let v = dec.read_datetime(0x420020).unwrap();
        assert_eq!(dt.and_utc().timestamp(), v);
        // let e = dec.read_integer(0x420020).unwrap_err();
        // assert!(matches!(e, Error::EOF));

        #[cfg(feature = "chrono")]
        {
            let mut dec = TtlvDecoder::new(&input);
            let v = dec.tag_decode::<chrono::NaiveDateTime>(0x420020).unwrap();
            assert_eq!(dt, v);
            // let e = dec.read_integer(0x420020).unwrap_err();
            // assert!(matches!(e, Error::EOF));

            let mut dec = TtlvDecoder::new(&input);
            let v = dec
                .tag_decode::<chrono::DateTime<chrono::Utc>>(0x420020)
                .unwrap();
            assert_eq!(dt.and_utc(), v);
            // let e = dec.read_integer(0x420020).unwrap_err();
            // assert!(matches!(e, Error::EOF));

            let mut dec = TtlvDecoder::new(&input);
            let v = dec
                .tag_decode::<chrono::DateTime<chrono::Local>>(0x420020)
                .unwrap();
            assert_eq!(dt.and_utc(), v);
            // let e = dec.read_integer(0x420020).unwrap_err();
            // assert!(matches!(e, Error::EOF));
        }
    }

    #[test]
    fn test_encode_struct() {
        let input = hex(
            "42 00 20 | 01 | 00 00 00 20 | 42 00 04 | 05 | 00 00 00 04 | 00 00 00 FE 00 00 00 00 | 42 00 05 | 02 | 00 00 00 04 | 00 00 00 FF 00 00 00 00",
        );
        let mut dec = TtlvDecoder::new(&input);
        dec.read_struct(0x420020, |d| {
            assert_eq!(254, d.read_enum(0x420004).unwrap());
            assert_eq!(255, d.read_integer(0x420005).unwrap());
            Ok(())
        })
        .unwrap();
        // let e = dec.read_integer(0x420020).unwrap_err();
        // assert!(matches!(e, Error::EOF));
    }
}
