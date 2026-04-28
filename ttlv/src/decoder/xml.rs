use std::borrow::{BorrowMut, Cow};

use data_encoding::HEXUPPER_PERMISSIVE;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use task_local_extensions::Extensions;

use crate::{BitmaskUnit, Decoder, Error, Expected, RawTag, Result, Tag, Type};

/// [`Decoder`] for the XML representation produced by [`XmlEncoder`](crate::XmlEncoder).
///
/// Reads from a `&[u8]` slice using `quick-xml` and yields tags as
/// [`RawTag`]s — a tag is taken from the element's local name (with an
/// `0xXXXXXX` prefix recognized as a numeric tag) and falls back to the
/// `tag` attribute on `<TTLV>` elements.
pub struct XmlDecoder<'a, E: BorrowMut<Extensions>> {
    reader: quick_xml::Reader<&'a [u8]>,
    evt: Option<Event<'a>>,
    ext: E,
}

impl<'a> XmlDecoder<'a, Extensions> {
    /// Creates a decoder reading XML from `buf`. Fails if the first event
    /// cannot be read.
    pub fn new(buf: &'a [u8]) -> Result<Self> {
        let mut dec = Self {
            reader: quick_xml::Reader::from_reader(buf),
            evt: None,
            ext: Extensions::new(),
        };
        dec.next()?;
        Ok(dec)
    }
}

impl<'a, E: BorrowMut<Extensions>> XmlDecoder<'a, E> {
    fn next(&mut self) -> Result<()> {
        if let Some(Event::End(..) | Event::Eof) = self.evt {
            // This decoder has already reached its end
            return Err(Error::EOF);
        }
        loop {
            let evt = self.reader.read_event()?;
            match evt {
                evt @ (Event::Start(..) | Event::Empty(..) | Event::End(..) | Event::Eof) => {
                    self.evt = Some(evt);
                    return Ok(());
                }
                _ => { /* Ignore everything else */ }
            }
        }
    }

    fn get_event(&self) -> &Event<'a> {
        self.evt
            .as_ref()
            .expect("XML reader not initialized. next() method must be called")
    }

    fn get_start(&self) -> Result<&BytesStart<'_>> {
        match self.get_event() {
            Event::Empty(bs) | Event::Start(bs) => Ok(bs),
            Event::Eof | Event::End(..) => Err(Error::EOF),
            other => unreachable!("Event {:?} cannot be handled", other),
        }
    }

    fn get_end(&self) -> Option<BytesEnd<'static>> {
        let Event::Start(start) = self.get_event() else {
            return None;
        };
        Some(start.to_end().into_owned())
    }

    fn get_attribute(&'a self, name: &str) -> Result<Option<Cow<'a, str>>> {
        let bs = self.get_start()?;
        let Some(attr) = bs
            .try_get_attribute(name)
            .map_err(quick_xml::Error::InvalidAttr)?
        else {
            return Ok(None);
        };
        Ok(Some(attr.decode_and_unescape_value(self.reader.decoder())?))
    }

    fn raw_tag(&'a self) -> Result<Cow<'a, str>> {
        let local = self.get_start()?.name().local_name().into_inner();
        if local != b"TTLV" {
            return Ok(Cow::Borrowed(std::str::from_utf8(local)?));
        }
        self.get_attribute("tag")?.ok_or(Error::MissingTag)
    }

    fn value(&'a self) -> Result<Cow<'a, str>> {
        self.get_attribute("value")?.ok_or(Error::MissingValue)
    }

    fn assert_type(&self, ty: Type, tag: &impl Tag) -> Result<()> {
        if !self.tag()?.matches(tag) {
            return Err(Error::UnexpectedTag {
                got: self.tag()?,
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
        Ok(())
    }
}

impl<'a, E: BorrowMut<Extensions>> Decoder for XmlDecoder<'a, E> {
    type StructDecoder<'b> = XmlDecoder<'a, &'b mut Extensions>;
    type Tag = RawTag;

    fn extensions(&mut self) -> &mut Extensions {
        self.ext.borrow_mut()
    }

    fn tag(&self) -> Result<Self::Tag> {
        let raw = self.raw_tag()?;
        if let Some(pref) = raw.strip_prefix("0x") {
            return Ok(RawTag::Num(u32::from_str_radix(pref, 16)?));
        }
        Ok(RawTag::Str(raw.to_string()))
    }

    fn get_type(&self) -> Result<Type> {
        let Some(typ) = self.get_attribute("type")? else {
            return Ok(Type::Structure);
        };
        Type::try_from(typ.as_ref()).map_err(|_| Error::InvalidTypeStr(typ.to_string()))
    }

    fn read_struct<T>(
        &mut self,
        tag: impl Tag,
        f: impl FnOnce(&mut Self::StructDecoder<'_>) -> Result<T>,
    ) -> Result<T> {
        self.assert_type(Type::Structure, &tag)?;
        let end = self.get_end();

        // Take the event
        let evt = if end.is_some() {
            // Advance the cursor into the started element
            self.next()?;
            self.evt.take()
        } else {
            Some(Event::Eof)
        };

        let mut d = XmlDecoder {
            reader: self.reader.clone(),
            evt,
            ext: self.ext.borrow_mut(),
        };
        let v = match f(&mut d) {
            Ok(v) => v,
            e @ Err(Error::InvalidStruct(..)) => return e,
            Err(e) => return Err(Error::InvalidStruct(tag.raw().to_owned(), Box::new(e))),
        };
        self.reader = d.reader;
        let evt = d.evt;
        if let Some(end) = end
            && evt != Some(Event::End(end.borrow()))
        {
            self.reader.read_to_end(end.name())?;
        }
        self.next()?;
        Ok(v)
    }

    fn read_integer(&mut self, tag: impl Tag) -> Result<i32> {
        self.assert_type(Type::Integer, &tag)?;
        // TODO: Ensure event is an empty tag
        let v = self.value()?;
        let v = if let Some(pref) = v.strip_prefix("0x") {
            i32::from_str_radix(pref, 16)?
        } else {
            v.parse()?
        };
        self.next()?;
        Ok(v)
    }

    fn read_long(&mut self, tag: impl Tag) -> Result<i64> {
        self.assert_type(Type::LongInteger, &tag)?;
        // TODO: Ensure event is an empty tag
        let v = self.value()?;
        let v = if let Some(pref) = v.strip_prefix("0x") {
            i64::from_str_radix(pref, 16)?
        } else {
            v.parse()?
        };
        self.next()?;
        Ok(v)
    }

    fn read_bigint(&mut self, tag: impl Tag) -> Result<Vec<u8>> {
        self.assert_type(Type::BigInteger, &tag)?;
        let v = HEXUPPER_PERMISSIVE.decode(self.value()?.as_bytes())?;
        self.next()?;
        Ok(v)
    }

    fn read_enum(&mut self, tag: impl Tag) -> Result<Self::Tag> {
        self.assert_type(Type::Enumeration, &tag)?;
        // TODO: Ensure event is an empty tag
        let v = self.value()?;
        let v = if let Some(pref) = v.strip_prefix("0x") {
            u32::from_str_radix(pref, 16)?.into()
        } else {
            v.parse()
                .map(RawTag::Num)
                .unwrap_or(RawTag::Str(v.to_string()))
        };
        self.next()?;
        Ok(v)
    }

    fn read_bool(&mut self, tag: impl Tag) -> Result<bool> {
        self.assert_type(Type::Boolean, &tag)?;
        // TODO: Ensure event is an empty tag
        let v = self.value()?.parse()?;
        self.next()?;
        Ok(v)
    }

    fn read_string(&mut self, tag: impl Tag) -> Result<String> {
        self.assert_type(Type::TextString, &tag)?;
        // TODO: Ensure event is an empty tag
        let v = self.value()?.into();
        self.next()?;
        Ok(v)
    }

    fn read_bytes(&mut self, tag: impl Tag) -> Result<Vec<u8>> {
        self.assert_type(Type::ByteString, &tag)?;
        // TODO: Ensure event is an empty tag
        let v = self.value()?;
        let v = HEXUPPER_PERMISSIVE.decode(v.as_bytes())?;
        self.next()?;
        Ok(v)
    }

    fn read_datetime(&mut self, tag: impl Tag) -> Result<i64> {
        self.assert_type(Type::DateTime, &tag)?;
        // TODO: Ensure event is an empty tag
        let v = self.value()?;
        let v = chrono::DateTime::parse_from_rfc3339(&v)?;
        self.next()?;
        Ok(v.timestamp())
    }

    fn read_interval(&mut self, tag: impl Tag) -> Result<u32> {
        self.assert_type(Type::Interval, &tag)?;
        // TODO: Ensure event is an empty tag
        let v = self.value()?;
        let v = if let Some(pref) = v.strip_prefix("0x") {
            u32::from_str_radix(pref, 16)?
        } else {
            v.parse()?
        };
        self.next()?;
        Ok(v)
    }

    fn read_bitmask<B: crate::Bitmask>(&mut self, tag: impl Tag) -> Result<B> {
        self.assert_type(Type::Integer, &tag)?;
        // TODO: Ensure event is an empty tag
        let v = self.value()?;
        let v = v
            .split(" ")
            .map(|v| {
                if let Some(pref) = v.strip_prefix("0x") {
                    Ok::<_, crate::Error>(BitmaskUnit::Unnamed(u32::from_str_radix(pref, 16)?))
                } else {
                    Ok(v.parse()
                        .map(BitmaskUnit::Unnamed)
                        .unwrap_or(BitmaskUnit::Named(v.into())))
                }
            })
            .try_fold(B::empty(), |mut acc, v| {
                acc.insert_unit(v?)?;
                Ok::<_, crate::Error>(acc)
            })?;
        self.next()?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integer() {
        let input = r#"<TestTag type="Integer" value="12"/>"#;

        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        let i = dec.read_integer("TestTag").unwrap();
        assert_eq!(12, i)
    }

    #[test]
    fn test_integer_hex_value() {
        let input = r#"<TestTag type="Integer" value="0x0000000C"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        assert_eq!(12, dec.read_integer("TestTag").unwrap());
    }

    #[test]
    fn test_long_integer() {
        let input = r#"<MyTag type="LongInteger" value="1234567890123"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        assert_eq!(1234567890123i64, dec.read_long("MyTag").unwrap());
    }

    #[test]
    fn test_long_integer_hex() {
        let input = r#"<MyTag type="LongInteger" value="0x000000012A05F200"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        assert_eq!(5000000000i64, dec.read_long("MyTag").unwrap());
    }

    #[test]
    fn test_bigint() {
        let input = r#"<MyTag type="BigInteger" value="0102030405060708"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        assert_eq!(
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            dec.read_bigint("MyTag").unwrap()
        );
    }

    #[test]
    fn test_enum_hex() {
        let input = r#"<MyTag type="Enumeration" value="0x00000001"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        let v = dec.read_enum("MyTag").unwrap();
        assert_eq!(v, RawTag::Num(1));
    }

    #[test]
    fn test_enum_decimal() {
        let input = r#"<MyTag type="Enumeration" value="42"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        let v = dec.read_enum("MyTag").unwrap();
        assert_eq!(v, RawTag::Num(42));
    }

    #[test]
    fn test_enum_named() {
        let input = r#"<MyTag type="Enumeration" value="Active"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        let v = dec.read_enum("MyTag").unwrap();
        assert_eq!(v, RawTag::Str("Active".into()));
    }

    #[test]
    fn test_boolean_true() {
        let input = r#"<MyTag type="Boolean" value="true"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        assert!(dec.read_bool("MyTag").unwrap());
    }

    #[test]
    fn test_boolean_false() {
        let input = r#"<MyTag type="Boolean" value="false"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        assert!(!dec.read_bool("MyTag").unwrap());
    }

    #[test]
    fn test_text_string() {
        let input = r#"<MyTag type="TextString" value="Hello World"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        assert_eq!("Hello World", dec.read_string("MyTag").unwrap());
    }

    #[test]
    fn test_byte_string() {
        let input = r#"<MyTag type="ByteString" value="DEADBEEF"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        assert_eq!(
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            dec.read_bytes("MyTag").unwrap()
        );
    }

    #[test]
    fn test_datetime() {
        // 2008-03-14T11:56:40+00:00 = unix 1205495800
        let input = r#"<MyTag type="DateTime" value="2008-03-14T11:56:40+00:00"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        assert_eq!(1205495800i64, dec.read_datetime("MyTag").unwrap());
    }

    #[test]
    fn test_interval_decimal() {
        let input = r#"<MyTag type="Interval" value="3600"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        assert_eq!(3600u32, dec.read_interval("MyTag").unwrap());
    }

    #[test]
    fn test_interval_hex() {
        let input = r#"<MyTag type="Interval" value="0x00000E10"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        assert_eq!(3600u32, dec.read_interval("MyTag").unwrap());
    }

    #[test]
    fn test_bitmask_named() {
        let input = r#"<MyTag type="Integer" value="4"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        let v: i32 = dec.read_bitmask("MyTag").unwrap();
        assert_eq!(4, v);
    }

    #[test]
    fn test_bitmask_hex_value() {
        let input = r#"<MyTag type="Integer" value="0x00000004"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        let v: i32 = dec.read_bitmask("MyTag").unwrap();
        assert_eq!(4, v);
    }

    #[test]
    fn test_unexpected_tag_error() {
        let input = r#"<WrongTag type="Integer" value="1"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        let err = dec.read_integer("ExpectedTag").unwrap_err();
        assert!(matches!(err, Error::UnexpectedTag { .. }));
    }

    #[test]
    fn test_unexpected_type_error() {
        let input = r#"<MyTag type="Boolean" value="true"/>"#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        let err = dec.read_integer("MyTag").unwrap_err();
        assert!(matches!(err, Error::UnexpectedType { .. }));
    }

    #[test]
    fn test_eof_on_empty_input() {
        let input = r#""#;
        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        let err = dec.read_integer("MyTag").unwrap_err();
        assert!(matches!(err, Error::EOF));
    }

    #[test]
    fn test_numeric_tag_via_0x_prefix() {
        // Tag element with 0x prefix should be parsed as RawTag::Num
        let input = r#"<TTLV type="Integer" tag="0x420001" value="7"/>"#;
        let dec = XmlDecoder::new(input.as_bytes()).unwrap();
        let tag = dec.tag().unwrap();
        assert_eq!(tag, RawTag::Num(0x420001));
    }

    #[test]
    fn test_get_type_defaults_to_structure_when_no_type_attr() {
        // When no 'type' attribute is present, get_type() should return Structure
        let input = r#"<TTLV tag="0x420001"></TTLV>"#;
        let dec = XmlDecoder::new(input.as_bytes()).unwrap();
        assert_eq!(Type::Structure, dec.get_type().unwrap());
    }

    #[test]
    fn test_struct() {
        let input = r#"<TTLV type="Structure" tag="0x420011"/>
<TTLV type="Structure" tag="0x420011"></TTLV>
<TTLV tag="0x420001">
    <TestTag type="Integer" value="12"/>
    <TTLV type="Integer" tag="0x420003" value="0x0000000F"/>
    <TTLV type="Integer" tag="0x420004" value="0x0000000F"/>
</TTLV>
<TTLV tag="0x420001">
    <TestTag type="Integer" value="12"/>
    <TTLV type="Integer" tag="0x420003" value="0x0000000F"/>
    <TTLV type="Integer" tag="0x420004" value="0x0000000F"/>
</TTLV>
<TTLV type="Integer" tag="0x420005" value="0x00000010"/>"#;

        let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
        dec.read_struct(0x420011, |_| Ok(())).unwrap();
        dec.read_struct(0x420011, |_| Ok(())).unwrap();
        dec.read_struct(0x420001, |d| {
            assert_eq!(12, d.read_integer("TestTag")?);
            assert_eq!(15, d.read_integer(0x420003)?);
            assert_eq!(15, d.read_integer(0x420004)?);
            Ok(())
        })
        .unwrap();
        dec.read_struct(0x420001, |d| {
            assert_eq!(12, d.read_integer("TestTag")?);
            Ok(())
        })
        .unwrap();
        assert_eq!(16, dec.read_integer(0x420005).unwrap());
    }
}
