use std::{borrow::BorrowMut, io};

use quick_xml::ElementWriter;
use task_local_extensions::Extensions;

use crate::{Bitmask, Encodable, Encoder, Tag, Type};

pub struct XmlEncoder<T: BorrowMut<quick_xml::Writer<Vec<u8>>>, E: BorrowMut<Extensions>>(T, E);

impl Default for XmlEncoder<quick_xml::Writer<Vec<u8>>, Extensions> {
    fn default() -> Self {
        Self::new()
    }
}

impl XmlEncoder<quick_xml::Writer<Vec<u8>>, Extensions> {
    pub fn encode_to_string(v: &impl Encodable) -> String {
        let mut enc = Self::new();
        enc.encode(v);
        enc.into_string()
    }

    pub fn new() -> Self {
        Self(
            quick_xml::Writer::new_with_indent(Vec::new(), b' ', 4),
            Extensions::new(),
        )
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0.into_inner()
    }

    pub fn into_string(self) -> String {
        // Unwrapping here as the buffer is internal and must
        // always hold valid UTF8 encoded data.
        String::from_utf8(self.into_inner()).unwrap()
    }
}

impl<T: BorrowMut<quick_xml::Writer<Vec<u8>>>, E: BorrowMut<Extensions>> XmlEncoder<T, E> {
    pub fn bytes(&self) -> &[u8] {
        self.0.borrow().get_ref()
    }

    pub fn as_str(&self) -> &str {
        // Unwrapping here as the buffer is internal and must
        // always hold valid UTF8 encoded data.
        std::str::from_utf8(self.bytes()).unwrap()
    }

    fn create_element(
        &mut self,
        tag: impl Tag,
        typ: Type,
        f: impl FnOnce(ElementWriter<Vec<u8>>, &mut Extensions),
    ) {
        let name = tag.name().unwrap_or("TTLV");
        // TODO: Ensure tag name is not empty and contains only valid characteres
        let mut elt = self.0.borrow_mut().create_element(name);
        if typ != Type::Structure {
            elt = elt.with_attribute(("type", &typ.to_string()[..]));
        }
        if name == "TTLV" {
            //FIXME: Do not panic
            elt = elt.with_attribute(("tag", &format!("{:#08X}", tag.numeric().unwrap())[..]));
        }
        f(elt, self.1.borrow_mut());
    }

    fn write_raw_value(&mut self, tag: impl Tag, typ: Type, value: &str) {
        self.create_element(tag, typ, |elt, _| {
            elt.with_attribute(("value", value)).write_empty().unwrap();
        })
    }
}

impl<T: BorrowMut<quick_xml::Writer<Vec<u8>>>, E: BorrowMut<Extensions>> Encoder
    for XmlEncoder<T, E>
{
    type StructEncoder<'b> = XmlEncoder<&'b mut quick_xml::Writer<Vec<u8>>, &'b mut Extensions>;

    fn extensions(&mut self) -> &mut Extensions {
        self.1.borrow_mut()
    }

    fn write_struct(&mut self, tag: impl Tag, f: impl FnOnce(&mut Self::StructEncoder<'_>)) {
        self.create_element(tag, Type::Structure, |elt, ext| {
            elt.write_inner_content(|w| {
                let mut e = XmlEncoder(w, ext);
                f(&mut e);
                Ok::<(), io::Error>(())
            })
            .unwrap();
        });
    }

    fn write_integer(&mut self, tag: impl Tag, value: i32) {
        self.write_raw_value(tag, Type::Integer, &value.to_string());
    }
    fn write_long(&mut self, tag: impl Tag, value: i64) {
        self.write_raw_value(tag, Type::LongInteger, &value.to_string());
    }
    fn write_bigint(&mut self, tag: impl Tag, num: impl AsRef<[u8]>) {
        //TODO: Add padding ?
        let hex_data = data_encoding::HEXUPPER.encode(num.as_ref());
        self.write_raw_value(tag, Type::BigInteger, &hex_data);
    }
    fn write_enum(&mut self, tag: impl Tag, value: impl Tag) {
        if let Some(s) = value.name() {
            self.write_raw_value(tag, Type::Enumeration, s);
        } else {
            self.write_raw_value(
                tag,
                Type::Enumeration,
                &format!("{:#010X}", value.numeric().unwrap()), // FIXME: Do not panic
            );
        }
    }
    fn write_bool(&mut self, tag: impl Tag, value: bool) {
        self.write_raw_value(tag, Type::Boolean, &value.to_string());
    }
    fn write_string(&mut self, tag: impl Tag, s: impl AsRef<str>) {
        self.write_raw_value(tag, Type::TextString, s.as_ref());
    }
    fn write_bytes(&mut self, tag: impl Tag, s: impl AsRef<[u8]>) {
        let hex = data_encoding::HEXUPPER.encode(s.as_ref());
        self.write_raw_value(tag, Type::ByteString, &hex)
    }
    fn write_datetime(&mut self, tag: impl Tag, date: i64) {
        let dt = chrono::DateTime::from_timestamp(date, 0).unwrap();
        self.write_raw_value(
            tag,
            Type::DateTime,
            &dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        );
    }
    fn write_interval(&mut self, tag: impl Tag, seconds: u32) {
        self.write_raw_value(tag, Type::Interval, &seconds.to_string());
    }

    fn write_bitmask(&mut self, tag: impl Tag, value: impl Bitmask) {
        self.write_raw_value(tag, Type::Integer, &value.format(" "));
    }
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;

    use crate::TagEncodable;

    use super::*;

    crate::bitmask! {
        #[derive(Clone, Copy)]
        struct MyBitmask: u32 {
            const Foo = 1;
            const Bar = 2;
        }
    }

    #[test]
    fn test_xml_struct() {
        let mut enc = XmlEncoder::new();
        enc.write_struct(0x420001, |e| {
            e.write_integer((0x420000, "TestTag"), 12);
            e.write_enum(0x420003, 12);
            e.write_bool("TheBool", true);
            e.write_string((0x420004, "SayHi"), "Hello World !");
            e.write_struct("Test1", |e| {
                e.write_long("LongValue", i64::MAX);
                e.write_string("Hello", "World");
                e.write_bytes("TheBytes", b"\xff\x42");
                e.write_interval("Duration", 12);
                DateTime::parse_from_rfc3339("1996-12-19T16:39:57+00:00")
                    .unwrap()
                    .encode("TheDate", e);
            });
            e.write_struct((0x420012, "Test2"), |_| {});
            e.write_bitmask(0x420042, 1 | 2);
            e.write_bitmask(0x420043, MyBitmask::all() | MyBitmask::from_bits_retain(4));
        });

        // println!("{}", enc.as_str());

        let expect = r#"<TTLV tag="0x420001">
    <TestTag type="Integer" value="12"/>
    <TTLV type="Enumeration" tag="0x420003" value="0x0000000C"/>
    <TheBool type="Boolean" value="true"/>
    <SayHi type="TextString" value="Hello World !"/>
    <Test1>
        <LongValue type="LongInteger" value="9223372036854775807"/>
        <Hello type="TextString" value="World"/>
        <TheBytes type="ByteString" value="FF42"/>
        <Duration type="Interval" value="12"/>
        <TheDate type="DateTime" value="1996-12-19T16:39:57Z"/>
    </Test1>
    <Test2>
    </Test2>
    <TTLV type="Integer" tag="0x420042" value="0x00000001 0x00000002"/>
    <TTLV type="Integer" tag="0x420043" value="Foo Bar 0x00000004"/>
</TTLV>"#;
        let res = enc.into_string();
        assert_eq!(expect, res);
    }
}
