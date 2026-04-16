use std::iter;

use task_local_extensions::Extensions;

use crate::{Bitmask, Encoder, Tag, Type};

#[derive(Default)]
pub struct TtlvEncoder {
    buf: Vec<u8>,
    ext: Extensions,
}

impl TtlvEncoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.ext.clear();
        //TODO: zeroize buff
        self.buf.clear();
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    fn write_byte(&mut self, byte: u8) {
        self.buf.push(byte);
    }

    fn write(&mut self, bytes: impl AsRef<[u8]>) {
        self.buf.extend_from_slice(bytes.as_ref());
    }

    fn write_tag(&mut self, tag: u32) {
        let bytes = tag.to_be_bytes();
        let bytes = [bytes[1], bytes[2], bytes[3]];
        self.write(bytes);
    }

    fn write_type(&mut self, typ: Type) {
        self.write_byte(typ as u8)
    }

    fn write_length(&mut self, len: usize) {
        self.write((len as u32).to_be_bytes());
    }

    const fn pad_for_len(l: usize) -> usize {
        (8 - l % 8) % 8
    }

    fn pad(&mut self, n: usize, value: u8) {
        self.buf.extend(iter::repeat_n(value, n))
    }

    fn raw_encode(&mut self, tag: impl Tag, typ: Type, len: usize, value: impl AsRef<[u8]>) {
        self.write_tag(tag.numeric().unwrap()); // FIXME: Do not panic
        self.write_type(typ);
        self.write_length(len);
        self.write(value.as_ref())
    }
}

impl Encoder for TtlvEncoder {
    type StructEncoder<'b> = Self;

    fn extensions(&mut self) -> &mut Extensions {
        &mut self.ext
    }

    fn write_integer(&mut self, tag: impl Tag, value: i32) {
        self.raw_encode(tag, Type::Integer, 4, value.to_be_bytes());
        self.pad(4, 0);
    }

    fn write_long(&mut self, tag: impl Tag, value: i64) {
        self.raw_encode(tag, Type::LongInteger, 8, value.to_be_bytes());
    }

    fn write_bigint(&mut self, tag: impl Tag, num: impl AsRef<[u8]>) {
        self.write_tag(tag.numeric().unwrap());
        self.write_type(Type::BigInteger);
        let num = num.as_ref();
        let pad_len = Self::pad_for_len(num.len());
        self.write_length(num.len() + pad_len);
        // Extend sign
        let pad = if (num[0] >> 7) & 0x01 == 0x01 {
            0xFF
        } else {
            0
        };
        self.pad(pad_len, pad);
        self.write(num);
    }

    fn write_struct(&mut self, tag: impl Tag, f: impl FnOnce(&mut Self::StructEncoder<'_>)) {
        self.write_tag(tag.numeric().unwrap());
        self.write_type(Type::Structure);
        let off = self.buf.len();

        self.write_length(0);
        f(self);
        let len = self.buf.len() - off - 4;
        self.buf[off..off + 4].copy_from_slice(&(len as u32).to_be_bytes()[..]);
    }

    fn write_enum(&mut self, tag: impl Tag, value: impl Tag) {
        //FIXME: Do not panic
        self.raw_encode(
            tag,
            Type::Enumeration,
            4,
            value.numeric().unwrap().to_be_bytes(),
        );
        self.pad(4, 0);
    }

    fn write_bool(&mut self, tag: impl Tag, value: bool) {
        let mut v = [0; 8];
        if value {
            v[7] = 1;
        }
        self.raw_encode(tag, Type::Boolean, 8, v);
    }

    fn write_string(&mut self, tag: impl Tag, s: impl AsRef<str>) {
        let s = s.as_ref();
        self.raw_encode(tag, Type::TextString, s.len(), s);
        self.pad(Self::pad_for_len(s.len()), 0)
    }

    fn write_bytes(&mut self, tag: impl Tag, s: impl AsRef<[u8]>) {
        let s = s.as_ref();
        self.raw_encode(tag, Type::ByteString, s.len(), s);
        self.pad(Self::pad_for_len(s.len()), 0)
    }

    fn write_datetime(&mut self, tag: impl Tag, date: i64) {
        self.raw_encode(tag, Type::DateTime, 8, date.to_be_bytes());
    }

    fn write_interval(&mut self, tag: impl Tag, seconds: u32) {
        self.raw_encode(tag, Type::Interval, 4, seconds.to_be_bytes());
        self.pad(4, 0);
    }

    fn write_bitmask(&mut self, tag: impl Tag, value: impl Bitmask) {
        self.write_integer(tag, value.value());
    }
}

#[cfg(test)]
mod tests {
    use std::time;

    use super::*;

    fn hex(s: &str) -> String {
        s.replace([' ', '|'], "").to_uppercase()
    }

    #[test]
    fn test_encode_integer() {
        let mut enc = TtlvEncoder::new();
        enc.write_integer(0x420020, 8);
        let expected = hex("42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00");
        assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));
    }

    #[test]
    fn test_encode_long() {
        let mut enc = TtlvEncoder::new();
        enc.write_long(0x420020, 123456789000000000);
        let expected = hex("42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00");
        assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));
    }

    /*
       fn TestEncodeBigInteger() {
       t.Run("positive", fn() {
           let mut enc = Encoder::new();
           b := big.NewInt(0)
           b.SetString("1234567890000000000000000000", 10)
           enc.BigInteger(0x420020, b)
           let expected = hex("42 00 20 | 04 | 00 00 00 10 | 00 00 00 00 03 FD 35 EB 6B C2 DF 46 18 08 00 00")
           assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));
       })
       // t.Run("zero", fn() {
       // 	let mut enc = Encoder::new();
       // 	b := big.NewInt(0)
       // 	enc.EncodeBigInteger(0x420020, b)
       // 	expected := "42002004000000100000000003FD35EB6BC2DF4618080000"
       // 	assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));
       // })
       // t.Run("negative", fn() {
       // 	let mut enc = Encoder::new();
       // 	b := big.NewInt(0)
       // 	b.SetString("-1234567890000000000000000000", 10)
       // 	enc.EncodeBigInteger(0x420020, b)
       // 	expected := "42002004000000100000000003FD35EB6BC2DF4618080000"
       // 	assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));
       // })
       }
    */

    #[test]
    fn test_encode_enum() {
        let mut enc = TtlvEncoder::new();
        enc.write_enum(0x420020, 255);
        let expected = hex("42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00");
        assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));
    }

    #[test]
    fn test_encode_boolean() {
        let mut enc = TtlvEncoder::new();
        enc.write_bool(0x420020, true);
        let expected = hex("42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 01");
        assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));

        let mut enc = TtlvEncoder::new();
        enc.write_bool(0x420020, false);
        let expected = hex("42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 00");
        assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));
    }

    #[test]
    fn test_encode_string() {
        let mut enc = TtlvEncoder::new();
        enc.write_string(0x420020, "Hello World");
        let expected =
            hex("42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00 00 00");
        assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));
    }

    #[test]
    fn test_encode_byte_string() {
        let mut enc = TtlvEncoder::new();
        enc.write_bytes(0x420020, [0x01, 0x02, 0x03]);
        let expected = hex("42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00");
        assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));
    }

    #[test]
    fn test_encode_interval() {
        let mut enc = TtlvEncoder::new();
        enc.write_interval(0x420020, chrono::Duration::days(10).num_seconds() as u32);
        let expected = hex("42 00 20 | 0A | 00 00 00 04 | 00 0D 2F 00 00 00 00 00");
        assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));

        let mut enc = TtlvEncoder::new();
        enc.tag_encode(0x420020, &time::Duration::from_secs(10 * 24 * 60 * 60));
        assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));

        #[cfg(feature = "chrono")]
        {
            let mut enc = TtlvEncoder::new();
            enc.tag_encode(0x420020, &chrono::Duration::days(10));
            assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));
        }
    }

    #[test]
    fn test_encode_datetime() {
        let mut enc = TtlvEncoder::new();
        let dt = chrono::NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(2008, 3, 14).unwrap(),
            chrono::NaiveTime::from_hms_opt(11, 56, 40).unwrap(),
        );
        enc.write_datetime(0x420020, dt.and_utc().timestamp());
        let expected = hex("42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8");
        assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));

        #[cfg(feature = "chrono")]
        {
            let mut enc = TtlvEncoder::new();
            enc.tag_encode(0x420020, &dt);
            assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));

            let mut enc = TtlvEncoder::new();
            enc.tag_encode(0x420020, &dt.and_utc());
            assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));
        }
    }

    #[test]
    fn test_encode_struct() {
        let mut enc = TtlvEncoder::new();
        enc.write_struct(0x420020, |e| {
            e.write_enum(0x420004, 254);
            e.write_integer(0x420005, 255);
        });
        let expected = hex(
            "42 00 20 | 01 | 00 00 00 20 | 42 00 04 | 05 | 00 00 00 04 | 00 00 00 FE 00 00 00 00 | 42 00 05 | 02 | 00 00 00 04 | 00 00 00 FF 00 00 00 00",
        );
        assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));
    }

    #[test]
    fn test_encode_bitmask() {
        let mut enc = TtlvEncoder::new();
        enc.write_bitmask(0x420020, 8);
        let expected = hex("42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00");
        assert_eq!(expected, data_encoding::HEXUPPER.encode(enc.bytes()));
    }
}
