use crate::{Decodable, Decoder, Encodable, Encoder, Error, Result, TtlvDecoder, TtlvEncoder};

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Dummy type for testing Stream::receive — never actually decoded.
    #[derive(Debug)]
    struct Dummy;
    impl Decodable for Dummy {
        fn decode(_: &mut impl crate::Decoder) -> Result<Self> {
            unreachable!()
        }
    }

    #[test]
    fn test_receive_rejects_oversized_message() {
        // Craft a TTLV header: Tag=0x420020, Type=Structure(0x01), Length=0x02000000 (32 MiB)
        // This exceeds the 16 MiB default max.
        let header: [u8; 8] = [
            0x42, 0x00, 0x20, // tag
            0x01, // type: Structure
            0x02, 0x00, 0x00, 0x00, // length: 32 MiB
        ];
        let mut stream = Stream::new(Cursor::new(header));
        let err = stream.receive::<Dummy>().unwrap_err();
        assert!(matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData));
    }

    #[test]
    fn test_receive_accepts_within_limit() {
        // Craft a header with length just under the max — the read will fail with EOF
        // (no body data), but it should NOT be rejected by the size check.
        // Tag=0x420020, Type=Structure(0x01), Length=16 (small message)
        let header: [u8; 8] = [
            0x42, 0x00, 0x20, // tag
            0x01, // type: Structure
            0x00, 0x00, 0x00, 0x10, // length: 16 bytes
        ];
        let mut stream = Stream::new(Cursor::new(header));
        let err = stream.receive::<Dummy>().unwrap_err();
        // Should fail with EOF (no body data), NOT with InvalidData (size rejection)
        assert!(matches!(err, Error::EOF));
    }
}

/// Default maximum message size: 16 MiB.
const DEFAULT_MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

pub struct Stream<IO> {
    io: IO,
    max_message_size: usize,
}

impl<IO> Stream<IO> {
    pub fn new(stream: IO) -> Self {
        Self {
            io: stream,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        }
    }

    pub fn with_max_message_size(mut self, max: usize) -> Self {
        self.max_message_size = max;
        self
    }
}

impl<IO> Stream<IO> {
    pub fn into_inner(self) -> IO {
        self.io
    }
}

impl<IO: std::io::Write + std::io::Read> Stream<IO> {
    pub fn roundtrip<D: Decodable>(&mut self, msg: &impl Encodable) -> Result<D> {
        self.send(msg)?;
        self.receive()
    }
}

impl<IO: std::io::Write> Stream<IO> {
    pub fn send(&mut self, msg: &impl Encodable) -> Result<()> {
        let mut encoder = TtlvEncoder::new();
        encoder.encode(msg);
        self.io.write_all(encoder.bytes())?;
        self.io.flush()?;
        Ok(())
    }
}

impl<IO: std::io::Read> Stream<IO> {
    pub fn receive<D: Decodable>(&mut self) -> Result<D> {
        let mut read = 0;
        let mut buf = vec![0; 512];
        let mut need = 8;
        loop {
            buf.resize(need, 0);
            let n = self.io.read(&mut buf[read..need])?;
            if n == 0 {
                if read == 0 {
                    return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
                }
                return Err(Error::EOF);
            }
            read += n;
            if read >= need {
                let mut decoder = TtlvDecoder::new(&buf[..need]);
                need = 8 + decoder.padded_len()?;
                if need > self.max_message_size {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "message size {need} exceeds maximum allowed size {}",
                            self.max_message_size
                        ),
                    )));
                }
                if read >= need {
                    return decoder.decode();
                }
            }
        }
    }
}
