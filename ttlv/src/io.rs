use crate::{Decodable, Decoder, Encodable, Encoder, Error, Result, TtlvDecoder, TtlvEncoder};

/// Default maximum message size: 16 MiB.
const DEFAULT_MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Length-prefixed framing adapter for TTLV over a synchronous I/O channel.
///
/// Wraps any `Read` and/or `Write` and exchanges full TTLV messages: a
/// message's length is read from its outer `Structure` header so each call
/// returns one complete value. Incoming messages whose declared length
/// exceeds the configured maximum (set via
/// [`with_max_message_size`](Self::with_max_message_size); 16 MiB by default)
/// are rejected before any body bytes are read.
pub struct Stream<IO> {
    io: IO,
    max_message_size: usize,
}

impl<IO> Stream<IO> {
    /// Wraps `stream` with default framing limits.
    pub fn new(stream: IO) -> Self {
        Self {
            io: stream,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        }
    }

    /// Sets the maximum size, in bytes, of a single incoming TTLV message.
    /// Messages exceeding `max` are rejected with an [`Error::Io`] whose
    /// kind is [`std::io::ErrorKind::InvalidData`].
    pub fn with_max_message_size(mut self, max: usize) -> Self {
        self.max_message_size = max;
        self
    }
}

impl<IO> Stream<IO> {
    /// Drops the framing layer and returns the wrapped I/O object.
    pub fn into_inner(self) -> IO {
        self.io
    }
}

impl<IO: std::io::Write + std::io::Read> Stream<IO> {
    /// Sends `msg` and waits for one full response.
    pub fn roundtrip<D: Decodable>(&mut self, msg: &impl Encodable) -> Result<D> {
        self.send(msg)?;
        self.receive()
    }
}

impl<IO: std::io::Write> Stream<IO> {
    /// Encodes `msg` and writes it to the underlying stream, then flushes.
    pub fn send(&mut self, msg: &impl Encodable) -> Result<()> {
        let mut encoder = TtlvEncoder::new();
        encoder.encode(msg)?;
        self.io.write_all(encoder.bytes())?;
        self.io.flush()?;
        Ok(())
    }
}

impl<IO: std::io::Read> Stream<IO> {
    /// Reads bytes until a full TTLV message can be decoded into `D`, then
    /// returns it. Returns [`Error::EOF`] if the peer closed after some bytes
    /// of a message were read but before the message was complete (truncation),
    /// and [`Error::Io`] with [`std::io::ErrorKind::UnexpectedEof`] if the peer
    /// closed before any bytes were read on this call. Other [`Error`]s
    /// indicate framing or decoding failure.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Encodable, Encoder};
    use std::io::Cursor;

    // Decode is never invoked — Stream::receive returns before getting that far in these tests.
    #[derive(Debug)]
    struct Dummy;
    impl Decodable for Dummy {
        fn decode(_: &mut impl crate::Decoder) -> Result<Self> {
            unreachable!()
        }
    }

    // A real, decodable TTLV message — used where Dummy can't be (send/roundtrip paths).
    #[derive(Debug, PartialEq)]
    struct Msg(i32);

    impl Encodable for Msg {
        fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
            encoder.write_struct(0x420020u32, |e| e.write_integer(0x420001u32, self.0))
        }
    }

    impl Decodable for Msg {
        fn decode(decoder: &mut impl crate::Decoder) -> Result<Self> {
            decoder.read_struct(0x420020u32, |d| d.read_integer(0x420001u32).map(Msg))
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

    #[test]
    fn test_receive_eof_before_any_bytes() {
        let mut stream = Stream::new(Cursor::new([]));
        let err = stream.receive::<Dummy>().unwrap_err();
        assert!(matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn test_stream_into_inner() {
        let cursor = Cursor::new(vec![0u8; 0]);
        let stream = Stream::new(cursor);
        let inner = stream.into_inner();
        assert_eq!(inner.position(), 0);
    }

    #[test]
    fn test_stream_with_max_message_size() {
        // Verify custom limit is honoured: 100-byte limit, 32 MiB declared length → rejected
        let header: [u8; 8] = [0x42, 0x00, 0x20, 0x01, 0x02, 0x00, 0x00, 0x00];
        let mut stream = Stream::new(Cursor::new(header)).with_max_message_size(100);
        let err = stream.receive::<Dummy>().unwrap_err();
        assert!(matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData));
    }

    #[test]
    fn test_send_writes_encoded_message() {
        let mut buf = Vec::new();
        let mut stream = Stream::new(&mut buf);
        stream.send(&Msg(42)).unwrap();

        let mut dec = crate::TtlvDecoder::new(&buf);
        let decoded: Msg = Decodable::decode(&mut dec).unwrap();
        assert_eq!(decoded, Msg(42));
    }

    #[test]
    fn test_roundtrip() {
        let mut enc = crate::TtlvEncoder::new();
        Msg(99).encode(&mut enc).unwrap();
        let bytes = enc.into_inner();

        // Pre-load the response in a cursor and route the stream through it.
        let duplex = DuplexCursor {
            read: Cursor::new(bytes),
            write: Vec::new(),
        };
        let mut stream = Stream::new(duplex);

        // The send-side payload is irrelevant — only the read-side matters here.
        let decoded: Msg = stream.roundtrip(&Msg(0)).unwrap();
        assert_eq!(decoded, Msg(99));
    }

    struct DuplexCursor {
        read: Cursor<Vec<u8>>,
        write: Vec<u8>,
    }

    impl std::io::Read for DuplexCursor {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(buf)
        }
    }

    impl std::io::Write for DuplexCursor {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.write.flush()
        }
    }
}
