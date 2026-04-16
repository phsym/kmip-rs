use crate::{Decodable, Decoder, Encodable, Encoder, Error, Result, TtlvDecoder, TtlvEncoder};

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
