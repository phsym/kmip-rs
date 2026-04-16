use crate::{Decodable, Decoder, Encodable, Encoder, Error, Result, TtlvDecoder, TtlvEncoder};

pub struct Stream<IO>(IO);

impl<IO> Stream<IO> {
    pub fn new(stream: IO) -> Self {
        Self(stream)
    }
}

impl<IO> Stream<IO> {
    pub fn into_inner(self) -> IO {
        self.0
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
        self.0.write_all(encoder.bytes())?;
        self.0.flush()?;
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
            let n = self.0.read(&mut buf[read..need])?;
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
                if read >= need {
                    return decoder.decode();
                }
            }
        }
    }
}
