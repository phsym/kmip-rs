use futures_util::{
    AsyncReadExt, AsyncWriteExt,
    io::{AsyncRead, AsyncWrite},
};

use crate::{
    Decodable, Decoder, Encodable, Encoder, Error, Result, Stream, TtlvDecoder, TtlvEncoder,
};

impl<IO> Stream<IO>
where
    IO: AsyncWrite + AsyncRead + Unpin,
{
    /// Sends `msg` and waits for one full response.
    pub async fn roundtrip_async<D: Decodable>(&mut self, msg: &impl Encodable) -> Result<D> {
        self.send_async(msg).await?;
        self.receive_async().await
    }
}

impl<IO> Stream<IO>
where
    IO: AsyncWrite + Unpin,
{
    /// Encodes `msg` and writes it to the underlying stream, then flushes.
    pub async fn send_async(&mut self, msg: &impl Encodable) -> Result<()> {
        let mut encoder = TtlvEncoder::new();
        encoder.encode(msg)?;
        self.io.write_all(encoder.bytes()).await?;
        self.io.flush().await?;
        Ok(())
    }
}

impl<IO> Stream<IO>
where
    IO: AsyncRead + Unpin,
{
    /// Reads bytes until a full TTLV message can be decoded into `D`, then
    /// returns it. Returns [`Error::EOF`] if the peer closed after some bytes
    /// of a message were read but before the message was complete (truncation),
    /// and [`Error::Io`] with [`std::io::ErrorKind::UnexpectedEof`] if the peer
    /// closed before any bytes were read on this call. Other [`Error`]s
    /// indicate framing or decoding failure.
    pub async fn receive_async<D: Decodable>(&mut self) -> Result<D> {
        let mut read = 0;
        let mut buf = Vec::with_capacity(512);
        let mut need = 8;
        loop {
            buf.resize(need, 0);
            let n = self.io.read(&mut buf[read..need]).await?;
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
    use std::pin::Pin;

    use crate::{Decodable, Decoder, Encodable, Encoder};
    use crate::{Error, Result, Stream};
    use futures_util::io::Cursor;
    use futures_util::{AsyncRead, AsyncWrite};

    // Decode is never invoked. Stream::receive returns before getting that far in these tests.
    #[derive(Debug)]
    struct Dummy;
    impl Decodable for Dummy {
        fn decode(_: &mut impl crate::Decoder) -> Result<Self> {
            unreachable!()
        }
    }

    // A real, decodable TTLV message. Used where Dummy can't be (send/roundtrip paths).
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

    #[tokio::test]
    async fn test_receive_rejects_oversized_message() {
        // Craft a TTLV header: Tag=0x420020, Type=Structure(0x01), Length=0x02000000 (32 MiB)
        // This exceeds the 16 MiB default max.
        let header: [u8; 8] = [
            0x42, 0x00, 0x20, // tag
            0x01, // type: Structure
            0x02, 0x00, 0x00, 0x00, // length: 32 MiB
        ];
        let mut stream = Stream::new(Cursor::new(header));
        let err = stream.receive_async::<Dummy>().await.unwrap_err();
        assert!(matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData));
    }

    #[tokio::test]
    async fn test_receive_accepts_within_limit() {
        // Craft a header with length just under the max — the read will fail with EOF
        // (no body data), but it should NOT be rejected by the size check.
        // Tag=0x420020, Type=Structure(0x01), Length=16 (small message)
        let header: [u8; 8] = [
            0x42, 0x00, 0x20, // tag
            0x01, // type: Structure
            0x00, 0x00, 0x00, 0x10, // length: 16 bytes
        ];
        let mut stream = Stream::new(Cursor::new(header));
        let err = stream.receive_async::<Dummy>().await.unwrap_err();
        // Should fail with EOF (no body data), NOT with InvalidData (size rejection)
        assert!(matches!(err, Error::EOF));
    }

    #[tokio::test]
    async fn test_receive_eof_before_any_bytes() {
        let mut stream = Stream::new(Cursor::new([]));
        let err = stream.receive_async::<Dummy>().await.unwrap_err();
        assert!(matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof));
    }

    #[tokio::test]
    async fn test_stream_with_max_message_size() {
        // Verify custom limit is honoured: 100-byte limit, 32 MiB declared length -> rejected
        let header: [u8; 8] = [0x42, 0x00, 0x20, 0x01, 0x02, 0x00, 0x00, 0x00];
        let mut stream = Stream::new(Cursor::new(header)).with_max_message_size(100);
        let err = stream.receive_async::<Dummy>().await.unwrap_err();
        assert!(matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData));
    }

    #[tokio::test]
    async fn test_send_writes_encoded_message() {
        let mut buf = Vec::new();
        let mut stream = Stream::new(&mut buf);
        stream.send_async(&Msg(42)).await.unwrap();

        let mut dec = crate::TtlvDecoder::new(&buf);
        let decoded: Msg = Decodable::decode(&mut dec).unwrap();
        assert_eq!(decoded, Msg(42));
    }

    #[tokio::test]
    async fn test_roundtrip() {
        let mut enc = crate::TtlvEncoder::new();
        Msg(99).encode(&mut enc).unwrap();
        let bytes = enc.into_inner();

        // Pre-load the response in a cursor and route the stream through it.
        let duplex = DuplexCursor {
            read: Cursor::new(bytes),
            write: Vec::new(),
        };
        let mut stream = Stream::new(duplex);

        // The send-side payload is irrelevant. Only the read-side matters here.
        let decoded: Msg = stream.roundtrip_async(&Msg(0)).await.unwrap();
        assert_eq!(decoded, Msg(99));
    }

    struct DuplexCursor {
        read: Cursor<Vec<u8>>,
        write: Vec<u8>,
    }

    impl AsyncRead for DuplexCursor {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DuplexCursor {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().write).poll_write(cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().write).poll_flush(cx)
        }

        fn poll_close(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().write).poll_close(cx)
        }
    }
}
