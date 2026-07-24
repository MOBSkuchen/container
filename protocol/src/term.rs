//! Framing for the interactive session side channels.
//!
//! A session now rides bierpc's persistent call on the same TLS connection
//! that carries unary RPC (see `crate::session`), which is reused for the
//! call's reply afterwards. That connection can never be closed to mean "the
//! session is over", so **both** directions are framed and end with an
//! explicit `Close`:
//!
//! ```text
//! [u8 kind][u32 be len][len bytes]
//!   kind 0  Data    bytes, verbatim (keystrokes one way, terminal output the other)
//!   kind 1  Resize  [u16 be cols][u16 be rows]   (client → server only)
//!   kind 2  Close   empty; "no more session bytes, the reply follows"
//! ```
//!
//! An unknown kind is skipped, not fatal, so the format can still grow.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const KIND_DATA: u8 = 0;
pub const KIND_RESIZE: u8 = 1;
pub const KIND_CLOSE: u8 = 2;

pub const HEADER_LEN: usize = 5;

/// Guards against a corrupt or hostile length prefix turning into a huge
/// allocation. Real keystroke batches are a few bytes; a paste is a few KiB.
pub const MAX_FRAME: usize = 64 * 1024;

pub fn data_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(KIND_DATA);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn resize_frame(cols: u16, rows: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + 4);
    out.push(KIND_RESIZE);
    out.extend_from_slice(&4u32.to_be_bytes());
    out.extend_from_slice(&cols.to_be_bytes());
    out.extend_from_slice(&rows.to_be_bytes());
    out
}

pub fn close_frame() -> [u8; HEADER_LEN] {
    [KIND_CLOSE, 0, 0, 0, 0]
}

#[derive(Debug, PartialEq)]
pub enum Frame<'a> {
    Data(&'a [u8]),
    Resize { cols: u16, rows: u16 },
    /// End of session: no more frames follow, the persistent call's reply is next.
    Close,
    /// A known-length frame of an unrecognised kind: skip it, do not
    /// desynchronise. Lets the format grow without breaking old servers.
    Unknown,
}

impl Frame<'_> {
    pub fn to_owned(&self) -> OwnedFrame {
        match self {
            Frame::Data(bytes) => OwnedFrame::Data(bytes.to_vec()),
            Frame::Resize { cols, rows } => OwnedFrame::Resize { cols: *cols, rows: *rows },
            Frame::Close => OwnedFrame::Close,
            Frame::Unknown => OwnedFrame::Unknown,
        }
    }
}

/// The self-owning form yielded by `FrameReader`, so a decoded frame can
/// outlive the read buffer it came from.
#[derive(Debug, PartialEq)]
pub enum OwnedFrame {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Close,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub enum Decoded<'a> {
    /// A whole frame, plus how many bytes of the buffer it consumed.
    Frame(Frame<'a>, usize),
    /// Not enough bytes yet; keep reading.
    Incomplete,
    /// Unrecoverable: the length prefix is beyond what a frame may be.
    Invalid,
}

pub fn decode(buf: &[u8]) -> Decoded<'_> {
    if buf.len() < HEADER_LEN {
        return Decoded::Incomplete;
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > MAX_FRAME {
        return Decoded::Invalid;
    }
    let end = HEADER_LEN + len;
    if buf.len() < end {
        return Decoded::Incomplete;
    }

    let payload = &buf[HEADER_LEN..end];
    let frame = match buf[0] {
        KIND_DATA => Frame::Data(payload),
        KIND_RESIZE if payload.len() == 4 => Frame::Resize {
            cols: u16::from_be_bytes([payload[0], payload[1]]),
            rows: u16::from_be_bytes([payload[2], payload[3]]),
        },
        KIND_CLOSE => Frame::Close,
        _ => Frame::Unknown,
    };
    Decoded::Frame(frame, end)
}

/// Bytes still needed to complete the frame `pending` has started — the header
/// first, then its declared payload. At least 1 whenever `decode` is
/// `Incomplete`. Used to bound each read to the frame boundary.
fn frame_shortfall(pending: &[u8]) -> usize {
    if pending.len() < HEADER_LEN {
        return HEADER_LEN - pending.len();
    }
    let len = u32::from_be_bytes([pending[1], pending[2], pending[3], pending[4]]) as usize;
    (HEADER_LEN + len).saturating_sub(pending.len()).max(1)
}

/// Reads whole frames off an async stream, buffering partial ones. Used as a
/// `select!` branch, so it yields one frame per call rather than looping.
pub struct FrameReader {
    pending: Vec<u8>,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReader {
    pub fn new() -> Self {
        Self { pending: Vec::new() }
    }

    /// The next whole frame, `None` at a clean end of stream. A length past
    /// `MAX_FRAME`, or an EOF mid-frame, is an error.
    ///
    /// Never reads past the current frame's last byte: after a `Close`, the
    /// buffer is empty, so whatever follows on the stream — e.g. the persistent
    /// call's reply — is left untouched for the next reader.
    pub async fn next<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> io::Result<Option<OwnedFrame>> {
        let mut buf = [0u8; 8192];
        loop {
            match decode(&self.pending) {
                Decoded::Frame(frame, used) => {
                    let owned = frame.to_owned();
                    self.pending.drain(..used);
                    return Ok(Some(owned));
                }
                Decoded::Invalid => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "session frame length out of range"));
                }
                Decoded::Incomplete => {
                    // Only what this frame still needs — reading further would
                    // swallow the bytes that come after it.
                    let want = frame_shortfall(&self.pending).min(buf.len());
                    let n = r.read(&mut buf[..want]).await?;
                    if n == 0 {
                        return if self.pending.is_empty() {
                            Ok(None)
                        } else {
                            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stream ended mid-frame"))
                        };
                    }
                    self.pending.extend_from_slice(&buf[..n]);
                }
            }
        }
    }

    /// End our side of a session: send `Close`, then (unless the peer's `Close`
    /// was already seen) discard frames until it arrives, leaving the stream
    /// positioned at the persistent call's reply.
    pub async fn finish<R, W>(&mut self, r: &mut R, w: &mut W, peer_closed: bool) -> io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        w.write_all(&close_frame()).await?;
        w.flush().await?;
        if !peer_closed {
            while !matches!(self.next(r).await?, None | Some(OwnedFrame::Close)) {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_data() {
        let frame = data_frame(b"ls -la\r");
        assert_eq!(decode(&frame), Decoded::Frame(Frame::Data(b"ls -la\r"), frame.len()));
    }

    #[test]
    fn round_trips_resize() {
        let frame = resize_frame(120, 40);
        assert_eq!(decode(&frame), Decoded::Frame(Frame::Resize { cols: 120, rows: 40 }, frame.len()));
    }

    #[test]
    fn reports_partial_frames_rather_than_guessing() {
        let frame = data_frame(b"hello");
        for cut in 0..frame.len() {
            assert_eq!(decode(&frame[..cut]), Decoded::Incomplete, "cut at {cut}");
        }
    }

    #[test]
    fn consumes_exactly_one_frame_from_a_batch() {
        let mut buf = data_frame(b"a");
        buf.extend_from_slice(&resize_frame(80, 24));
        let Decoded::Frame(first, used) = decode(&buf) else { panic!("expected a frame") };
        assert_eq!(first, Frame::Data(b"a"));
        assert_eq!(decode(&buf[used..]), Decoded::Frame(Frame::Resize { cols: 80, rows: 24 }, 9));
    }

    #[test]
    fn rejects_an_absurd_length_instead_of_allocating() {
        let mut buf = vec![KIND_DATA];
        buf.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(decode(&buf), Decoded::Invalid);
    }

    #[test]
    fn round_trips_close() {
        assert_eq!(decode(&close_frame()), Decoded::Frame(Frame::Close, HEADER_LEN));
    }

    #[tokio::test]
    async fn frame_reader_yields_frames_then_eof() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&data_frame(b"hi"));
        stream.extend_from_slice(&resize_frame(80, 24));
        stream.extend_from_slice(&close_frame());
        let mut cursor = std::io::Cursor::new(stream);
        let mut reader = FrameReader::new();
        assert_eq!(reader.next(&mut cursor).await.unwrap(), Some(OwnedFrame::Data(b"hi".to_vec())));
        assert_eq!(reader.next(&mut cursor).await.unwrap(), Some(OwnedFrame::Resize { cols: 80, rows: 24 }));
        assert_eq!(reader.next(&mut cursor).await.unwrap(), Some(OwnedFrame::Close));
        assert_eq!(reader.next(&mut cursor).await.unwrap(), None);
    }

    // The bytes that follow a frame (e.g. the persistent call's reply after a
    // Close) must not be swallowed, even when they arrive in the same read.
    #[tokio::test]
    async fn frame_reader_stops_at_the_boundary() {
        use tokio::io::AsyncReadExt;
        let mut stream = close_frame().to_vec();
        stream.extend_from_slice(b"REPLY-BYTES");
        let mut cursor = std::io::Cursor::new(stream);
        let mut reader = FrameReader::new();
        assert_eq!(reader.next(&mut cursor).await.unwrap(), Some(OwnedFrame::Close));
        // Everything after the Close frame is still on the stream, untouched.
        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"REPLY-BYTES");
    }

    #[test]
    fn skips_unknown_kinds_without_desynchronising() {
        let mut buf = vec![250u8];
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(b"xyz");
        buf.extend_from_slice(&data_frame(b"after"));
        let Decoded::Frame(frame, used) = decode(&buf) else { panic!("expected a frame") };
        assert_eq!(frame, Frame::Unknown);
        assert_eq!(decode(&buf[used..]), Decoded::Frame(Frame::Data(b"after"), 10));
    }
}
