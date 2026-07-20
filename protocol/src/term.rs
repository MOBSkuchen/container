//! Framing for the interactive shell session's side channel.
//!
//! A shell session runs against a real PTY, so the bytes in it are the
//! terminal's own stream — escape sequences and all. That leaves nowhere to
//! put a window-resize message, which the PTY needs to redraw full-screen
//! programs correctly. So the **client → server** direction is framed:
//!
//! ```text
//! [u8 kind][u32 be len][len bytes]
//!   kind 0  Data    keystrokes, verbatim
//!   kind 1  Resize  [u16 be cols][u16 be rows]
//! ```
//!
//! The **server → client** direction stays unframed: it is only ever terminal
//! output, and framing it would buy nothing but overhead.
//!
//! Attach sessions do not use this — they remain a plain line-oriented byte
//! bridge to the supervised process's pipes.

pub const KIND_DATA: u8 = 0;
pub const KIND_RESIZE: u8 = 1;

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

#[derive(Debug, PartialEq)]
pub enum Frame<'a> {
    Data(&'a [u8]),
    Resize { cols: u16, rows: u16 },
    /// A known-length frame of an unrecognised kind: skip it, do not
    /// desynchronise. Lets the format grow without breaking old servers.
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
        _ => Frame::Unknown,
    };
    Decoded::Frame(frame, end)
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
