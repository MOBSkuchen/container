//! `client shell <target>` / `client attach <target>`.
//!
//! `shell` runs against a real PTY and is a dumb conduit in both directions,
//! Ctrl+C included, ending when the shell does. `attach` bridges to the
//! supervised process, which runs on pipes with no PTY, so this end emulates
//! the shell feel locally (`editor::LineEditor`) and Ctrl+C ends the session
//! instead of being forwarded.

#[cfg(not(windows))]
use std::time::Duration;

use anyhow::Context;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use protocol::{Action, TerminalMode, term};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::console::RawConsole;
use crate::editor::{Keystroke, LineEditor};
use crate::net::{self, Endpoint};

/// Unix only: its shell pump forwards raw stdin bytes, so reading resize
/// events would mean sharing stdin with the byte pump; Windows gets resizes
/// as console events instead.
#[cfg(not(windows))]
const RESIZE_POLL: Duration = Duration::from_millis(250);

/// Split out from the bridges so it can be exercised without a TTY.
pub async fn open_session(endpoint: &Endpoint, mode: TerminalMode) -> anyhow::Result<TcpStream> {
    net::open_session(endpoint, Action::OpenTerminal { mode }).await
}

pub fn window_size() -> (u16, u16) {
    crossterm::terminal::size().unwrap_or((80, 24))
}

pub async fn shell(endpoint: &Endpoint, id: u128, label: &str) -> anyhow::Result<()> {
    let (cols, rows) = window_size();
    let stream = open_session(endpoint, TerminalMode::Shell { id, cols, rows }).await
        .with_context(|| format!("opening a shell session on {label}"))?;

    println!("── shell on {label} · type 'exit' to end the session ──");

    {
        let _console = RawConsole::enter()?;
        pump_shell(stream, cols, rows).await?;
    }

    println!("\n── session ended ──");
    Ok(())
}

/// `CONTAINER_SHELL_TEE=<path>` writes everything the server sends into a
/// file, for diagnosing "my terminal shows garbage" without guessing.
fn open_tee() -> Option<std::fs::File> {
    std::env::var_os("CONTAINER_SHELL_TEE").and_then(|path| std::fs::File::create(path).ok())
}

#[cfg(windows)]
enum Intercept {
    /// `\e[6n`: the remote pty is asking its terminal where the cursor is,
    /// and blocks its output pipeline until answered.
    CursorQuery,
    /// `\e[?9001h/l`: ConPTY asking its terminal to switch to
    /// win32-input-mode. Letting it reach the local console would flip our
    /// own input into that encoding, so it's swallowed with no reply.
    Drop,
}

/// Removes from the printable stream the few sequences the remote pty
/// addresses at the terminal rather than the screen — they must not reach
/// the local console, which would inject its reply into our own input queue
/// and get mangled by the event decoder (evt_probe showed a `\e[..R` reply
/// arriving back as a phantom F3 key). The pump answers on the socket
/// itself instead, like a terminal emulator would.
#[cfg(windows)]
#[derive(Default)]
struct OutputFilter {
    /// An unfinished candidate match at the end of the previous chunk.
    carry: Vec<u8>,
}

#[cfg(windows)]
impl OutputFilter {
    const PATTERNS: [(&[u8], Intercept); 3] = [
        (b"\x1b[6n", Intercept::CursorQuery),
        (b"\x1b[?9001h", Intercept::Drop),
        (b"\x1b[?9001l", Intercept::Drop),
    ];

    /// Splits a chunk into what should be printed and how many cursor
    /// queries were removed. A trailing partial match is held back until
    /// the next chunk decides what it was.
    fn feed(&mut self, chunk: &[u8]) -> (Vec<u8>, u32) {
        let mut data = std::mem::take(&mut self.carry);
        data.extend_from_slice(chunk);

        let mut printable = Vec::with_capacity(data.len());
        let mut queries = 0u32;
        let mut i = 0;
        'scan: while i < data.len() {
            if data[i] == 0x1b {
                let rest = &data[i..];
                for (pattern, action) in &Self::PATTERNS {
                    if rest.starts_with(pattern) {
                        if matches!(action, Intercept::CursorQuery) {
                            queries += 1;
                        }
                        i += pattern.len();
                        continue 'scan;
                    }
                    if pattern.starts_with(rest) {
                        self.carry = rest.to_vec();
                        break 'scan;
                    }
                }
            }
            printable.push(data[i]);
            i += 1;
        }
        (printable, queries)
    }
}

/// A console byte read never yields arrows, function keys or Ctrl+C, no
/// matter which console modes are set (evt_probe demonstrates this), so
/// this reads decoded events instead — the same API the TUI uses — and
/// re-encodes each key into the escape sequence a terminal would have sent,
/// which ConPTY on the far side parses back into key events for the shell.
#[cfg(windows)]
async fn pump_shell(stream: TcpStream, cols: u16, rows: u16) -> anyhow::Result<()> {
    let _ = (cols, rows); // the pty was already created at this size

    let (mut sock_r, mut sock_w) = stream.into_split();
    let mut stdout = tokio::io::stdout();
    let mut events = EventStream::new();
    let mut tee = open_tee();
    let mut debug = std::env::var_os("CONTAINER_SHELL_DEBUG")
        .and_then(|path| std::fs::File::create(path).ok());
    let mut dbg = move |line: String| {
        if let Some(file) = debug.as_mut() {
            use std::io::Write;
            let _ = writeln!(file, "{line}");
            let _ = file.flush();
        }
    };
    let mut from_remote = [0u8; 8192];
    let mut filter = OutputFilter::default();

    // A Release normally echoes a tracked Press and must be dropped or every
    // keystroke doubles — except a Release with no matching Press (a ^C
    // synthesized from pasted input can arrive that way), which must not be.
    let mut pressed: std::collections::HashSet<(KeyCode, KeyModifiers)> =
        std::collections::HashSet::new();

    dbg("pump: start".into());
    loop {
        tokio::select! {
            read = sock_r.read(&mut from_remote) => match read {
                Ok(0) | Err(_) => {
                    dbg(format!("pump: socket closed ({read:?})"));
                    return Ok(());
                }
                Ok(n) => {
                    dbg(format!("pump: {n} bytes from remote"));
                    if let Some(file) = tee.as_mut() {
                        use std::io::Write;
                        let _ = file.write_all(&from_remote[..n]);
                    }
                    let (printable, queries) = filter.feed(&from_remote[..n]);
                    stdout.write_all(&printable).await?;
                    stdout.flush().await?;
                    // Answered only once everything before the query is on
                    // screen, so the reported position is the one it meant.
                    for _ in 0..queries {
                        let (row, col) = crate::console::cursor_position().unwrap_or((1, 1));
                        dbg(format!("pump: answering cursor query with {row};{col}"));
                        let reply = format!("\x1b[{row};{col}R");
                        if sock_w.write_all(&term::data_frame(reply.as_bytes())).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            },
            event = events.next() => match event {
                None => return Ok(()),
                Some(Err(e)) => return Err(e.into()),
                Some(Ok(Event::Key(key))) => {
                    dbg(format!("pump: key {key:?}"));
                    let forward = match key.kind {
                        KeyEventKind::Press => {
                            pressed.insert((key.code, key.modifiers));
                            true
                        }
                        KeyEventKind::Repeat => true,
                        KeyEventKind::Release => !pressed.remove(&(key.code, key.modifiers)),
                    };
                    if forward
                        && let Some(bytes) = encode_key(&key)
                        && sock_w.write_all(&term::data_frame(&bytes)).await.is_err() {
                        return Ok(());
                    }
                }
                Some(Ok(Event::Resize(new_cols, new_rows))) => {
                    dbg(format!("pump: resize {new_cols}x{new_rows}"));
                    if sock_w.write_all(&term::resize_frame(new_cols, new_rows)).await.is_err() {
                        return Ok(());
                    }
                }
                // Only reported if the remote asked for it (its `\e[?1004h`
                // passed through to the local console), so it always has a
                // waiting recipient.
                Some(Ok(Event::FocusGained)) => {
                    if sock_w.write_all(&term::data_frame(b"\x1b[I")).await.is_err() {
                        return Ok(());
                    }
                }
                Some(Ok(Event::FocusLost)) => {
                    if sock_w.write_all(&term::data_frame(b"\x1b[O")).await.is_err() {
                        return Ok(());
                    }
                }
                Some(Ok(other)) => dbg(format!("pump: ignored {other:?}")),
            },
        }
    }
}

/// On unix a raw-mode tty hands over the byte stream exactly as a terminal
/// produced it, so bytes are forwarded verbatim instead of decoding and
/// re-encoding events.
#[cfg(not(windows))]
async fn pump_shell(stream: TcpStream, mut cols: u16, mut rows: u16) -> anyhow::Result<()> {
    let (mut sock_r, mut sock_w) = stream.into_split();
    let mut stdout = tokio::io::stdout();
    let mut resize_tick = tokio::time::interval(RESIZE_POLL);
    resize_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut tee = open_tee();

    // A blocking tty read can't be cancelled, so it runs on a plain OS
    // thread rather than `tokio::io::stdin()` — a tokio blocking task stuck
    // there would keep the process alive after the session ends, until one
    // more key is pressed. A detached thread just dies with us.
    let (key_tx, mut key_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if key_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
            }
        }
    });

    let mut from_remote = [0u8; 8192];

    loop {
        tokio::select! {
            read = sock_r.read(&mut from_remote) => match read {
                Ok(0) | Err(_) => return Ok(()),
                Ok(n) => {
                    if let Some(file) = tee.as_mut() {
                        use std::io::Write;
                        let _ = file.write_all(&from_remote[..n]);
                    }
                    stdout.write_all(&from_remote[..n]).await?;
                    stdout.flush().await?;
                }
            },
            key = key_rx.recv() => match key {
                None => return Ok(()),
                Some(bytes) => {
                    let frame = term::data_frame(&bytes);
                    if sock_w.write_all(&frame).await.is_err() {
                        return Ok(());
                    }
                }
            },
            _ = resize_tick.tick() => {
                let (new_cols, new_rows) = window_size();
                if (new_cols, new_rows) != (cols, rows) {
                    cols = new_cols;
                    rows = new_rows;
                    if sock_w.write_all(&term::resize_frame(cols, rows)).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// The xterm byte sequence for one decoded key press, or `None` for keys
/// with no representation (bare modifiers).
#[cfg(windows)]
fn encode_key(key: &KeyEvent) -> Option<Vec<u8>> {
    use KeyCode::*;

    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let m = 1 + shift as u8 + 2 * (alt as u8) + 4 * (ctrl as u8);

    let arrow = |c: u8| if m == 1 {
        vec![0x1b, b'[', c]
    } else {
        format!("\x1b[1;{m}{}", c as char).into_bytes()
    };
    let tilde = |n: u8| if m == 1 {
        format!("\x1b[{n}~").into_bytes()
    } else {
        format!("\x1b[{n};{m}~").into_bytes()
    };
    // Alt is an ESC prefix (Alt+X sends `\ex`).
    let plain = |bytes: Vec<u8>| if alt {
        let mut v = Vec::with_capacity(bytes.len() + 1);
        v.push(0x1b);
        v.extend(bytes);
        v
    } else {
        bytes
    };

    Some(match key.code {
        Char(c) => {
            let base = match ctrl.then(|| ctrl_byte(c)).flatten() {
                Some(b) => vec![b],
                None => c.to_string().into_bytes(),
            };
            plain(base)
        }
        Enter => plain(vec![b'\r']),
        Tab if shift => vec![0x1b, b'[', b'Z'],
        Tab => plain(vec![b'\t']),
        BackTab => vec![0x1b, b'[', b'Z'],
        Backspace => plain(vec![0x7f]),
        Esc => vec![0x1b],
        Up => arrow(b'A'),
        Down => arrow(b'B'),
        Right => arrow(b'C'),
        Left => arrow(b'D'),
        Home => arrow(b'H'),
        End => arrow(b'F'),
        Insert => tilde(2),
        Delete => tilde(3),
        PageUp => tilde(5),
        PageDown => tilde(6),
        // F1-F4 are SS3 when unmodified, CSI like the arrows otherwise.
        F(n @ 1..=4) if m == 1 => vec![0x1b, b'O', b'P' + n - 1],
        F(n @ 1..=4) => format!("\x1b[1;{m}{}", (b'P' + n - 1) as char).into_bytes(),
        F(5) => tilde(15),
        F(6) => tilde(17),
        F(7) => tilde(18),
        F(8) => tilde(19),
        F(9) => tilde(20),
        F(10) => tilde(21),
        F(11) => tilde(23),
        F(12) => tilde(24),
        _ => return None,
    })
}

#[cfg(windows)]
fn ctrl_byte(c: char) -> Option<u8> {
    match c {
        'a'..='z' => Some(c as u8 - b'a' + 1),
        'A'..='Z' => Some(c.to_ascii_lowercase() as u8 - b'a' + 1),
        ' ' | '@' => Some(0),
        '[' => Some(0x1b),
        '\\' => Some(0x1c),
        ']' => Some(0x1d),
        '^' => Some(0x1e),
        '_' | '/' => Some(0x1f),
        '?' => Some(0x7f),
        _ => None,
    }
}

pub async fn attach(endpoint: &Endpoint, id: u128, label: &str) -> anyhow::Result<()> {
    let stream = open_session(endpoint, TerminalMode::Attach(id)).await
        .with_context(|| format!("opening an attach session on {label}"))?;

    println!("── attached to {label} · Ctrl+C detaches, ↑↓ history, the instance keeps running ──");

    let ended_by_remote = {
        // RawConsole rather than plain raw mode: the redraws below are ANSI,
        // which a Windows console only interprets with VT processing on.
        let _console = RawConsole::enter()?;
        pump_attach(stream).await?
    };

    if ended_by_remote {
        println!("\n── the instance's output stream closed ──");
    } else {
        println!("\n── detached ──");
    }
    Ok(())
}

const PROMPT: &str = "\x1b[2m❯\x1b[22m ";

/// The whole edit row: clear it, prompt, line, cursor put back in place.
fn edit_row(editor: &LineEditor) -> String {
    let display = editor.display();
    let back = display.chars().count() - editor.cursor();
    let mut row = format!("\r\x1b[K{PROMPT}{display}");
    if back > 0 {
        row.push_str(&format!("\x1b[{back}D"));
    }
    row
}

/// Returns true if the remote end closed the session, false if the user did.
///
/// The editor owns the bottom row; remote output (always whole lines) is
/// written above it by clearing the row, printing, and putting the row back.
async fn pump_attach(stream: TcpStream) -> anyhow::Result<bool> {
    let (mut sock_r, mut sock_w) = stream.into_split();
    let mut events = EventStream::new();
    let mut stdout = tokio::io::stdout();
    let mut editor = LineEditor::new();
    let mut buf = [0u8; 4096];

    stdout.write_all(edit_row(&editor).as_bytes()).await?;
    stdout.flush().await?;

    loop {
        tokio::select! {
            read = sock_r.read(&mut buf) => match read {
                Ok(0) | Err(_) => return Ok(true),
                Ok(n) => {
                    let mut out = b"\r\x1b[K".to_vec();
                    out.extend_from_slice(&crlf(&buf[..n]));
                    out.extend_from_slice(edit_row(&editor).as_bytes());
                    stdout.write_all(&out).await?;
                    stdout.flush().await?;
                }
            },
            event = events.next() => match event {
                None => return Ok(false),
                Some(Err(e)) => return Err(e.into()),
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    if is_ctrl(&key, 'c') {
                        return Ok(false);
                    }
                    match editor.handle(&key) {
                        Keystroke::Ignored => {}
                        Keystroke::Edited => {
                            stdout.write_all(edit_row(&editor).as_bytes()).await?;
                            stdout.flush().await?;
                        }
                        Keystroke::Submit(text) => {
                            // Scroll the submitted line away, then a fresh prompt.
                            stdout.write_all(format!("\r\n{}", edit_row(&editor)).as_bytes()).await?;
                            stdout.flush().await?;
                            if sock_w.write_all(text.as_bytes()).await.is_err() {
                                return Ok(true);
                            }
                        }
                    }
                }
                Some(Ok(_)) => {}
            },
        }
    }
}

fn is_ctrl(key: &KeyEvent, c: char) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char(got) if got.eq_ignore_ascii_case(&c))
}

/// Raw mode does not translate: a bare `\n` would step down a row without
/// returning to column 0.
fn crlf(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut prev = 0u8;
    for &b in bytes {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}
