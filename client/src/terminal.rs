//! `client shell <target>` / `client attach <target>`.
//!
//! Terminals are a CLI mode, not a TUI screen: the app never has to suspend
//! itself, and the session owns the console outright.
//!
//! The two modes are deliberately different, because what is on the far end
//! differs:
//!
//! - **shell** runs against a real PTY. This end is a dumb conduit — every
//!   byte goes straight through, `Ctrl+C` included, and the remote shell does
//!   the echoing, line editing and screen drawing. Full-screen programs work.
//!   The session ends when the shell does (`exit`), like PuTTY or ssh.
//! - **attach** bridges to the *supervised* process, which runs on pipes with
//!   no PTY. Nothing echoes and no escape sequence means anything, so this end
//!   runs a small line editor, and `Ctrl+C` ends the session rather than being
//!   forwarded — there is nothing on the far side that could act on it.

use std::time::Duration;

use anyhow::{Context, bail};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use futures::StreamExt;
use protocol::{Action, Response, TerminalMode, term};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::console::RawConsole;
use crate::net::{self, Endpoint};

/// How often the local window size is compared against the last one sent.
/// Unix only — its shell pump forwards raw stdin bytes, so reading resize
/// events would mean sharing stdin with the byte pump; Windows gets resizes
/// as console events instead.
#[cfg(not(windows))]
const RESIZE_POLL: Duration = Duration::from_millis(250);

/// Ask for a session, then connect to the side-channel port and complete the
/// token handshake. Split out from the bridges so it can be exercised without
/// a TTY: everything after this point needs a real console.
pub async fn open_session(endpoint: &Endpoint, mode: TerminalMode) -> anyhow::Result<TcpStream> {
    let addr = endpoint.addr;
    let (port, token, ttl_secs) = match net::call(endpoint, Action::OpenTerminal { mode }).await {
        Ok(Response::SessionOpened { port, token, ttl_secs, .. }) => (port, token, ttl_secs),
        Ok(other) => bail!("expected a terminal session, got {other:?}"),
        Err(e) => bail!("{e}"),
    };

    let mut stream = tokio::time::timeout(
        Duration::from_secs(ttl_secs.max(1)),
        TcpStream::connect((addr.ip(), port)),
    ).await
        .with_context(|| format!("session port {port} did not accept a connection within {ttl_secs}s"))?
        .with_context(|| format!("connecting to session port {port}"))?;

    // Interactive sessions ride this socket: a keystroke and its echo are
    // both tiny writes, and Nagle would batch them into visible typing lag.
    let _ = stream.set_nodelay(true);

    stream.write_all(&token).await.context("sending the session token")?;
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await.context("the server closed the session without acknowledging it")?;
    if ack[0] != 1 {
        bail!("the server rejected the session token");
    }
    Ok(stream)
}

/// The local window size, or a conventional default if it cannot be read
/// (piped stdout, for instance) — a pty still needs *some* size.
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

/// The debug tee: `CONTAINER_SHELL_TEE=<path>` also writes everything the
/// server sends into a file — the exact bytes the local terminal has to
/// render, for diagnosing "my terminal shows garbage" without guessing.
fn open_tee() -> Option<std::fs::File> {
    std::env::var_os("CONTAINER_SHELL_TEE").and_then(|path| std::fs::File::create(path).ok())
}

/// What the output filter decided about one recognized escape sequence.
#[cfg(windows)]
enum Intercept {
    /// `\e[6n`: the remote pty is asking its terminal where the cursor is —
    /// and blocks its whole output pipeline until somebody answers.
    CursorQuery,
    /// Swallowed with no reply owed (`\e[?9001h`: ConPTY asking its terminal
    /// to switch to win32-input-mode. Letting it reach the local console
    /// would flip *our* input into that encoding — every keystroke arrives
    /// as escape-sequence spam — and we already send ConPTY plain VT.)
    Drop,
}

/// Recognizes, and removes from the printable stream, the few sequences the
/// remote pty addresses *at the terminal* rather than at the screen. They
/// must not reach the local console: the console would inject its reply into
/// our own input queue, where the event decoder mangles it beyond repair
/// (evt_probe shows a `\e[..R` reply coming back as a phantom F3 key).
/// Instead the pump answers on the socket itself, like a terminal emulator.
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

    /// Split a chunk into what should be printed and how many cursor queries
    /// were removed from it. A trailing partial candidate is held back until
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
                        // Might complete in the next chunk; hold it back.
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

/// Raw conduit outward, decoded key events inward.
///
/// Output is written to the console verbatim — minus the handful of
/// terminal-addressed queries `OutputFilter` intercepts, which the pump
/// answers itself the way PuTTY would. Input cannot be raw at all on
/// Windows: a console *byte* read only ever yields character keys — arrows,
/// function keys and Ctrl+C never appear in the stream no matter which
/// console modes are set (evt_probe demonstrates this). So the decoded
/// events are read, the same way the TUI reads them, and each key is
/// re-encoded into the escape sequence a terminal would have sent — which
/// the far side's ConPTY parses right back into key events for the shell.
/// Resizes arrive as events too, so no polling.
#[cfg(windows)]
async fn pump_shell(stream: TcpStream, cols: u16, rows: u16) -> anyhow::Result<()> {
    // The pty was created at this size already; only changes matter now.
    let _ = (cols, rows);

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

    // Keys that arrived as a Press. A Release is normally the echo of one of
    // these and must be dropped or every keystroke doubles — but some events
    // only ever arrive as a Release (a ^C synthesized from pasted input, for
    // one), and dropping those would lose real keystrokes.
    let mut pressed: std::collections::HashSet<(KeyCode, KeyModifiers)> =
        std::collections::HashSet::new();

    dbg("pump: start".into());
    loop {
        tokio::select! {
            read = sock_r.read(&mut from_remote) => match read {
                // The shell exited, or the server tore the session down.
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
                    // Answer once everything before the query is on screen,
                    // so the reported position is the one the query meant.
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
                // The console only reports focus if the remote asked for it
                // (its `\e[?1004h` passed through to the local console), so
                // a report always has a waiting recipient.
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
                // Mouse: nothing on the far side wants it.
                Some(Ok(other)) => dbg(format!("pump: ignored {other:?}")),
            },
        }
    }
}

/// On unix a raw-mode tty hands over the byte stream exactly as a terminal
/// produced it — arrows, Ctrl+C and all — so bytes are forwarded verbatim
/// instead of decoding and re-encoding events. Resize has no event here;
/// the size is polled.
#[cfg(not(windows))]
async fn pump_shell(stream: TcpStream, mut cols: u16, mut rows: u16) -> anyhow::Result<()> {
    let (mut sock_r, mut sock_w) = stream.into_split();
    let mut stdout = tokio::io::stdout();
    let mut resize_tick = tokio::time::interval(RESIZE_POLL);
    resize_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut tee = open_tee();

    // Keystrokes come from a plain OS thread, not `tokio::io::stdin()`: a
    // tty read blocks until the next keypress and cannot be cancelled, and a
    // tokio blocking task stuck like that keeps the runtime — and therefore
    // the whole process — alive after the session ends, until one more key is
    // pressed. A detached thread parked in read(2) just dies with us.
    let (key_tx, mut key_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                // EOF: stop typing; dropping the sender hangs up the pump.
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
                // The shell exited, or the server tore the session down.
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

/// One decoded key press → the bytes a terminal would have sent for it
/// (xterm encoding, which ConPTY on the far side parses). `None` for keys
/// with no byte representation, like bare modifiers.
#[cfg(windows)]
fn encode_key(key: &KeyEvent) -> Option<Vec<u8>> {
    use KeyCode::*;

    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    // xterm's modifier parameter: 1, plus shift 1 / alt 2 / ctrl 4.
    let m = 1 + shift as u8 + 2 * (alt as u8) + 4 * (ctrl as u8);

    // Cursor-style keys: `\e[A`, with modifiers `\e[1;{m}A`.
    let arrow = |c: u8| if m == 1 {
        vec![0x1b, b'[', c]
    } else {
        format!("\x1b[1;{m}{}", c as char).into_bytes()
    };
    // Editing keys: `\e[{n}~`, with modifiers `\e[{n};{m}~`.
    let tilde = |n: u8| if m == 1 {
        format!("\x1b[{n}~").into_bytes()
    } else {
        format!("\x1b[{n};{m}~").into_bytes()
    };
    // Ordinary bytes; Alt is an ESC prefix (Alt+X sends `\ex`).
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
        // F1–F4 are SS3 when unmodified, CSI like the arrows otherwise.
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

/// The C0 control a terminal sends for Ctrl plus this character, if any.
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

// ---- attach ------------------------------------------------------------

/// Restores cooked mode however we leave the attach bridge.
struct RawMode;

impl RawMode {
    fn enter() -> anyhow::Result<Self> {
        enable_raw_mode().context("could not switch the terminal to raw mode")?;
        Ok(RawMode)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

pub async fn attach(endpoint: &Endpoint, id: u128, label: &str) -> anyhow::Result<()> {
    let stream = open_session(endpoint, TerminalMode::Attach(id)).await
        .with_context(|| format!("opening an attach session on {label}"))?;

    println!("── attached to {label} · Ctrl+C detaches, the instance keeps running ──");

    let ended_by_remote = {
        let _raw = RawMode::enter()?;
        pump_attach(stream).await?
    };

    if ended_by_remote {
        println!("\n── the instance's output stream closed ──");
    } else {
        println!("\n── detached ──");
    }
    Ok(())
}

/// Returns true if the remote end closed the session, false if the user did.
async fn pump_attach(stream: TcpStream) -> anyhow::Result<bool> {
    let (mut sock_r, mut sock_w) = stream.into_split();
    let mut events = EventStream::new();
    let mut stdout = tokio::io::stdout();
    let mut line: Vec<char> = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        tokio::select! {
            read = sock_r.read(&mut buf) => match read {
                Ok(0) | Err(_) => return Ok(true),
                Ok(n) => {
                    // Raw mode does not translate: a bare \n would step down
                    // a row without returning to column 0.
                    stdout.write_all(&crlf(&buf[..n])).await?;
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
                    if let Some(out) = edit(&mut line, key) {
                        stdout.write_all(out.echo.as_bytes()).await?;
                        stdout.flush().await?;
                        if let Some(send) = out.send
                            && sock_w.write_all(send.as_bytes()).await.is_err() {
                            return Ok(true);
                        }
                    }
                }
                Some(Ok(_)) => {}
            },
        }
    }
}

struct Edit {
    /// Local echo, since the remote is a pipe and echoes nothing.
    echo: String,
    send: Option<String>,
}

fn edit(line: &mut Vec<char>, key: KeyEvent) -> Option<Edit> {
    match key.code {
        KeyCode::Enter => {
            let text: String = line.drain(..).collect();
            // cmd.exe and POSIX shells both accept CRLF-terminated lines.
            Some(Edit { echo: "\r\n".to_string(), send: Some(format!("{text}\r\n")) })
        }
        KeyCode::Backspace => {
            line.pop()?;
            // Erase the glyph, not just the cursor position.
            Some(Edit { echo: "\x08 \x08".to_string(), send: None })
        }
        KeyCode::Tab => {
            line.push('\t');
            Some(Edit { echo: "\t".to_string(), send: None })
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            line.push(c);
            Some(Edit { echo: c.to_string(), send: None })
        }
        _ => None,
    }
}

fn is_ctrl(key: &KeyEvent, c: char) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char(got) if got.eq_ignore_ascii_case(&c))
}

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
