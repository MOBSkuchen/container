//! Drives `client shell` under a real ConPTY and reports what a terminal
//! would actually experience.
//!
//! The pipe-based smoke tests cannot reach the client's console code —
//! `RawConsole`, the ReadConsoleW/WriteConsoleW paths inside std, the resize
//! poll — because none of it runs when stdin/stdout are pipes. A child of a
//! ConPTY gets genuine console handles, so all of it runs here, and what this
//! probe reads from the master side is exactly the byte stream a terminal
//! emulator would have to render.
//!
//! Checks: prompt appears, per-keystroke echo latency, multi-line output,
//! window resize propagation, and that `exit` ends the client process.
//!
//! Usage: cargo run -p client --example shell_probe -- <server-addr> <client-exe>

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use protocol::{Action, ErrorCode, RepoState, Response, RetryPolicy, auth};

use client::book::{Book, ServerEntry};
use client::net::{self, Endpoint, NetError};

const INSTANCE: &str = "shell-probe";
/// Must match the phrase the test server was created with.
const PHRASE: &str = "smoke-test-passphrase";

const COLS: u16 = 100;
const ROWS: u16 = 30;

fn endpoint(addr: SocketAddr) -> Endpoint {
    Endpoint::new(addr, auth::hash_or_random(Some(PHRASE)).to_vec())
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let addr = SocketAddr::from_str(&args.next().expect("server addr")).expect("bad addr");
    let client_exe = PathBuf::from(args.next().expect("path to client.exe"));
    assert!(client_exe.exists(), "no client binary at {}", client_exe.display());

    let ep = endpoint(addr);
    ensure_instance(&ep).await;

    let dir = std::env::temp_dir().join("container-shell-probe");
    std::fs::create_dir_all(&dir).unwrap();
    let book_path = dir.join("servers.chld");
    let book = Book {
        key: ep.key.clone(),
        servers: vec![ServerEntry { id: 1, name: "probe".into(), addr, key: Vec::new() }],
    };
    client::book::save(&book_path, &book).await.expect("writing the probe book");

    // Everything below is blocking pty work; no other tasks are running.
    probe(&client_exe, &book_path, &dir);
}

/// Create the fixture instance if needed and wait until its checkout exists —
/// the shell needs a cwd on the server side.
async fn ensure_instance(ep: &Endpoint) {
    let existing = match net::call(ep, Action::ListInstances).await {
        Ok(Response::InstanceList(list)) => list.into_iter().find(|i| i.name == INSTANCE),
        other => panic!("server not reachable for probe setup: {other:?}"),
    };

    let id = match existing {
        Some(inst) => inst.id,
        None => match net::call(ep, Action::CreateInstance {
            name: INSTANCE.to_string(),
            repo_url: "https://github.com/octocat/Hello-World".to_string(),
            branch: None,
            command: "cmd.exe".to_string(),
            args: vec!["/q".into(), "/k".into(), "echo probe-instance".into()],
            env: Default::default(),
            autostart: false,
            retry_policy: RetryPolicy::Never,
        }).await {
            Ok(Response::InstanceCreated { id }) => id,
            other => panic!("could not create the fixture instance: {other:?}"),
        },
    };

    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match net::call(ep, Action::CheckInstance { id }).await {
            Ok(Response::InstanceStatus(status)) => match status.repo {
                RepoState::Ready => return,
                RepoState::CloneFailed(e) => panic!("fixture clone failed: {e}"),
                RepoState::Provisioning => {}
            },
            Ok(other) => panic!("unexpected reply to CheckInstance: {other:?}"),
            Err(NetError::Api(e)) if e.code == ErrorCode::NotFound => panic!("fixture vanished"),
            Err(_) => {}
        }
        assert!(Instant::now() < deadline, "fixture clone did not finish in time");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

struct Session {
    rx: mpsc::Receiver<Vec<u8>>,
    writer: Box<dyn Write + Send>,
    transcript: Vec<u8>,
    /// How far the DSR scan got, so a query is answered exactly once.
    scanned: usize,
}

impl Session {
    /// Pull whatever output has arrived, without blocking longer than `wait`.
    fn drain(&mut self, wait: Duration) -> usize {
        let before = self.transcript.len();
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left.max(Duration::from_millis(1))) {
                Ok(chunk) => {
                    self.transcript.extend_from_slice(&chunk);
                    self.answer_queries();
                    // Keep pulling until the stream goes quiet briefly.
                    if Instant::now() >= deadline {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        self.transcript.len() - before
    }

    /// Do what a terminal does with a cursor-position query: answer it.
    fn answer_queries(&mut self) {
        // Re-scan a little overlap in case the query split across chunks.
        let start = self.scanned.saturating_sub(3);
        let mut i = start;
        while i + 4 <= self.transcript.len() {
            if &self.transcript[i..i + 4] == b"\x1b[6n" {
                // A realistic answer: a terminal mid-scrollback, cursor well
                // below the top — the easy `1;1` would hide anchoring bugs.
                let _ = self.writer.write_all(b"\x1b[17;1R");
                let _ = self.writer.flush();
                println!("      (answered a cursor-position query)");
                i += 4;
            } else {
                i += 1;
            }
        }
        self.scanned = self.transcript.len();
    }

    fn send(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).expect("writing to the pty");
        self.writer.flush().expect("flushing the pty");
    }

    /// Wait until `needle` shows up in output received after `mark`.
    fn wait_for(&mut self, mark: usize, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let text = String::from_utf8_lossy(&self.transcript[mark..]);
            if text.contains(needle) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            self.drain(Duration::from_millis(50));
        }
    }
}

fn probe(client_exe: &PathBuf, book_path: &PathBuf, out_dir: &PathBuf) {
    let pair = native_pty_system()
        .openpty(PtySize { rows: ROWS, cols: COLS, pixel_width: 0, pixel_height: 0 })
        .expect("opening the outer pty");

    let mut cmd = CommandBuilder::new(client_exe);
    cmd.args(["-c", &book_path.to_string_lossy(), "shell", &format!("probe/{INSTANCE}")]);
    // Capture what the server sends before the outer conhost re-renders it —
    // this is the byte stream a real terminal would have to interpret.
    cmd.env("CONTAINER_SHELL_TEE", out_dir.join("inner.raw"));
    cmd.env("CONTAINER_SHELL_DEBUG", out_dir.join("debug.log"));
    let mut child = pair.slave.spawn_command(cmd).expect("spawning the client");
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().expect("cloning the reader");
    let writer = pair.master.take_writer().expect("taking the writer");

    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    // Detached on purpose: ConPTY holds the pipe open until the master drops,
    // and the probe exits as a whole anyway.
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
            }
        }
    });

    let mut s = Session { rx, writer, transcript: Vec::new(), scanned: 0 };
    let mut failures: Vec<String> = Vec::new();

    // 1. The remote prompt must appear on its own.
    println!("[1] waiting for the remote prompt...");
    if !s.wait_for(0, ">", Duration::from_secs(20)) {
        failures.push("no shell prompt within 20s".into());
    }
    s.drain(Duration::from_millis(700));

    // 2. Echo latency, one keystroke at a time like a human.
    println!("[2] typing 'echo probe-ok' one key at a time...");
    let mut latencies: Vec<u128> = Vec::new();
    for b in "echo probe-ok".bytes() {
        let mark = s.transcript.len();
        let t0 = Instant::now();
        s.send(&[b]);
        let deadline = Instant::now() + Duration::from_secs(2);
        while s.transcript.len() == mark && Instant::now() < deadline {
            s.drain(Duration::from_millis(5));
        }
        if s.transcript.len() > mark {
            latencies.push(t0.elapsed().as_millis());
        } else {
            failures.push(format!("keystroke {:?} never echoed", b as char));
            break;
        }
    }
    let mark = s.transcript.len();
    s.send(b"\r");
    if !s.wait_for(mark, "probe-ok", Duration::from_secs(5)) {
        failures.push("'echo probe-ok' produced no output".into());
    }
    s.drain(Duration::from_millis(500));
    if !latencies.is_empty() {
        let mut sorted = latencies.clone();
        sorted.sort();
        println!(
            "      echo latency ms: min {} / median {} / max {}   ({latencies:?})",
            sorted[0], sorted[sorted.len() / 2], sorted[sorted.len() - 1]
        );
    }

    // 3. Multi-line output for formatting inspection.
    println!("[3] running 'dir /b'...");
    let mark = s.transcript.len();
    s.send(b"dir /b\r");
    if !s.wait_for(mark, "README", Duration::from_secs(5)) {
        failures.push("'dir /b' did not list the checkout".into());
    }
    s.drain(Duration::from_millis(500));

    // 3b. Arrow keys only exist if ENABLE_VIRTUAL_TERMINAL_INPUT actually
    //     took: the outer conhost delivers my `\e[A` as an Up key event, and
    //     only VT input mode turns that back into bytes the client can read.
    println!("[3b] pressing Up — the previous command should be recalled...");
    let mark = s.transcript.len();
    s.send(b"\x1b[A");
    if !s.wait_for(mark, "dir /b", Duration::from_secs(3)) {
        failures.push("Up arrow did not recall history (VT input mode is not working)".into());
        s.send(b"\x1b"); // leave nothing half-typed
    } else {
        s.send(b"\x1b"); // ESC clears cmd's recalled line
    }
    s.drain(Duration::from_millis(300));

    // 3c. Non-ASCII input has to survive the whole chain: UTF-8 in, UTF-16
    //     console events, UTF-8 frames, the inner pty, and back.
    println!("[3c] typing 'echo grüß-ok'...");
    let mark = s.transcript.len();
    s.send("echo gr\u{fc}\u{df}-ok\r".as_bytes());
    if !s.wait_for(mark, "gr\u{fc}\u{df}-ok", Duration::from_secs(5)) {
        failures.push("umlauts got mangled between keyboard and shell".into());
    }
    s.drain(Duration::from_millis(300));

    // 3d. Ctrl+C must reach the far side and interrupt the running command —
    //     the whole point of the PuTTY-style rework.
    println!("[3d] interrupting a 30s ping with Ctrl+C...");
    let mark = s.transcript.len();
    s.send(b"ping -n 30 127.0.0.1\r");
    if !s.wait_for(mark, "127.0.0.1", Duration::from_secs(5)) {
        failures.push("ping never started".into());
    }
    let mark = s.transcript.len();
    s.send(b"\x03");
    // Interrupted means the prompt takes commands again long before the 30
    // pings are done — a marker echo proves that better than hunting for the
    // prompt string, which the renderer may coalesce into a later repaint.
    std::thread::sleep(Duration::from_millis(1500));
    s.send(b"echo alive-after-interrupt\r");
    if !s.wait_for(mark, "alive-after-interrupt", Duration::from_secs(8)) {
        failures.push("Ctrl+C did not interrupt the running command".into());
    }
    s.drain(Duration::from_millis(300));

    // 4. Resize the outer window; the client's poll should carry it through
    //    to the remote pty within ~250ms.
    println!("[4] resizing the window to 90x25...");
    pair.master
        .resize(PtySize { rows: 25, cols: 90, pixel_width: 0, pixel_height: 0 })
        .expect("resizing the outer pty");
    std::thread::sleep(Duration::from_millis(800));
    let mark = s.transcript.len();
    s.send(b"mode con\r");
    if !s.wait_for(mark, "90", Duration::from_secs(5)) {
        failures.push("the resize never reached the remote pty (no '90' from `mode con`)".into());
    }
    s.drain(Duration::from_millis(500));

    // 5. `exit` must end the session AND the client process, promptly.
    println!("[5] typing 'exit'...");
    s.send(b"exit\r");
    let t0 = Instant::now();
    let mut exited = false;
    while t0.elapsed() < Duration::from_secs(4) {
        if child.try_wait().expect("try_wait").is_some() {
            exited = true;
            break;
        }
        s.drain(Duration::from_millis(100));
    }
    if !exited {
        println!("      client still running 4s after exit — sending one extra key to test the stdin theory");
        s.send(b" ");
        let t1 = Instant::now();
        while t1.elapsed() < Duration::from_secs(3) {
            if child.try_wait().expect("try_wait").is_some() {
                failures.push(format!(
                    "client hung after `exit` until another key was pressed ({}ms + keypress)",
                    t0.elapsed().as_millis()
                ));
                exited = true;
                break;
            }
            s.drain(Duration::from_millis(100));
        }
    }
    if !exited {
        failures.push("client never exited after `exit`; killing it".into());
        let _ = child.kill();
    }
    s.drain(Duration::from_millis(300));

    let raw = out_dir.join("transcript.raw");
    std::fs::write(&raw, &s.transcript).unwrap();
    let visible = String::from_utf8_lossy(&s.transcript)
        .replace('\u{1b}', "\\e")
        .replace('\r', "\\r")
        .replace('\u{7}', "\\a");
    let txt = out_dir.join("transcript.txt");
    std::fs::write(&txt, &visible).unwrap();
    println!("\ntranscript: {} ({} bytes, sanitized copy in transcript.txt)", raw.display(), s.transcript.len());

    if let Ok(log) = std::fs::read_to_string(out_dir.join("debug.log")) {
        println!("\n---- client debug log (last 40 lines) ----");
        let lines: Vec<&str> = log.lines().collect();
        for line in lines.iter().skip(lines.len().saturating_sub(40)) {
            println!("{line}");
        }
    }

    println!("\n---- last 1500 chars of the sanitized stream ----");
    let tail: String = visible.chars().rev().take(1500).collect::<Vec<_>>().into_iter().rev().collect();
    println!("{tail}");
    println!("---- end ----\n");

    if failures.is_empty() {
        println!("PROBE PASSED");
    } else {
        println!("PROBE FOUND {} PROBLEM(S):", failures.len());
        for f in &failures {
            println!("  - {f}");
        }
        std::process::exit(1);
    }
}
