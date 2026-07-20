use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use processkit::ProcessStdin;
use protocol::term;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, Mutex};

// `attach_bridge` speaks plain bytes to the *supervised* process, which
// processkit runs on pipes, so it's line-wise — fine for CLIs, not
// full-screen programs. `shell_bridge` runs its own shell under a real PTY
// instead and is a raw byte conduit.

/// `docker attach`-style: bridge the socket to an already-running instance.
pub async fn attach_bridge(
    stream: TcpStream,
    mut output_rx: broadcast::Receiver<Vec<u8>>,
    stdin_slot: Arc<Mutex<Option<ProcessStdin>>>,
) {
    let (mut sock_r, mut sock_w) = stream.into_split();
    let mut buf = [0u8; 4096];

    loop {
        tokio::select! {
            chunk = output_rx.recv() => {
                match chunk {
                    Ok(chunk) => {
                        if sock_w.write_all(&chunk).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    // Sender dropped: the supervised run ended.
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            read = sock_r.read(&mut buf) => {
                match read {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        let mut slot = stdin_slot.lock().await;
                        let Some(stdin) = slot.as_mut() else { break };
                        if stdin.write(&buf[..n]).await.is_err() || stdin.flush().await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
    let _ = sock_w.shutdown().await;
}

/// `docker exec`-style: a fresh shell in the instance's repo dir, run under a
/// real PTY (ConPTY on Windows) and bridged to the socket as raw bytes.
/// Client → server is framed (`protocol::term`, for resize messages);
/// server → client is the terminal's raw output.
pub async fn shell_bridge(stream: TcpStream, shell: String, cwd: PathBuf, cols: u16, rows: u16) {
    let (mut sock_r, mut sock_w) = stream.into_split();

    let size = PtySize { rows: rows.max(1), cols: cols.max(1), pixel_width: 0, pixel_height: 0 };
    let pair = match native_pty_system().openpty(size) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("shell terminal: opening a pty failed: {e}");
            let _ = sock_w.write_all(format!("failed to open a pty: {e}\r\n").as_bytes()).await;
            return;
        }
    };

    let mut cmd = CommandBuilder::new(&shell);
    cmd.cwd(&cwd);
    let mut child = match pair.slave.spawn_command(cmd) {
        Ok(child) => child,
        Err(e) => {
            eprintln!("shell terminal: starting '{shell}' failed: {e}");
            let _ = sock_w.write_all(format!("failed to start shell: {e}\r\n").as_bytes()).await;
            return;
        }
    };
    // The slave handle must go before the master will ever report EOF.
    drop(pair.slave);

    let reader = match pair.master.try_clone_reader() {
        Ok(reader) => reader,
        Err(e) => {
            eprintln!("shell terminal: cloning the pty reader failed: {e}");
            let _ = child.kill();
            return;
        }
    };
    let writer = match pair.master.take_writer() {
        Ok(writer) => writer,
        Err(e) => {
            eprintln!("shell terminal: taking the pty writer failed: {e}");
            let _ = child.kill();
            return;
        }
    };

    // portable-pty's handles are blocking, so each gets a thread and talks to
    // the async side over a channel.
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
    let output_pump = thread::spawn(move || pump_pty_output(reader, out_tx));
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    let input_pump = thread::spawn(move || pump_pty_input(writer, in_rx));

    // The child has to be waited on separately. ConPTY keeps its end of the
    // output pipe open until the pseudoconsole itself is closed, so the
    // reader thread does *not* see EOF when the shell exits — without this,
    // typing `exit` would leave the session hanging.
    let mut killer = child.clone_killer();
    let (exited_tx, mut exited_rx) = mpsc::channel::<()>(1);
    let child_waiter = thread::spawn(move || {
        let _ = child.wait();
        let _ = exited_tx.blocking_send(());
    });

    let mut pending = Vec::new();
    let mut buf = [0u8; 8192];

    'session: loop {
        tokio::select! {
            // Biased so pending output is flushed before the exit branch wins
            // the race — otherwise a command's last line can be lost.
            biased;
            chunk = out_rx.recv() => {
                match chunk {
                    // The pty closed for real (unix, or the master went away).
                    None => break,
                    Some(chunk) => {
                        if sock_w.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                }
            }
            _ = exited_rx.recv() => {
                // The shell exited, e.g. the user typed `exit`. Drain whatever
                // it printed on the way out, then close.
                while let Ok(chunk) = out_rx.try_recv() {
                    if sock_w.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                break;
            }
            read = sock_r.read(&mut buf) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        pending.extend_from_slice(&buf[..n]);
                        // Resizes are applied inside; keystrokes come back to
                        // be forwarded here, so no borrow of the master is
                        // held across an await (`MasterPty` is not `Sync`).
                        let Some(chunks) = drain_frames(&mut pending, &pair.master) else {
                            break;
                        };
                        for chunk in chunks {
                            if in_tx.send(chunk).await.is_err() {
                                break 'session;
                            }
                        }
                    }
                }
            }
        }
    }

    // Order matters on the way out: kill the shell, close the writer channel
    // so its thread drops the writer, then drop the master — closing the
    // pseudoconsole is what finally releases the reader thread.
    let _ = killer.kill();
    drop(in_tx);
    let _ = sock_w.shutdown().await;
    drop(pair.master);
    let _ = output_pump.join();
    let _ = input_pump.join();
    let _ = child_waiter.join();
}

/// Consume every whole frame in `pending`, applying resizes as they are seen
/// and returning the keystroke payloads for the caller to forward.
///
/// Synchronous on purpose: `MasterPty` is `Send` but not `Sync`, so a borrow
/// of it must not be held across an await.
///
/// `None` means the stream is unusable and the session must end.
fn drain_frames(
    pending: &mut Vec<u8>,
    master: &Box<dyn MasterPty + Send>,
) -> Option<Vec<Vec<u8>>> {
    let mut data = Vec::new();
    loop {
        match term::decode(pending) {
            term::Decoded::Incomplete => return Some(data),
            term::Decoded::Invalid => {
                eprintln!("shell terminal: bad frame length from the client; closing");
                return None;
            }
            term::Decoded::Frame(frame, used) => {
                match frame {
                    term::Frame::Data(payload) => data.push(payload.to_vec()),
                    term::Frame::Resize { cols, rows } => {
                        let size = PtySize {
                            rows: rows.max(1), cols: cols.max(1),
                            pixel_width: 0, pixel_height: 0,
                        };
                        if let Err(e) = master.resize(size) {
                            eprintln!("shell terminal: resize to {cols}x{rows} failed: {e}");
                        }
                    }
                    // Forward-compatibility: a newer client's frame kind is
                    // skipped, not treated as a desync.
                    term::Frame::Unknown => {}
                }
                pending.drain(..used);
            }
        }
    }
}

fn pump_pty_output(mut reader: Box<dyn Read + Send>, out_tx: mpsc::Sender<Vec<u8>>) {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                    return;
                }
            }
        }
    }
}

fn pump_pty_input(mut writer: Box<dyn Write + Send>, mut in_rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(chunk) = in_rx.blocking_recv() {
        if writer.write_all(&chunk).is_err() || writer.flush().is_err() {
            return;
        }
    }
}
