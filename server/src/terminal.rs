use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use processkit::ProcessStdin;
use protocol::term::{self, FrameReader, OwnedFrame};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, Mutex};

// Both bridges run over the persistent session stream, framed in both
// directions (`protocol::term`) and ended with an explicit `Close` — the
// connection itself is never closed, it carries the call's reply next.
//
// `attach_bridge` speaks plain bytes (inside Data frames) to the *supervised*
// process, which processkit runs on pipes, so it's line-wise — fine for CLIs,
// not full-screen programs. `shell_bridge` runs its own shell under a real PTY.

/// `docker attach`-style: bridge the session to an already-running instance.
pub async fn attach_bridge<S: AsyncRead + AsyncWrite + Unpin + Send>(
    s: &mut S,
    mut output_rx: broadcast::Receiver<Vec<u8>>,
    stdin_slot: Arc<Mutex<Option<ProcessStdin>>>,
) -> std::io::Result<()> {
    let (mut sock_r, mut sock_w) = tokio::io::split(s);
    let mut reader = FrameReader::new();

    let peer_closed = loop {
        tokio::select! {
            chunk = output_rx.recv() => match chunk {
                Ok(chunk) => {
                    sock_w.write_all(&term::data_frame(&chunk)).await?;
                    sock_w.flush().await?;
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                // Sender dropped: the supervised run ended.
                Err(broadcast::error::RecvError::Closed) => break false,
            },
            frame = reader.next(&mut sock_r) => match frame? {
                // Peer vanished without a Close: nothing to hand off to.
                None => return Ok(()),
                Some(OwnedFrame::Close) => break true,
                Some(OwnedFrame::Data(bytes)) => {
                    let mut slot = stdin_slot.lock().await;
                    let Some(stdin) = slot.as_mut() else { break false };
                    if stdin.write(&bytes).await.is_err() || stdin.flush().await.is_err() {
                        break false;
                    }
                }
                Some(_) => {} // Resize/Unknown carry no meaning for a pipe.
            },
        }
    };
    reader.finish(&mut sock_r, &mut sock_w, peer_closed).await
}

/// `docker exec`-style: a fresh shell in the instance's repo dir, run under a
/// real PTY (ConPTY on Windows). Both directions are framed: client → server
/// carries keystrokes (Data) and resizes (Resize); server → client carries the
/// terminal's output as Data frames, ending with Close.
pub async fn shell_bridge<S: AsyncRead + AsyncWrite + Unpin + Send>(
    s: &mut S,
    shell: String,
    cwd: PathBuf,
    cols: u16,
    rows: u16,
) -> std::io::Result<()> {
    let (mut sock_r, mut sock_w) = tokio::io::split(s);
    let mut reader = FrameReader::new();

    let size = PtySize { rows: rows.max(1), cols: cols.max(1), pixel_width: 0, pixel_height: 0 };
    let pair = match native_pty_system().openpty(size) {
        Ok(pair) => pair,
        Err(e) => return fail(&mut reader, &mut sock_r, &mut sock_w, format!("failed to open a pty: {e}")).await,
    };

    let mut cmd = CommandBuilder::new(&shell);
    cmd.cwd(&cwd);
    let mut child = match pair.slave.spawn_command(cmd) {
        Ok(child) => child,
        Err(e) => return fail(&mut reader, &mut sock_r, &mut sock_w, format!("failed to start shell: {e}")).await,
    };
    // The slave handle must go before the master will ever report EOF.
    drop(pair.slave);

    let pty_reader = match pair.master.try_clone_reader() {
        Ok(reader) => reader,
        Err(e) => {
            let _ = child.kill();
            return fail(&mut reader, &mut sock_r, &mut sock_w, format!("cloning the pty reader failed: {e}")).await;
        }
    };
    let writer = match pair.master.take_writer() {
        Ok(writer) => writer,
        Err(e) => {
            let _ = child.kill();
            return fail(&mut reader, &mut sock_r, &mut sock_w, format!("taking the pty writer failed: {e}")).await;
        }
    };

    // portable-pty's handles are blocking, so each gets a thread and talks to
    // the async side over a channel.
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
    let output_pump = thread::spawn(move || pump_pty_output(pty_reader, out_tx));
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

    // `Some(bool)`: session over, bool = the client's Close was already seen.
    // `None` on the peer vanishing, so we skip the close handshake.
    let outcome: Option<bool> = 'session: loop {
        tokio::select! {
            // Biased so pending output is flushed before the exit branch wins
            // the race — otherwise a command's last line can be lost.
            biased;
            chunk = out_rx.recv() => match chunk {
                // The pty closed for real (unix, or the master went away).
                None => break Some(false),
                Some(chunk) => {
                    if sock_w.write_all(&term::data_frame(&chunk)).await.is_err() || sock_w.flush().await.is_err() {
                        break None;
                    }
                }
            },
            _ = exited_rx.recv() => {
                // The shell exited, e.g. the user typed `exit`. Drain whatever
                // it printed on the way out, then end.
                while let Ok(chunk) = out_rx.try_recv() {
                    if sock_w.write_all(&term::data_frame(&chunk)).await.is_err() {
                        break 'session None;
                    }
                }
                let _ = sock_w.flush().await;
                break Some(false);
            }
            frame = reader.next(&mut sock_r) => match frame {
                Err(_) => break None,
                Ok(None) => break None,
                Ok(Some(OwnedFrame::Close)) => break Some(true),
                Ok(Some(OwnedFrame::Data(bytes))) => {
                    if in_tx.send(bytes).await.is_err() {
                        break None;
                    }
                }
                Ok(Some(OwnedFrame::Resize { cols, rows })) => {
                    // `MasterPty` is not `Sync`, so this borrow must not cross
                    // an await — it doesn't.
                    let size = PtySize { rows: rows.max(1), cols: cols.max(1), pixel_width: 0, pixel_height: 0 };
                    if let Err(e) = pair.master.resize(size) {
                        eprintln!("shell terminal: resize to {cols}x{rows} failed: {e}");
                    }
                }
                Ok(Some(OwnedFrame::Unknown)) => {}
            },
        }
    };

    // Order matters on the way out: kill the shell, close the writer channel
    // so its thread drops the writer, then drop the master — closing the
    // pseudoconsole is what finally releases the reader thread.
    let _ = killer.kill();
    drop(in_tx);
    let result = match outcome {
        Some(peer_closed) => reader.finish(&mut sock_r, &mut sock_w, peer_closed).await,
        None => Ok(()),
    };
    drop(pair.master);
    let _ = output_pump.join();
    let _ = input_pump.join();
    let _ = child_waiter.join();
    result
}

/// Report a setup error to the client mid-session (a Data frame it can print),
/// then end the session cleanly so the reply can follow.
async fn fail<R, W>(reader: &mut FrameReader, r: &mut R, w: &mut W, msg: String) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    eprintln!("shell terminal: {msg}");
    let _ = w.write_all(&term::data_frame(format!("{msg}\r\n").as_bytes())).await;
    let _ = w.flush().await;
    let _ = reader.finish(r, w, false).await;
    Err(std::io::Error::other(msg))
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
