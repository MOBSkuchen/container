use std::path::PathBuf;
use std::sync::Arc;
use futures::StreamExt;
use processkit::{Command, LineTerminator, ProcessGroup, ProcessStdin};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, Mutex};

// Both bridges speak raw bytes after the session handshake:
// client -> server bytes go to the process's stdin, server -> client bytes are
// the merged stdout+stderr lines. processkit is pipe-based (no PTY), so output
// arrives line-wise — fine for CLIs and REPLs, not full-screen TUI apps.

/// `docker attach`-style: bridge the socket to an already-running instance.
/// Ends when the client disconnects or the process exits.
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

/// `docker exec`-style: spawn a fresh shell in the instance's repo dir and
/// bridge it to the socket. The shell's whole tree is killed on disconnect.
pub async fn shell_bridge(stream: TcpStream, shell: String, cwd: PathBuf) {
    let (mut sock_r, mut sock_w) = stream.into_split();

    let group = match ProcessGroup::new() {
        Ok(group) => group,
        Err(e) => {
            eprintln!("shell terminal: creating process group failed: {e}");
            let _ = sock_w.write_all(format!("failed to start shell: {e}\n").as_bytes()).await;
            return;
        }
    };
    let cmd = Command::new(&shell)
        .current_dir(&cwd)
        .keep_stdin_open()
        .no_timeout()
        .line_terminator(LineTerminator::CarriageReturn)
        .create_no_window();
    let mut run = match group.start(&cmd).await {
        Ok(run) => run,
        Err(e) => {
            eprintln!("shell terminal: starting '{shell}' failed: {e}");
            let _ = sock_w.write_all(format!("failed to start shell: {e}\n").as_bytes()).await;
            return;
        }
    };
    let mut stdin = run.take_stdin();
    let mut events = run.output_events().ok();
    let mut buf = [0u8; 4096];

    loop {
        tokio::select! {
            ev = async {
                match events.as_mut() {
                    Some(e) => e.next().await,
                    None => None,
                }
            } => {
                match ev {
                    Some(event) => {
                        if let Some(text) = event.text() {
                            let mut chunk = text.as_bytes().to_vec();
                            chunk.push(b'\n');
                            if sock_w.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                    }
                    // Streams closed: the shell exited (e.g. the user typed `exit`).
                    None => break,
                }
            }
            read = sock_r.read(&mut buf) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let Some(stdin) = stdin.as_mut() else { break };
                        if stdin.write(&buf[..n]).await.is_err() || stdin.flush().await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }

    let _ = sock_w.shutdown().await;
    let _ = group.shutdown_ref().await;
}
