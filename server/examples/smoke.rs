//! Test-only RPC client that drives the server end-to-end.
//!
//! Usage:
//!   cargo run --example smoke -- <server-addr>            # full flow
//!   cargo run --example smoke -- <server-addr> phase2     # after a server
//!       restart: verify the instance came back via autostart, then clean up.
//!
//! Not the real client product — just enough to exercise every Action.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use bierpc::RpcClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use protocol::{auth, term};
use protocol::{AuthFailure, Reply, Request};
use server::api::{Action, ErrorCode, Response, TerminalMode};
use server::manager::{RepoState, RetryPolicy, RunState};

/// The shared key both ends are set up with; see `main`.
const PHRASE: &str = "smoke-test-passphrase";

fn key() -> Vec<u8> {
    auth::hash_or_random(Some(PHRASE)).to_vec()
}

async fn call(addr: SocketAddr, action: Action) -> Response {
    call_with(addr, &key(), action).await.expect("rpc call failed")
}

/// One authenticated round trip. The server handles a single action per
/// connection, so this dials fresh each time.
async fn call_with(addr: SocketAddr, key: &[u8], action: Action) -> Result<Response, AuthFailure> {
    let payload = auth::encode(&action).await.expect("encode failed");
    let request = auth::sign_request(key, payload);
    let nonce = request.nonce.clone();

    let mut client = RpcClient::<Request>::new(addr).await.expect("connect failed");
    let reply = client.call::<Reply>(request).await.expect("rpc call failed");

    let payload = auth::verify_reply(key, &nonce, &reply)?;
    Ok(auth::decode(payload).await.expect("decode failed"))
}

/// Send a request verbatim, bypassing the signing helpers, so replay and
/// tampering can be exercised.
async fn call_raw(addr: SocketAddr, request: Request) -> Reply {
    let mut client = RpcClient::<Request>::new(addr).await.expect("connect failed");
    client.call::<Reply>(request).await.expect("rpc call failed")
}

fn expect_err(resp: &Response, code: ErrorCode, what: &str) {
    match resp {
        Response::Error(e) if e.code == code => println!("OK   {what}: rejected as expected ({})", e.msg),
        other => panic!("FAIL {what}: expected {code:?} error, got {other:?}"),
    }
}

async fn open_session(addr: SocketAddr, resp: Response) -> (TcpStream, Option<u64>) {
    let Response::SessionOpened { port, token, size, .. } = resp else {
        panic!("expected SessionOpened, got {resp:?}");
    };
    let mut stream = TcpStream::connect((addr.ip(), port)).await.expect("session connect failed");
    stream.write_all(&token).await.expect("token send failed");
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await.expect("no handshake ack");
    assert_eq!(ack[0], 1, "bad handshake ack");
    (stream, size)
}

/// Read from a *pty* session until `needle` shows up, answering the
/// cursor-position reports ConPTY asks for along the way.
///
/// ConPTY probes the terminal it believes it is attached to with `ESC[6n` and
/// waits for a reply before getting on with things. The real client passes
/// that through to an actual console, which answers by itself; a bare socket
/// has to be told to.
async fn pty_read_until(stream: &mut TcpStream, needle: &str, secs: u64) -> String {
    const DSR: &[u8] = b"\x1b[6n";
    let mut collected = Vec::new();
    let mut answered = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut buf = [0u8; 4096];

    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                collected.extend_from_slice(&buf[..n]);

                let asked = collected.windows(DSR.len()).filter(|w| *w == DSR).count();
                while answered < asked {
                    let reply = term::data_frame(b"\x1b[1;1R");
                    if stream.write_all(&reply).await.is_err() {
                        break;
                    }
                    answered += 1;
                }

                if String::from_utf8_lossy(&collected).contains(needle) {
                    break;
                }
            }
        }
    }
    String::from_utf8_lossy(&collected).into_owned()
}

/// Read from the socket until `needle` shows up or `secs` elapse.
async fn read_until(stream: &mut TcpStream, needle: &str, secs: u64) -> String {
    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut buf = [0u8; 4096];
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                collected.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&collected).contains(needle) {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }
    String::from_utf8_lossy(&collected).into_owned()
}

/// The auth layer is the only thing standing between the network and full
/// control of the server, so every rejection path gets exercised.
async fn check_auth(addr: SocketAddr) {
    let wrong = auth::hash_or_random(Some("not-the-right-passphrase")).to_vec();
    match call_with(addr, &wrong, Action::Ping).await {
        Err(AuthFailure::BadKey) => println!("OK   auth: the wrong key is rejected"),
        other => panic!("FAIL auth: a wrong key was not rejected: {other:?}"),
    }

    // Replay: the very same signed bytes must not work twice.
    let payload = auth::encode(&Action::Ping).await.unwrap();
    let request = auth::sign_request(&key(), payload);
    let again = Request {
        nonce: request.nonce.clone(),
        timestamp_ms: request.timestamp_ms,
        mac: request.mac.clone(),
        payload: request.payload.clone(),
    };
    match call_raw(addr, request).await {
        Reply::Signed { .. } => {}
        other => panic!("FAIL auth: a valid request was rejected: {other:?}"),
    }
    match call_raw(addr, again).await {
        Reply::Rejected(AuthFailure::Replay) => println!("OK   auth: a replayed request is rejected"),
        other => panic!("FAIL auth: a replay was accepted: {other:?}"),
    }

    // Tampering: flipping a payload byte must break the MAC.
    let payload = auth::encode(&Action::Ping).await.unwrap();
    let mut tampered = auth::sign_request(&key(), payload);
    tampered.payload.push(0xff);
    match call_raw(addr, tampered).await {
        Reply::Rejected(AuthFailure::BadKey) => println!("OK   auth: a tampered payload is rejected"),
        other => panic!("FAIL auth: tampering was accepted: {other:?}"),
    }

    // Clock skew: a timestamp outside the window is refused even though the
    // MAC covers it and therefore still verifies.
    let payload = auth::encode(&Action::Ping).await.unwrap();
    let mut stale = auth::sign_request(&key(), payload);
    stale.timestamp_ms -= (auth::MAX_SKEW.as_millis() as u64) + 5_000;
    // Re-signed at the old timestamp: a captured-and-held request, not a
    // corrupted one, so the MAC itself is perfectly valid.
    stale.mac = auth::request_mac(&key(), &stale.nonce, stale.timestamp_ms, &stale.payload);
    match call_raw(addr, stale).await {
        Reply::Rejected(AuthFailure::Stale) => println!("OK   auth: a stale request is rejected"),
        other => panic!("FAIL auth: a stale request was accepted: {other:?}"),
    }

    // A reply must not verify against a nonce it was not signed for.
    let payload = auth::encode(&Action::Ping).await.unwrap();
    let request = auth::sign_request(&key(), payload);
    let reply = call_raw(addr, request).await;
    let mut other_nonce = vec![0u8; 16];
    other_nonce[0] = 1;
    match auth::verify_reply(&key(), &other_nonce, &reply) {
        Err(AuthFailure::BadKey) => println!("OK   auth: a reply will not verify against another nonce"),
        other => panic!("FAIL auth: reply verified against the wrong nonce: {other:?}"),
    }
}

struct StatFields {
    total_stg: u64,
    total_ram: u64,
    free_ram: u64,
    network_recv: u64,
    network_trans: u64,
    cpu_usage: f64,
}

async fn stat(addr: SocketAddr) -> StatFields {
    match call(addr, Action::Stat).await {
        Response::StatResponse {
            total_stg, total_ram, free_ram, network_recv, network_trans, cpu_usage, ..
        } => StatFields { total_stg, total_ram, free_ram, network_recv, network_trans, cpu_usage },
        other => panic!("expected StatResponse, got {other:?}"),
    }
}

async fn find_instance(addr: SocketAddr, name: &str) -> Option<(u128, RepoState, RunState)> {
    match call(addr, Action::ListInstances).await {
        Response::InstanceList(list) => list.into_iter()
            .find(|i| i.name == name)
            .map(|i| (i.id, i.repo, i.run)),
        other => panic!("expected InstanceList, got {other:?}"),
    }
}

async fn wait_repo_ready(addr: SocketAddr, id: u128) {
    for _ in 0..120 {
        match call(addr, Action::CheckInstance { id }).await {
            Response::InstanceStatus(st) => match st.repo {
                RepoState::Ready => return,
                RepoState::CloneFailed(e) => panic!("clone failed: {e}"),
                RepoState::Provisioning => tokio::time::sleep(Duration::from_millis(500)).await,
            },
            other => panic!("expected InstanceStatus, got {other:?}"),
        }
    }
    panic!("repo not ready after 60s");
}

const NAME: &str = "smoke-test";

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let addr = SocketAddr::from_str(&args.next().unwrap_or("127.0.0.1:5000".to_string()))
        .expect("bad server address");
    let phase2 = args.next().as_deref() == Some("phase2");

    if phase2 {
        run_phase2(addr).await;
    } else {
        run_full(addr).await;
    }
}

/// After a server restart: the autostart instance must be running again.
async fn run_phase2(addr: SocketAddr) {
    let (id, _repo, run) = find_instance(addr, NAME).await.expect("instance missing after restart");
    match run {
        RunState::Starting | RunState::Running { .. } => println!("OK   autostart: instance is running after restart"),
        other => panic!("FAIL autostart: expected running, got {other:?}"),
    }
    match call(addr, Action::StopInstance { id }).await {
        Response::Done => println!("OK   stop after restart"),
        other => panic!("stop failed: {other:?}"),
    }
    match call(addr, Action::RemoveInstance { id, delete_files: true }).await {
        Response::Done => println!("OK   remove: cleaned up"),
        other => panic!("remove failed: {other:?}"),
    }
    println!("\nphase2 passed");
}

async fn run_full(addr: SocketAddr) {
    // 0. Leftovers from a previous aborted run must not fail the name check.
    if let Some((id, _, _)) = find_instance(addr, NAME).await {
        let _ = call(addr, Action::StopInstance { id }).await;
        let _ = call(addr, Action::RemoveInstance { id, delete_files: true }).await;
        println!("info: removed leftover instance from a previous run");
    }

    match call(addr, Action::Ping).await {
        Response::Pong => println!("OK   ping"),
        other => panic!("expected Pong, got {other:?}"),
    }

    check_auth(addr).await;

    // Stat's sampled fields are easy to get subtly wrong: CPU needs two
    // refreshes of a persistent System, and the network counters must be
    // cumulative so clients can derive rates from consecutive polls.
    let first = stat(addr).await;
    assert!(first.total_ram > 0, "total_ram is zero");
    assert!(first.free_ram <= first.total_ram, "free_ram exceeds total_ram");
    assert!(first.total_stg > 0, "total_stg is zero");
    assert!(
        first.network_recv > 0,
        "network_recv is 0 — counters must be cumulative (total_received), not per-refresh deltas",
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    let second = stat(addr).await;
    assert!(
        second.network_recv >= first.network_recv && second.network_trans >= first.network_trans,
        "network counters went backwards: {:?} then {:?}",
        (first.network_recv, first.network_trans),
        (second.network_recv, second.network_trans),
    );
    assert!(
        (0.0..=100.0).contains(&second.cpu_usage),
        "cpu_usage {} is out of range",
        second.cpu_usage,
    );
    println!(
        "OK   stat (total_ram={}, cpu={:.1}%, net_recv={})",
        second.total_ram, second.cpu_usage, second.network_recv,
    );

    // 1. Create: a tiny public repo; the command is an interactive cmd.exe so
    //    we can exercise the attach terminal.
    let id = match call(addr, Action::CreateInstance {
        name: NAME.to_string(),
        repo_url: "https://github.com/octocat/Hello-World".to_string(),
        branch: None,
        command: "cmd.exe".to_string(),
        args: vec!["/q".to_string(), "/k".to_string(), "echo instance-started".to_string()],
        env: HashMap::from([("SMOKE_MARKER".to_string(), "1".to_string())]),
        autostart: false,
        retry_policy: RetryPolicy::Never,
    }).await {
        Response::InstanceCreated { id } => { println!("OK   create (id={id:032x})"); id }
        other => panic!("create failed: {other:?}"),
    };

    // Duplicate names must be rejected.
    let dup = call(addr, Action::CreateInstance {
        name: NAME.to_string(),
        repo_url: "https://example.invalid/x".to_string(),
        branch: None,
        command: "x".to_string(),
        args: vec![],
        env: HashMap::new(),
        autostart: false,
        retry_policy: RetryPolicy::Never,
    }).await;
    expect_err(&dup, ErrorCode::Conflict, "duplicate name");

    // Running before the clone finished must be rejected (or the clone was
    // fast — then skip this check).
    match call(addr, Action::RunInstance { id }).await {
        Response::Error(e) if e.code == ErrorCode::Provisioning => {
            println!("OK   run-while-provisioning: rejected as expected");
        }
        Response::Done => {
            println!("info: clone won the race; stopping again");
            let _ = call(addr, Action::StopInstance { id }).await;
        }
        other => panic!("unexpected: {other:?}"),
    }

    wait_repo_ready(addr, id).await;
    println!("OK   clone finished");

    // 2. Run + check.
    match call(addr, Action::RunInstance { id }).await {
        Response::Done => println!("OK   run"),
        other => panic!("run failed: {other:?}"),
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    match call(addr, Action::CheckInstance { id }).await {
        Response::InstanceStatus(st) => match st.run {
            RunState::Running { ref pids, .. } => println!("OK   check: running (pids={pids:?}, stats={:?})", st.stats),
            other => panic!("expected Running, got {other:?}"),
        },
        other => panic!("check failed: {other:?}"),
    }
    expect_err(&call(addr, Action::RunInstance { id }).await, ErrorCode::AlreadyRunning, "double run");
    expect_err(&call(addr, Action::UpdateRepo { id }).await, ErrorCode::Conflict, "update-repo while running");

    // 2b. The console captures output with nobody attached: the instance
    //     echoes a marker at startup and we have not opened a terminal yet.
    match call(addr, Action::TailConsole { id, lines: 200 }).await {
        Response::Console { lines, dropped } => {
            let text = lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>().join("\n");
            assert!(text.contains("instance-started"), "console missed the startup output:\n{text}");
            assert!(text.contains("── started ──"), "console missed the start marker:\n{text}");
            assert_eq!(dropped, 0, "nothing should have been dropped yet");
            assert!(lines.iter().all(|l| l.at_ms > 0), "console lines carry no timestamp");
            println!("OK   console captured {} lines with nobody attached", lines.len());
        }
        other => panic!("tail-console failed: {other:?}"),
    }

    // The tail is a tail: asking for fewer lines returns the newest ones and
    // reports the rest as not shown.
    match call(addr, Action::TailConsole { id, lines: 1 }).await {
        Response::Console { lines, dropped } => {
            assert_eq!(lines.len(), 1, "expected exactly one line");
            assert!(dropped >= 1, "older lines should be reported as not shown");
            println!("OK   console tail is bounded (dropped={dropped})");
        }
        other => panic!("tail-console failed: {other:?}"),
    }

    // 3. Attach terminal.
    let resp = call(addr, Action::OpenTerminal { mode: TerminalMode::Attach(id) }).await;
    let (mut term, _) = open_session(addr, resp).await;
    term.write_all(b"echo from-attach-terminal\r\n").await.unwrap();
    let out = read_until(&mut term, "from-attach-terminal", 10).await;
    assert!(out.contains("from-attach-terminal"), "attach terminal produced: {out:?}");
    println!("OK   attach terminal (echo round-trip)");
    drop(term);

    // 4. Shell terminal: a real pty, independent of the instance process.
    let resp = call(addr, Action::OpenTerminal {
        mode: TerminalMode::Shell { id, cols: 80, rows: 24 },
    }).await;
    let (mut shell, _) = open_session(addr, resp).await;

    // A pty echoes what you type, so asserting on the command text would pass
    // even if nothing ran. Assert on a result the input does not contain.
    shell.write_all(&term::data_frame(b"set /a 21*2\r\n")).await.unwrap();
    let out = pty_read_until(&mut shell, "42", 10).await;
    assert!(out.contains("42"), "shell did not evaluate the expression: {out:?}");
    assert!(
        out.contains("set /a 21*2"),
        "a pty must echo the typed command back; got {out:?}",
    );
    println!("OK   shell terminal (pty runs commands and echoes)");

    // Resize must reach the pty: ask the shell how wide it thinks it is.
    // Matching the number, not a label — `mode con` output is localized.
    shell.write_all(&term::resize_frame(120, 40)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    shell.write_all(&term::data_frame(b"mode con\r\n")).await.unwrap();
    let out = pty_read_until(&mut shell, "120", 10).await;
    assert!(out.contains("120"), "resize did not reach the pty; `mode con` said: {out:?}");
    println!("OK   shell terminal (resize reaches the pty)");

    // Typing `exit` ends the session, exactly as in a normal terminal.
    shell.write_all(&term::data_frame(b"exit\r\n")).await.unwrap();
    let mut sink = [0u8; 1024];
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match shell.read(&mut sink).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    }).await;
    assert!(closed.is_ok(), "the session did not close after `exit`");
    println!("OK   shell terminal (`exit` closes the session)");
    drop(shell);

    // 5. A wrong session token must be dropped without an ack.
    let resp = call(addr, Action::OpenTerminal {
        mode: TerminalMode::Shell { id, cols: 80, rows: 24 },
    }).await;
    let Response::SessionOpened { port, .. } = resp else { panic!("expected SessionOpened") };
    let mut bad = TcpStream::connect((addr.ip(), port)).await.unwrap();
    bad.write_all(&[0u8; 32]).await.unwrap();
    let mut ack = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(3), bad.read(&mut ack)).await {
        Ok(Ok(0)) => println!("OK   wrong token: connection dropped"),
        Err(_) => println!("OK   wrong token: no ack within timeout"),
        other => panic!("wrong token was not rejected: {other:?}"),
    }

    // 6. File transfer: upload into the instances jail, download, compare.
    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let dest = PathBuf::from(format!("instances/{id:032x}/repo/smoke-upload.bin"));

    let resp = call(addr, Action::UploadFile { dest: dest.clone() }).await;
    let (mut up, _) = open_session(addr, resp).await;
    up.write_all(&(payload.len() as u64).to_be_bytes()).await.unwrap();
    up.write_all(&payload).await.unwrap();
    let mut ack = [0u8; 1];
    up.read_exact(&mut ack).await.expect("no upload commit ack");
    assert_eq!(ack[0], 1);
    println!("OK   upload ({} bytes committed)", payload.len());

    let resp = call(addr, Action::DownloadFile { src: dest.clone() }).await;
    let (mut down, size) = open_session(addr, resp).await;
    assert_eq!(size, Some(payload.len() as u64), "download size mismatch in response");
    let mut len_buf = [0u8; 8];
    down.read_exact(&mut len_buf).await.unwrap();
    assert_eq!(u64::from_be_bytes(len_buf), payload.len() as u64);
    let mut got = vec![0u8; payload.len()];
    down.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload, "downloaded bytes differ");
    println!("OK   download (round-trip matches)");

    // 6b. Directory listing must see the file we just uploaded, and must obey
    //     the same jail as transfers.
    let repo_rel = PathBuf::from(format!("instances/{id:032x}/repo"));
    match call(addr, Action::ListDir { path: repo_rel.clone() }).await {
        Response::DirListing { entries, .. } => {
            let up = entries.iter().find(|e| e.name == "smoke-upload.bin")
                .expect("uploaded file missing from listing");
            assert!(!up.is_dir, "uploaded file listed as a directory");
            assert_eq!(up.size, payload.len() as u64, "listed size mismatch");
            assert!(entries.iter().any(|e| e.is_dir && e.name == ".git"), "expected a .git dir in the listing");
            // Directories sort before files.
            let first_file = entries.iter().position(|e| !e.is_dir).unwrap_or(entries.len());
            assert!(entries[first_file..].iter().all(|e| !e.is_dir), "dirs must sort before files");
            println!("OK   list-dir ({} entries)", entries.len());
        }
        other => panic!("list-dir failed: {other:?}"),
    }
    expect_err(
        &call(addr, Action::ListDir { path: PathBuf::from("C:\\Windows") }).await,
        ErrorCode::AccessDenied, "list-dir out-of-root",
    );

    // The instance's own repo_dir must round-trip: the client roots its file
    // browser at the absolute path from CheckInstance.
    match call(addr, Action::CheckInstance { id }).await {
        Response::InstanceStatus(st) => {
            match call(addr, Action::ListDir { path: st.repo_dir.clone() }).await {
                Response::DirListing { .. } => println!("OK   list-dir via absolute repo_dir"),
                other => panic!("listing repo_dir {:?} failed: {other:?}", st.repo_dir),
            }
        }
        other => panic!("check failed: {other:?}"),
    }

    // Path jail: escapes and out-of-root paths must be rejected.
    expect_err(
        &call(addr, Action::DownloadFile { src: PathBuf::from("instances/../../secret.txt") }).await,
        ErrorCode::AccessDenied, "path traversal",
    );
    expect_err(
        &call(addr, Action::DownloadFile { src: PathBuf::from("C:\\Windows\\win.ini") }).await,
        ErrorCode::AccessDenied, "out-of-root absolute path",
    );

    // 6c. Archive transfer: upload a small tree as tar.gz, expect it unpacked
    //     server-side; download it back together with the earlier upload.
    let tree = std::env::temp_dir().join(format!("smoke-tree-{:08x}", rand::random::<u32>()));
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("a.txt"), b"alpha").unwrap();
    std::fs::write(tree.join("sub").join("b.txt"), b"beta").unwrap();

    let mut tarball = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut tarball, flate2::Compression::default());
        let mut tar = tar::Builder::new(enc);
        tar.append_dir_all("smoke-tree", &tree).unwrap();
        tar.into_inner().unwrap().finish().unwrap();
    }

    let dest_dir = PathBuf::from(format!("instances/{id:032x}/repo"));
    let resp = call(addr, Action::UploadArchive { dest: dest_dir.clone() }).await;
    let (mut up, _) = open_session(addr, resp).await;
    up.write_all(&(tarball.len() as u64).to_be_bytes()).await.unwrap();
    up.write_all(&tarball).await.unwrap();
    let mut ack = [0u8; 1];
    up.read_exact(&mut ack).await.expect("no unpack ack");
    assert_eq!(ack[0], 1);
    match call(addr, Action::ListDir { path: dest_dir.join("smoke-tree") }).await {
        Response::DirListing { entries, .. } => {
            assert!(entries.iter().any(|e| e.name == "a.txt" && !e.is_dir), "a.txt missing after unpack");
            assert!(entries.iter().any(|e| e.name == "sub" && e.is_dir), "sub/ missing after unpack");
        }
        other => panic!("unpacked tree not listable: {other:?}"),
    }
    println!("OK   archive upload (unpacked server-side)");

    let resp = call(addr, Action::DownloadArchive { paths: vec![
        dest_dir.join("smoke-tree"),
        dest_dir.join("smoke-upload.bin"),
    ] }).await;
    let (mut down, _) = open_session(addr, resp).await;
    let mut len_buf = [0u8; 8];
    down.read_exact(&mut len_buf).await.expect("no archive length");
    let mut archive = vec![0u8; u64::from_be_bytes(len_buf) as usize];
    down.read_exact(&mut archive).await.expect("archive cut short");

    let unpacked = std::env::temp_dir().join(format!("smoke-unpack-{:08x}", rand::random::<u32>()));
    tar::Archive::new(flate2::read::GzDecoder::new(&archive[..])).unpack(&unpacked).unwrap();
    assert_eq!(std::fs::read(unpacked.join("smoke-tree").join("a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(unpacked.join("smoke-tree").join("sub").join("b.txt")).unwrap(), b"beta");
    assert_eq!(std::fs::read(unpacked.join("smoke-upload.bin")).unwrap(), payload);
    println!("OK   archive download (round-trip matches)");

    expect_err(
        &call(addr, Action::DownloadArchive { paths: vec![PathBuf::from("C:\\Windows")] }).await,
        ErrorCode::AccessDenied, "archive out-of-root",
    );
    let _ = std::fs::remove_dir_all(&tree);
    let _ = std::fs::remove_dir_all(&unpacked);

    // 7. Update config + repo, then autostart prep for phase2.
    match call(addr, Action::StopInstance { id }).await {
        Response::Done => println!("OK   stop"),
        other => panic!("stop failed: {other:?}"),
    }
    match call(addr, Action::CheckInstance { id }).await {
        Response::InstanceStatus(st) => match st.run {
            RunState::Stopped => println!("OK   check: stopped"),
            other => panic!("expected Stopped, got {other:?}"),
        },
        other => panic!("check failed: {other:?}"),
    }
    expect_err(&call(addr, Action::KillInstance { id }).await, ErrorCode::NotRunning, "kill while stopped");

    match call(addr, Action::UpdateRepo { id }).await {
        Response::Done => println!("OK   update-repo accepted"),
        other => panic!("update-repo failed: {other:?}"),
    }
    wait_repo_ready(addr, id).await;
    println!("OK   update-repo finished");

    match call(addr, Action::UpdateInstance {
        id,
        name: None,
        repo_url: None,
        branch: None,
        command: None,
        args: None,
        env: None,
        autostart: Some(true),
        retry_policy: None,
    }).await {
        Response::Done => println!("OK   update-instance (autostart=true)"),
        other => panic!("update-instance failed: {other:?}"),
    }
    match call(addr, Action::RunInstance { id }).await {
        Response::Done => println!("OK   run again"),
        other => panic!("re-run failed: {other:?}"),
    }

    println!("\nfull flow passed — now restart the server and run: smoke {addr} phase2");
}
