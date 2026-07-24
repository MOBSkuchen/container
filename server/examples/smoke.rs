//! Test-only RPC client that drives the server end-to-end.
//!
//! Usage:
//!   cargo run --example smoke -- <server-addr>            # full flow
//!   cargo run --example smoke -- <server-addr> phase2     # after a server
//!       restart: verify the instance came back via autostart, then clean up.
//!   cargo run --example smoke -- <server-addr> bootstrap  # handover flow;
//!       leaves a detached server running (its pid is printed).
//!
//! Not the real client product — just enough to exercise every Action.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use bierpc::rpc::RpcClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use protocol::{auth, term};
use protocol::{AuthFailure, Reply, Request};
use server::api::{Action, ErrorCode, Response, TerminalMode};
use server::manager::{RepoState, RetryPolicy, RunState, Source};

/// The shared key both ends are set up with; see `main`.
const PHRASE: &str = "smoke-test-passphrase";

fn key() -> Vec<u8> {
    auth::hash_or_random(Some(PHRASE)).to_vec()
}

async fn call(addr: SocketAddr, action: Action) -> Response {
    call_with(addr, &key(), action).await.expect("rpc call failed")
}

/// One authenticated round trip. Dials fresh each time: connections are
/// reusable now, but a fresh dial keeps every call independent of the last
/// test's failure mode.
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
    match args.next().as_deref() {
        Some("phase2") => run_phase2(addr).await,
        Some("bootstrap") => run_bootstrap(addr).await,
        _ => run_full(addr).await,
    }
}

/// A call that tolerates the server being mid-handover.
async fn try_call(addr: SocketAddr, action: Action) -> Option<Response> {
    let payload = auth::encode(&action).await.ok()?;
    let request = auth::sign_request(&key(), payload);
    let nonce = request.nonce.clone();
    let mut client = RpcClient::<Request>::new(addr).await.ok()?;
    let reply = client.call::<Reply>(request).await.ok()?;
    let payload = auth::verify_reply(&key(), &nonce, &reply).ok()?;
    auth::decode::<Response>(payload).await.ok()
}

async fn try_ping(addr: SocketAddr) -> bool {
    matches!(try_call(addr, Action::Ping).await, Some(Response::Pong))
}

async fn stat_bootstrap(addr: SocketAddr) -> bool {
    match call(addr, Action::Stat).await {
        Response::StatResponse { bootstrap, .. } => bootstrap,
        other => panic!("expected StatResponse, got {other:?}"),
    }
}

/// Bootstrap handover: the server replaces itself with a self-managed copy.
/// Leaves a detached server running; its pid is printed for cleanup.
async fn run_bootstrap(addr: SocketAddr) {
    assert!(stat_bootstrap(addr).await, "bootstrap is not advertised as available");
    match call(addr, Action::Bootstrap).await {
        Response::Done => println!("OK   bootstrap accepted"),
        other => panic!("bootstrap failed: {other:?}"),
    }

    // The old process drains and exits; the replacement takes the port over.
    let mut up = false;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if try_ping(addr).await {
            up = true;
            break;
        }
    }
    assert!(up, "the replacement server did not come up within 30s");
    println!("OK   replacement server is answering");

    let list = match call(addr, Action::ListInstances).await {
        Response::InstanceList(list) => list,
        other => panic!("expected InstanceList, got {other:?}"),
    };
    let me = list.iter().find(|i| i.self_managed).expect("no self-managed instance listed");
    let RunState::Running { ref pids, .. } = me.run else {
        panic!("self instance is not running: {:?}", me.run);
    };
    println!("OK   self instance '{}' listed as running (pid {})", me.name, pids[0]);

    assert!(!stat_bootstrap(addr).await, "bootstrap still advertised after the handover");
    println!("OK   bootstrap no longer advertised");

    expect_err(&call(addr, Action::StopInstance { id: me.id }).await, ErrorCode::Conflict, "stop the self instance");
    expect_err(&call(addr, Action::KillInstance { id: me.id }).await, ErrorCode::Conflict, "kill the self instance");
    expect_err(&call(addr, Action::UpdateRepo { id: me.id }).await, ErrorCode::Conflict, "update-repo on the self instance");
    expect_err(
        &call(addr, Action::OpenTerminal { mode: TerminalMode::Attach(me.id) }).await,
        ErrorCode::Conflict, "attach to the self instance",
    );
    expect_err(&call(addr, Action::Bootstrap).await, ErrorCode::Conflict, "double bootstrap");

    match call(addr, Action::CheckInstance { id: me.id }).await {
        Response::InstanceStatus(st) => {
            assert!(st.config.self_managed, "check lost the self flag");
            assert!(st.repo_dir.is_absolute(), "self repo_dir is not absolute");
            println!("OK   check on the self instance (dir {})", st.repo_dir.display());
        }
        other => panic!("check failed: {other:?}"),
    }

    // Restarting the self instance replaces the whole server.
    let (self_id, old_pid) = (me.id, pids[0]);
    match call(addr, Action::RestartInstance { id: self_id }).await {
        Response::Done => {}
        other => panic!("self restart failed: {other:?}"),
    }
    let mut new_pid = None;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(Response::InstanceList(list)) = try_call(addr, Action::ListInstances).await
            && let Some(me) = list.iter().find(|i| i.self_managed)
            && let RunState::Running { ref pids, .. } = me.run
            && let Some(pid) = pids.first().copied()
            && pid != old_pid {
            new_pid = Some(pid);
            break;
        }
    }
    let new_pid = new_pid.expect("no replacement server with a fresh pid within 30s");
    println!("OK   restart of the self instance replaced the server (pid {old_pid} → {new_pid})");

    // Un-bootstrap: the entry is removable, and the offer comes back.
    match call(addr, Action::RemoveInstance { id: self_id, delete_files: false }).await {
        Response::Done => println!("OK   self instance removed (un-bootstrap)"),
        other => panic!("remove failed: {other:?}"),
    }
    assert!(stat_bootstrap(addr).await, "bootstrap not advertised again after un-bootstrap");
    println!("OK   bootstrap advertised again");

    println!("\nbootstrap flow passed — the detached server (pid {new_pid}) is still running");
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
        source: Source::Git { url: "https://github.com/octocat/Hello-World".to_string(), branch: None },
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
        source: Source::Git { url: "https://example.invalid/x".to_string(), branch: None },
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
            // The marker names the resolved executable, so "which binary ran"
            // is answerable from the console alone.
            assert!(text.contains("── started `"), "console missed the start marker:\n{text}");
            assert!(text.to_lowercase().contains("cmd.exe`"), "start marker lacks the resolved path:\n{text}");
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

    // 4b. Restart: same instance, fresh process.
    let old_pid = match call(addr, Action::CheckInstance { id }).await {
        Response::InstanceStatus(st) => match st.run {
            RunState::Running { ref pids, .. } => pids.first().copied(),
            other => panic!("expected Running before restart, got {other:?}"),
        },
        other => panic!("check failed: {other:?}"),
    };
    match call(addr, Action::RestartInstance { id }).await {
        Response::Done => {}
        other => panic!("restart failed: {other:?}"),
    }
    let mut new_pid = None;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Response::InstanceStatus(st) = call(addr, Action::CheckInstance { id }).await
            && let RunState::Running { pids, .. } = st.run
            && let Some(pid) = pids.first().copied()
            && Some(pid) != old_pid {
            new_pid = Some(pid);
            break;
        }
    }
    let new_pid = new_pid.expect("instance did not come back with a new pid after restart");
    println!("OK   restart (pid {} → {new_pid})", old_pid.unwrap_or(0));

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

    // 6d. Alternate sources: a URL download, and content pushed by the client.
    let url_id = match call(addr, Action::CreateInstance {
        name: "smoke-url".to_string(),
        source: Source::Url {
            url: "https://raw.githubusercontent.com/octocat/Hello-World/master/README".to_string(),
        },
        command: "cmd.exe".to_string(),
        args: vec!["/c".to_string(), "type".to_string(), "README".to_string()],
        env: HashMap::new(),
        autostart: false,
        retry_policy: RetryPolicy::Never,
    }).await {
        Response::InstanceCreated { id } => id,
        other => panic!("url create failed: {other:?}"),
    };
    wait_repo_ready(addr, url_id).await;
    match call(addr, Action::ListDir { path: PathBuf::from(format!("instances/{url_id:032x}/repo")) }).await {
        Response::DirListing { entries, .. } => {
            assert!(entries.iter().any(|e| e.name == "README" && !e.is_dir), "downloaded file missing");
        }
        other => panic!("url repo not listable: {other:?}"),
    }
    println!("OK   url source (plain file downloaded)");
    match call(addr, Action::RemoveInstance { id: url_id, delete_files: true }).await {
        Response::Done => {}
        other => panic!("url cleanup failed: {other:?}"),
    }

    let up_id = match call(addr, Action::CreateInstance {
        name: "smoke-uploaded".to_string(),
        source: Source::Upload { desc: "smoke-tree".to_string() },
        command: "cmd.exe".to_string(),
        args: vec!["/c".to_string(), "dir".to_string()],
        env: HashMap::new(),
        autostart: false,
        retry_policy: RetryPolicy::Never,
    }).await {
        Response::InstanceCreated { id } => id,
        other => panic!("upload create failed: {other:?}"),
    };
    expect_err(&call(addr, Action::RunInstance { id: up_id }).await,
        ErrorCode::Provisioning, "run before the content arrived");
    expect_err(&call(addr, Action::UpdateRepo { id: up_id }).await,
        ErrorCode::Conflict, "update-repo on an upload source");

    let resp = call(addr, Action::UploadSource { id: up_id }).await;
    let (mut push, _) = open_session(addr, resp).await;
    push.write_all(&(tarball.len() as u64).to_be_bytes()).await.unwrap();
    push.write_all(&tarball).await.unwrap();
    let mut ack = [0u8; 1];
    push.read_exact(&mut ack).await.expect("no source unpack ack");
    assert_eq!(ack[0], 1);
    wait_repo_ready(addr, up_id).await;
    match call(addr, Action::ListDir {
        path: PathBuf::from(format!("instances/{up_id:032x}/repo/smoke-tree")),
    }).await {
        Response::DirListing { entries, .. } => {
            assert!(entries.iter().any(|e| e.name == "a.txt"), "pushed content missing");
        }
        other => panic!("pushed content not listable: {other:?}"),
    }
    println!("OK   upload source (content pushed and ready)");
    match call(addr, Action::RemoveInstance { id: up_id, delete_files: true }).await {
        Response::Done => {}
        other => panic!("upload cleanup failed: {other:?}"),
    }

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
        source: None,
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
