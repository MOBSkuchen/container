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
use server::api::{Action, ErrorCode, Response, TerminalMode};
use server::manager::{RepoState, RetryPolicy, RunState};

async fn call(addr: SocketAddr, action: Action) -> Response {
    // The server handles one action per connection, so dial fresh each time.
    let mut client = RpcClient::<Action>::new(addr).await.expect("connect failed");
    client.call::<Response>(action).await.expect("rpc call failed")
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

    match call(addr, Action::Stat).await {
        Response::StatResponse { total_ram, .. } => println!("OK   stat (total_ram={total_ram})"),
        other => panic!("expected StatResponse, got {other:?}"),
    }

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

    // 3. Attach terminal.
    let resp = call(addr, Action::OpenTerminal { mode: TerminalMode::Attach(id) }).await;
    let (mut term, _) = open_session(addr, resp).await;
    term.write_all(b"echo from-attach-terminal\r\n").await.unwrap();
    let out = read_until(&mut term, "from-attach-terminal", 10).await;
    assert!(out.contains("from-attach-terminal"), "attach terminal produced: {out:?}");
    println!("OK   attach terminal (echo round-trip)");
    drop(term);

    // 4. Shell terminal (independent of the instance process).
    let resp = call(addr, Action::OpenTerminal { mode: TerminalMode::Shell(id) }).await;
    let (mut shell, _) = open_session(addr, resp).await;
    shell.write_all(b"echo from-shell-terminal\r\n").await.unwrap();
    let out = read_until(&mut shell, "from-shell-terminal", 10).await;
    assert!(out.contains("from-shell-terminal"), "shell terminal produced: {out:?}");
    shell.write_all(b"exit\r\n").await.unwrap();
    println!("OK   shell terminal (echo round-trip)");
    drop(shell);

    // 5. A wrong session token must be dropped without an ack.
    let resp = call(addr, Action::OpenTerminal { mode: TerminalMode::Shell(id) }).await;
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

    // Path jail: escapes and out-of-root paths must be rejected.
    expect_err(
        &call(addr, Action::DownloadFile { src: PathBuf::from("instances/../../secret.txt") }).await,
        ErrorCode::AccessDenied, "path traversal",
    );
    expect_err(
        &call(addr, Action::DownloadFile { src: PathBuf::from("C:\\Windows\\win.ini") }).await,
        ErrorCode::AccessDenied, "out-of-root absolute path",
    );

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
