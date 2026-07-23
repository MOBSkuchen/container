//! Headless driver for the landing page.
//!
//! Renders the real UI to a `TestBackend` and drives the real state machine
//! with synthetic keys, against a *live* server — so it covers the polling
//! path, not just the drawing.
//!
//! Usage: cargo run -p client --example tui_smoke -- <server-addr>
//!
//! Not a product surface: it exists so the TUI can be verified without a
//! human at a terminal.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Notify};

use client::app::{App, AppEvent, Row, Screen, spawn_poller};
use client::book::Book;
use client::net::{Endpoint, NetError};
use client::target;
use client::terminal as terminal_mod;
use protocol::{auth, term};
use protocol::{Action, ErrorCode, RepoState, Response, RetryPolicy, RunState, Source, TerminalMode};

const INSTANCE: &str = "tui-smoke";
/// Must match the phrase the test server was created with.
const PHRASE: &str = "smoke-test-passphrase";

fn key_bytes() -> Vec<u8> {
    auth::hash_or_random(Some(PHRASE)).to_vec()
}

fn endpoint(addr: SocketAddr) -> Endpoint {
    Endpoint::new(addr, key_bytes())
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    }
}

fn typed(app: &mut App, text: &str) {
    for c in text.chars() {
        app.on_key(key(KeyCode::Char(c)));
    }
}

/// The rendered screen as plain text, one String per row.
fn screen(terminal: &Terminal<TestBackend>) -> Vec<String> {
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect()
}

fn dump(label: &str, terminal: &Terminal<TestBackend>) {
    println!("\n--- {label} {}", "-".repeat(60usize.saturating_sub(label.len())));
    for line in screen(terminal) {
        println!("|{line}");
    }
}

fn assert_shows(terminal: &Terminal<TestBackend>, needle: &str, what: &str) {
    let text = screen(terminal).join("\n");
    assert!(text.contains(needle), "FAIL {what}: no '{needle}' on screen:\n{text}");
    println!("OK   {what}");
}

fn assert_hides(terminal: &Terminal<TestBackend>, needle: &str, what: &str) {
    let text = screen(terminal).join("\n");
    assert!(!text.contains(needle), "FAIL {what}: '{needle}' still on screen:\n{text}");
    println!("OK   {what}");
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from_str(
        &std::env::args().nth(1).unwrap_or("127.0.0.1:5000".to_string())
    ).expect("bad server address");

    // An instance so the tree has a child row. Provisioning is enough — we
    // never wait for the clone.
    let id = create_instance(addr).await;

    let dir = std::env::temp_dir().join(format!("container-tui-smoke-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("servers.chld");

    // The book starts with the key but no servers: the driver adds those
    // through the UI, and a keyless client could not poll anything.
    let book = Book { key: key_bytes(), servers: Vec::new() };
    let (book_tx, book_rx) = watch::channel(book.clone());
    let (events_tx, mut events_rx) = mpsc::channel(64);
    let refresh = Arc::new(Notify::new());
    spawn_poller(book_rx, events_tx.clone(), refresh.clone());

    // Tall enough that the detail pane and console both get room.
    let mut terminal = Terminal::new(TestBackend::new(110, 30)).unwrap();
    let mut app = App::new(book, config_path.clone(), book_tx, refresh, events_tx);

    // 1. First run: an empty book must say so rather than render nothing.
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    dump("empty book", &terminal);
    assert_shows(&terminal, "No servers yet.", "empty state");

    // 2. Add the live server through the form, exactly as a user would.
    app.on_key(key(KeyCode::Char('a')));
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    assert_shows(&terminal, "Add server", "add-server form opens");

    typed(&mut app, "smoke-box");
    app.on_key(key(KeyCode::Tab));
    // The address field is pre-filled; clear it first.
    for _ in 0..40 {
        app.on_key(key(KeyCode::Backspace));
    }
    typed(&mut app, &addr.to_string());
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    dump("filled form", &terminal);

    app.on_key(key(KeyCode::Enter));
    assert_eq!(app.book.servers.len(), 1, "server was not added");
    println!("OK   server added");

    // 3. A bad address must be rejected in the form, not saved.
    app.on_key(key(KeyCode::Char('a')));
    typed(&mut app, "bogus");
    app.on_key(key(KeyCode::Tab));
    for _ in 0..40 {
        app.on_key(key(KeyCode::Backspace));
    }
    typed(&mut app, "not-an-address");
    app.on_key(key(KeyCode::Enter));
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    assert_shows(&terminal, "is not a host:port address", "bad address rejected");
    assert_eq!(app.book.servers.len(), 1, "invalid server was saved anyway");
    app.on_key(key(KeyCode::Esc));

    // 4. Wait for the poller to bring back real data from the live server.
    let snapshot = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let event = events_rx.recv().await.expect("event channel closed");
            let is_snapshot = matches!(&event, AppEvent::Snapshot { .. });
            app.on_event(event);
            if is_snapshot {
                return;
            }
        }
    }).await;
    snapshot.expect("no snapshot from the poller within 15s");

    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    dump("live snapshot", &terminal);
    assert_shows(&terminal, "smoke-box", "server row");
    assert_shows(&terminal, "cpu", "vitals summary");
    assert_shows(&terminal, INSTANCE, "instance row");
    assert_shows(&terminal, "1/1 servers up", "header counts the server as up");

    // 5. Collapsing must hide the instance rows; expanding brings them back.
    //    The server may host instances other tests left behind, so this
    //    asserts on the tree's shape rather than on an exact row count.
    assert!(app.rows().len() >= 2, "expected a server row plus at least one instance row");
    app.on_key(key(KeyCode::Enter));
    assert_eq!(app.rows().len(), 1, "collapsing left instance rows behind");
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    assert_hides(&terminal, INSTANCE, "collapse hides instances");
    app.on_key(key(KeyCode::Enter));
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    assert_shows(&terminal, INSTANCE, "expand shows instances again");

    // 6. Cursor must not run off either end of the tree.
    let last = app.rows().len() - 1;
    for _ in 0..20 {
        app.on_key(key(KeyCode::Down));
    }
    assert_eq!(app.cursor, last, "cursor ran past the last row");
    for _ in 0..20 {
        app.on_key(key(KeyCode::Up));
    }
    assert_eq!(app.cursor, 0, "cursor ran past the first row");
    println!("OK   cursor clamped at both ends");

    // 7. Help overlay.
    app.on_key(key(KeyCode::Char('?')));
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    dump("help", &terminal);
    assert_shows(&terminal, "poll every server now", "help overlay");
    app.on_key(key(KeyCode::Esc));
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    assert_hides(&terminal, "poll every server now", "help closes");

    // 8. The book must have been persisted along the way.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let saved = client::book::load(&config_path).await.expect("re-reading the book failed");
    assert_eq!(saved.servers.len(), 1, "book not persisted");
    assert_eq!(saved.servers[0].addr, addr, "persisted address differs");
    assert_eq!(saved.key, key_bytes(), "the auth key did not survive the round trip");
    assert!(
        saved.key_for(&saved.servers[0]).is_some(),
        "the saved server resolves to no key",
    );
    println!("OK   server book round-trips through disk, key included");

    // 9. The manage screen, once the clone has landed.
    wait_repo_ready(addr, id).await;
    pump(&mut app, &mut events_rx, Duration::from_secs(5)).await;

    app.cursor = instance_row(&app);
    app.on_key(key(KeyCode::Enter));
    settle(&mut app, &mut events_rx).await;
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    dump("manage", &terminal);
    assert_shows(&terminal, "cpu", "server vitals in the sidebar");
    assert_shows(&terminal, "Hello-World", "repo url in the detail pane");
    assert_shows(&terminal, "client shell smoke-box/tui-smoke", "shell command hint");
    assert_shows(&terminal, "client attach smoke-box/tui-smoke", "attach command hint");
    assert_shows(&terminal, "not running", "run state");

    // 10. Start it from the TUI and watch the detail pane catch up.
    app.on_key(key(KeyCode::Char('r')));
    wait_run_state(&mut app, &mut events_rx, "running", 20).await;
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    dump("running", &terminal);
    assert_shows(&terminal, "▶ running", "instance reports running");
    assert_shows(&terminal, "pids", "pids listed while running");

    // 11. Terminals: sessions open through the client's own code path, and
    //     ending one must leave the instance alone.
    let resolved = target::resolve(&app.book, "smoke-box/tui-smoke").await
        .expect("resolving server/instance failed");
    assert_eq!(resolved.instance.id, id, "resolved the wrong instance");
    let bare = target::resolve(&app.book, "tui-smoke").await
        .expect("resolving a bare instance name failed");
    assert_eq!(bare.instance.id, id, "bare name resolved to the wrong instance");
    println!("OK   target resolution (qualified and bare)");

    let mut attach = terminal_mod::open_session(&endpoint(addr), TerminalMode::Attach(id)).await
        .expect("opening an attach session failed");
    attach.write_all(b"echo from-attach\r\n").await.unwrap();
    let out = read_until(&mut attach, "from-attach", 10).await;
    assert!(out.contains("from-attach"), "attach session produced: {out:?}");
    println!("OK   attach session round-trip");

    // Ctrl+C in the real client just drops the socket. The instance must
    // survive that — this is the whole point of the terminal rework.
    drop(attach);
    tokio::time::sleep(Duration::from_secs(1)).await;
    match client::net::check(&endpoint(addr), id).await.expect("check after detach failed").run {
        RunState::Running { .. } => println!("OK   detaching leaves the instance running"),
        other => panic!("FAIL detach killed the instance: {other:?}"),
    }

    // The shell session is a pty and is framed, unlike attach. It echoes, so
    // the assertion is on a result the input does not contain.
    let (cols, rows) = terminal_mod::window_size();
    let mut shell = terminal_mod::open_session(
        &endpoint(addr),
        TerminalMode::Shell { id, cols, rows },
    ).await.expect("opening a shell session failed");
    shell.write_all(&term::data_frame(b"set /a 21*2\r\n")).await.unwrap();
    let out = pty_read_until(&mut shell, "42", 10).await;
    assert!(out.contains("42"), "shell did not evaluate the expression: {out:?}");
    drop(shell);
    println!("OK   shell session round-trip (pty)");

    // 11b. The console panel shows what the instance printed, without any
    //      terminal being attached to collect it.
    wait_console(&mut app, &mut events_rx, "instance-started", 20).await;
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    dump("console", &terminal);
    assert_shows(&terminal, "instance-started", "console shows instance output");
    assert_shows(&terminal, "── started `", "console shows the start marker");

    // Scrolling back must stop following, and End must resume.
    app.on_key(key(KeyCode::PageUp));
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    assert_shows(&terminal, "scrolled back", "page-up leaves follow mode");
    app.on_key(key(KeyCode::End));
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    assert_hides(&terminal, "scrolled back", "end resumes following");

    // 11c. A wrong key must be refused, and the UI must say so rather than
    //      showing the server as merely unreachable.
    let bad = Endpoint::new(addr, auth::hash_or_random(Some("wrong-phrase")).to_vec());
    match client::net::stat(&bad).await {
        Err(NetError::Auth(_)) => println!("OK   a wrong key is rejected"),
        other => panic!("FAIL wrong key was not rejected: {other:?}"),
    }
    let keyless = Endpoint::new(addr, Vec::new());
    match client::net::stat(&keyless).await {
        Err(NetError::NoKey) => println!("OK   a missing key is reported before dialling"),
        other => panic!("FAIL keyless call was not caught: {other:?}"),
    }

    // 12. Stop it again, then check the edit form is pre-filled from the
    //     live config rather than blank.
    app.on_key(key(KeyCode::Char('x')));
    wait_run_state(&mut app, &mut events_rx, "stopped", 30).await;
    println!("OK   stop from the manage screen");

    app.on_key(key(KeyCode::Char('e')));
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    dump("edit instance", &terminal);
    assert_shows(&terminal, "Edit instance", "edit form opens");
    assert_shows(&terminal, "tui-smoke", "name pre-filled");
    assert_shows(&terminal, "Hello-World", "repo pre-filled");
    app.on_key(key(KeyCode::Esc));

    // 13. Removing the instance confirms, offers the delete-files toggle,
    //     and drops back to the landing page.
    app.on_key(key(KeyCode::Char('D')));
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    dump("remove instance", &terminal);
    assert_shows(&terminal, "also delete its files", "delete-files toggle offered");
    app.on_key(key(KeyCode::Char(' ')));
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    assert_shows(&terminal, "[x] also delete its files", "toggle flips on space");
    app.on_key(key(KeyCode::Char('y')));
    settle(&mut app, &mut events_rx).await;
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    assert!(matches!(app.screen(), Screen::Landing), "did not return to the landing page");
    assert_hides(&terminal, "client shell", "manage screen closed");
    println!("OK   instance removed from the manage screen");

    // 14. Escape from a manage screen returns rather than quitting.
    app.cursor = 0;
    assert!(!app.should_quit, "quit unexpectedly");

    // 15. Removal is confirmed, and cancelling really cancels.
    app.on_key(key(KeyCode::Char('d')));
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    assert_shows(&terminal, "Remove server", "remove confirmation");
    app.on_key(key(KeyCode::Char('n')));
    assert_eq!(app.book.servers.len(), 1, "cancelled removal removed anyway");
    app.on_key(key(KeyCode::Char('d')));
    app.on_key(key(KeyCode::Char('y')));
    assert_eq!(app.book.servers.len(), 0, "confirmed removal did not remove");
    terminal.draw(|f| client::ui::draw(f, &app)).unwrap();
    assert_shows(&terminal, "No servers yet.", "back to the empty state");

    remove_instance(addr, id).await;
    let _ = std::fs::remove_dir_all(&dir);
    println!("\ntui smoke passed");
}


/// Where our own fixture instance sits in the flattened tree. Other tests may
/// have left instances on the same server, so it is never a fixed index.
fn instance_row(app: &App) -> usize {
    app.rows().iter()
        .position(|row| matches!(row, Row::Instance { server, instance }
            if app.instances_of(app.book.servers[*server].id)
                .get(*instance)
                .is_some_and(|i| i.name == INSTANCE)))
        .expect("no row for the fixture instance")
}

/// Apply whatever the background tasks report for `dur`.
async fn pump(app: &mut App, rx: &mut mpsc::Receiver<AppEvent>, dur: Duration) {
    let deadline = Instant::now() + dur;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        match tokio::time::timeout(left, rx.recv()).await {
            Ok(Some(event)) => app.on_event(event),
            _ => return,
        }
    }
}

/// Long enough for one spawned round trip to land.
async fn settle(app: &mut App, rx: &mut mpsc::Receiver<AppEvent>) {
    pump(app, rx, Duration::from_millis(1500)).await;
}

async fn wait_repo_ready(addr: SocketAddr, id: u128) {
    for _ in 0..120 {
        match client::net::check(&endpoint(addr), id).await.expect("check failed").repo {
            RepoState::Ready => return,
            RepoState::CloneFailed(e) => panic!("clone failed: {e}"),
            RepoState::Provisioning => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    panic!("repo not ready after 60s");
}

/// Drive the app until the manage screen's detail reports the wanted state.
async fn wait_run_state(app: &mut App, rx: &mut mpsc::Receiver<AppEvent>, want: &str, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        let reached = app.manage()
            .and_then(|m| m.detail.as_ref())
            .is_some_and(|d| match want {
                "running" => matches!(d.run, RunState::Running { .. }),
                "stopped" => matches!(
                    d.run,
                    RunState::Stopped | RunState::NotRunning | RunState::Exited { .. },
                ),
                _ => false,
            });
        if reached {
            return;
        }
        pump(app, rx, Duration::from_millis(400)).await;
    }
    panic!("instance did not reach '{want}' within {secs}s");
}

/// Drive the app until the console panel contains `needle`.
async fn wait_console(app: &mut App, rx: &mut mpsc::Receiver<AppEvent>, needle: &str, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        let seen = app.manage()
            .is_some_and(|m| m.console.iter().any(|l| l.text.contains(needle)));
        if seen {
            return;
        }
        pump(app, rx, Duration::from_millis(400)).await;
    }
    panic!("'{needle}' never reached the console within {secs}s");
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
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                collected.extend_from_slice(&buf[..n]);

                let asked = collected.windows(DSR.len()).filter(|w| *w == DSR).count();
                while answered < asked {
                    if stream.write_all(&term::data_frame(b"\x1b[1;1R")).await.is_err() {
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

/// Read from a session socket until `needle` shows up or `secs` elapse.
async fn read_until(stream: &mut TcpStream, needle: &str, secs: u64) -> String {
    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut buf = [0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                collected.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&collected).contains(needle) {
                    break;
                }
            }
        }
    }
    String::from_utf8_lossy(&collected).into_owned()
}

async fn create_instance(addr: SocketAddr) -> u128 {
    // Drop a leftover from an aborted run first.
    if let Ok(Response::InstanceList(list)) = client::net::call(&endpoint(addr), Action::ListInstances).await
        && let Some(old) = list.iter().find(|i| i.name == INSTANCE) {
        remove_instance(addr, old.id).await;
    }

    match client::net::call(&endpoint(addr), Action::CreateInstance {
        name: INSTANCE.to_string(),
        source: Source::Git { url: "https://github.com/octocat/Hello-World".to_string(), branch: None },
        // Interactive, so the attach session has a live stdin to talk to.
        command: "cmd.exe".to_string(),
        args: vec!["/q".to_string(), "/k".to_string(), "echo instance-started".to_string()],
        env: Default::default(),
        autostart: false,
        retry_policy: RetryPolicy::Never,
    }).await {
        Ok(Response::InstanceCreated { id }) => id,
        other => panic!("could not create the fixture instance: {other:?}"),
    }
}

async fn remove_instance(addr: SocketAddr, id: u128) {
    // A clone may still be running; retry until the server lets it go.
    // Already-gone is the normal case when the test removed it itself.
    for _ in 0..60 {
        match client::net::call(&endpoint(addr), Action::RemoveInstance { id, delete_files: true }).await {
            Ok(_) => return,
            Err(NetError::Api(e)) if e.code == ErrorCode::NotFound => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    eprintln!("warning: could not remove the fixture instance {id:032x}");
}

