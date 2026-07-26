use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use crossterm::event::EventStream;
use protocol::auth;
use tokio::sync::{mpsc, watch, Notify};

use client::app::{self, App, RunOutcome, SessionKind, SessionRequest};
use client::book::{self, Book};
use client::{net, target, terminal};

#[derive(Parser)]
#[command(version, about = "Manage container servers and their instances", long_about = None)]
struct Cli {
    #[arg(help = "Config file where servers and instances are kept track of", long_help = "Config file where servers and instances are kept track of. Defaults to user storage.", short = 'c', long = "config", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Attaches the console to the output of an instance", long_about = "Attaches the console to the output of an instance. Use Ctrl+C to detach.")]
    Attach {
        #[arg(help = "<server>/<instance> or just <server> if the name is unambiguous")]
        target: String,
    },
    #[command(long_about = "Opens the shell on the remote server. Detaching requires exiting via remote (i.e. using exit)", about = "Opens the shell on the remote server.")]
    Shell {
        #[arg(help = "<server>/<instance> or just <server> if the name is unambiguous")]
        target: String,
    },
    #[command(about = "Browse and copy files between here and an instance's checkout")]
    Browse {
        #[arg(help = "<server>/<instance> or just <server> if the name is unambiguous")]
        target: String,
    },
    #[command(about = "List every server and its instances", long_about = "List every server and its instances, one line each — the scriptable view of what the TUI shows.")]
    Ls,
    #[command(about = "Set the auth key with the server", long_about = "Derive, create and set the key for auth with a remote server.")]
    Keygen {
        #[arg(help = "Phrase to derive key from.")]
        phrase: Option<String>,

        #[arg(long, help = "Set an existing key instead of deriving it.", conflicts_with = "phrase")]
        key: Option<String>,

        #[arg(long, help = "Server to set key for, leave empty for default", value_name = "NAME")]
        server: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or_else(book::default_path);

    let book = book::load(&config_path).await
        .map_err(|e| anyhow::anyhow!("reading the server list '{}': {e}", config_path.display()))?;

    match cli.command {
        Some(Command::Attach { target }) => {
            let found = target::resolve(&book, &target).await?;
            terminal::attach(&found.endpoint, found.instance.id, &found.label()).await
        }
        Some(Command::Shell { target }) => {
            let found = target::resolve(&book, &target).await?;
            terminal::shell(&found.endpoint, found.instance.id, &found.label()).await
        }
        Some(Command::Browse { target }) => {
            let found = target::resolve(&book, &target).await?;
            // The browser roots its remote panel at the checkout.
            let detail = net::check(&found.endpoint, found.instance.id).await
                .map_err(|e| anyhow::anyhow!("reading {}: {e}", found.label()))?;
            let start = BrowseStart {
                server: found.server.id,
                instance: found.instance.id,
                remote_root: detail.repo_dir,
            };
            tui(book, config_path, Some(start)).await
        }
        Some(Command::Ls) => ls(book).await,
        Some(Command::Keygen { phrase, key, server }) => {
            keygen(book, config_path, phrase, key, server).await
        }
        None => tui(book, config_path, None).await,
    }
}

/// One line per server and instance. Unreachable servers become a line, not
/// an error: a fleet with one dead box must still list the rest.
async fn ls(book: Book) -> anyhow::Result<()> {
    use protocol::{InstanceStatResponse, RepoState, RunState};

    if book.servers.is_empty() {
        println!("no servers configured — add one in the TUI (run `client` with no arguments)");
        return Ok(());
    }

    fn status(inst: &InstanceStatResponse) -> String {
        let first_line = |s: &str| s.lines().next().unwrap_or_default().to_string();
        if inst.self_managed {
            return "this server".to_string();
        }
        match &inst.repo {
            RepoState::Provisioning => return "preparing".to_string(),
            RepoState::CloneFailed(e) => return format!("source failed: {}", first_line(e)),
            RepoState::Ready => {}
        }
        match &inst.run {
            RunState::NotRunning | RunState::Stopped => "stopped".to_string(),
            RunState::Starting => "starting".to_string(),
            RunState::Running { pids, restarts } => {
                let pid = pids.first().map(|p| format!("pid {p}")).unwrap_or_else(|| "no pids".to_string());
                if *restarts > 0 { format!("running ({pid}, {restarts} restarts)") } else { format!("running ({pid})") }
            }
            RunState::Backoff { delay_ms, restarts } =>
                format!("restarting in {:.1}s ({restarts} restarts)", *delay_ms as f64 / 1000.0),
            RunState::Exited { code, signal, .. } => match (code, signal) {
                (Some(c), _) => format!("exited ({c})"),
                (None, Some(s)) => format!("killed by signal {s}"),
                (None, None) => "exited".to_string(),
            },
            RunState::Failed(e) => format!("failed: {}", first_line(e)),
        }
    }

    for server in &book.servers {
        let endpoint = book.endpoint_or_keyless(server);
        match net::stat(&endpoint).await {
            Ok(vitals) => {
                println!("{} ({})", server.name, server.addr);
                if vitals.instances.is_empty() {
                    println!("  (no instances)");
                }
                for inst in &vitals.instances {
                    // The id is what `attach`/`shell` accept unambiguously.
                    println!("  {:<24} {:032x}  {}", inst.name, inst.id, status(inst));
                }
            }
            Err(e) => println!("{} ({}) — {}", server.name, server.addr, e.short()),
        }
    }
    Ok(())
}

/// Opening screen for `client browse`.
struct BrowseStart {
    server: u128,
    instance: u128,
    remote_root: PathBuf,
}

async fn keygen(
    mut book: Book,
    config_path: PathBuf,
    phrase: Option<String>,
    hex: Option<String>,
    server: Option<String>,
) -> anyhow::Result<()> {
    let (key, source) = match hex {
        Some(hex) => (
            auth::from_hex(&hex).map_err(|e| anyhow::anyhow!("--key: {e}"))?,
            "copied from the server",
        ),
        None => {
            let phrase = phrase.filter(|p| !p.is_empty());
            let source = if phrase.is_some() { "derived from the passphrase" } else { "random" };
            (auth::hash_or_random(phrase.as_deref()).to_vec(), source)
        }
    };

    let scope = match server {
        Some(name) => {
            let entry = book.servers.iter_mut()
                .find(|s| s.name.eq_ignore_ascii_case(&name))
                .ok_or_else(|| anyhow::anyhow!("no server named '{name}' in {}", config_path.display()))?;
            entry.key = key.clone();
            format!("server '{}'", entry.name)
        }
        None => {
            book.key = key.clone();
            "all servers without a key of their own".to_string()
        }
    };

    book::save(&config_path, &book).await?;
    println!("Key ({source}) saved for {scope} in {}.", config_path.display());

    // A random key is useless until the other end has it, so say so and hand
    // over the one thing that makes it usable.
    if source == "random" {
        println!("\nNothing can re-derive this key. Set the same one on the server with:");
        println!("server keygen --key {}", auth::to_hex(&key));
        println!("\n(Or run `keygen <phrase>` on both sides instead.)");
    }
    Ok(())
}

async fn tui(book: Book, config_path: PathBuf, browse: Option<BrowseStart>) -> anyhow::Result<()> {
    let (book_tx, book_rx) = watch::channel(book.clone());
    let (events_tx, mut events_rx) = mpsc::channel(64);
    let refresh = Arc::new(Notify::new());

    app::spawn_poller(book_rx, events_tx.clone(), refresh.clone());

    // `init` installs a panic hook that restores the terminal, so a crash
    // cannot leave the console in raw mode.
    let mut terminal = ratatui::init();
    let mut app = App::new(book, config_path, book_tx, refresh, events_tx);
    if let Some(start) = browse {
        app.open_browse(start.server, start.instance, start.remote_root);
    }
    let result = loop {
        // Rebuilt per lap: a session runs its own EventStream, and two live
        // ones would compete for the same console events.
        let mut input = EventStream::new();
        match app.run(&mut terminal, &mut events_rx, &mut input).await {
            Ok(RunOutcome::Quit) => break Ok(()),
            Ok(RunOutcome::Session(request)) => {
                drop(input);
                ratatui::restore();
                let outcome = run_session(&request).await;
                terminal = ratatui::init();
                if let Err(e) = outcome {
                    app.error(format!("{} on {}: {e:#}", request.kind.verb(), request.label));
                }
            }
            Ok(RunOutcome::Edit(request)) => {
                drop(input);
                ratatui::restore();
                let outcome = client::edit::run(&request).await;
                terminal = ratatui::init();
                match outcome {
                    Ok(summary) => app.info(summary),
                    Err(e) => app.error(format!("edit '{}' failed — {e:#}", request.name)),
                }
                // The panels may now be showing a stale size or mtime.
                app.browse_refresh();
            }
            Err(e) => break Err(e),
        }
    };
    ratatui::restore();
    result
}

async fn run_session(request: &SessionRequest) -> anyhow::Result<()> {
    match request.kind {
        SessionKind::Shell => terminal::shell(&request.endpoint, request.instance, &request.label).await,
        SessionKind::Attach => terminal::attach(&request.endpoint, request.instance, &request.label).await,
    }
}
