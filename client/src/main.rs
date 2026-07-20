use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use crossterm::event::EventStream;
use protocol::auth;
use tokio::sync::{mpsc, watch, Notify};

use client::app::{self, App};
use client::book::{self, Book};
use client::{target, terminal};

#[derive(Parser)]
#[command(version, about = "Manage container servers and their instances", long_about = None)]
struct Cli {
    /// Server list to use (default: the per-user config directory).
    #[arg(short = 'c', long = "config", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Attach to a running instance's process, like `docker attach`.
    ///
    /// The supervised process runs on pipes, not a terminal, so this is
    /// line-oriented: no echo from the far end, no escape sequences. Ctrl+C
    /// detaches and the instance keeps running.
    Attach {
        /// `server/instance`, or just `instance` if the name is unambiguous.
        target: String,
    },
    /// Open a new shell in an instance's checkout, like `docker exec`.
    ///
    /// Runs against a real terminal on the server, so full-screen programs
    /// work and every key — Ctrl+C included — goes through. Type `exit` to
    /// end the session.
    Shell {
        /// `server/instance`, or just `instance` if the name is unambiguous.
        target: String,
    },
    /// Set the key used to authenticate with servers.
    ///
    /// Give the same passphrase the server was set up with and the two derive
    /// an identical key without it ever crossing the network.
    Keygen {
        /// Passphrase to derive the key from. Omit for a random key, which
        /// then has to be copied to the server by hand.
        phrase: Option<String>,

        /// Use a key printed by `server keygen` verbatim, as hex.
        #[arg(long, conflicts_with = "phrase")]
        key: Option<String>,

        /// Set the key for one server only, instead of the default used by
        /// every server that has none of its own.
        #[arg(long, value_name = "NAME")]
        server: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {e:#}");
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
        Some(Command::Keygen { phrase, key, server }) => {
            keygen(book, config_path, phrase, key, server).await
        }
        None => tui(book, config_path).await,
    }
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

async fn tui(book: Book, config_path: PathBuf) -> anyhow::Result<()> {
    let (book_tx, book_rx) = watch::channel(book.clone());
    let (events_tx, events_rx) = mpsc::channel(64);
    let refresh = Arc::new(Notify::new());

    app::spawn_poller(book_rx, events_tx.clone(), refresh.clone());

    // `init` installs a panic hook that restores the terminal, so a crash
    // cannot leave the console in raw mode.
    let mut terminal = ratatui::init();
    let app = App::new(book, config_path, book_tx, refresh, events_tx);
    let result = app.run(&mut terminal, events_rx, EventStream::new()).await;
    ratatui::restore();
    result
}
