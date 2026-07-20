use std::net::{SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::str::FromStr;
use bierpc::RpcServer;
use clap::Parser;
use console::Term;
use protocol::auth;
use server::api::{Api, Reply, Request};
use server::cli::{self, gather_value_routine, Commands};
use server::manager::InstanceManager;
use server::storage::{default_shell, ServerStg};

async fn _init(config_file: PathBuf) -> anyhow::Result<()> {
    let term = Term::stdout();

    let addr: SocketAddrV4 = gather_value_routine(&term, "Server address: ", Some(SocketAddrV4::from_str("0.0.0.0:5000").unwrap()))?;
    let storage_path: PathBuf = gather_value_routine(&term, "Storage path: ", Some(PathBuf::from_str("ctchld").unwrap()))?;
    let config_path: PathBuf = gather_value_routine(&term, "Config file: ", Some(config_file))?;
    let file_roots: String = gather_value_routine(&term, "File roots (';'-separated, empty for none): ", Some(String::new()))?;
    let session_ttl_secs: u64 = gather_value_routine(&term, "Session TTL (seconds): ", Some(30))?;
    let shell: String = gather_value_routine(&term, "Terminal shell: ", Some(default_shell()))?;

    let file_roots: Vec<PathBuf> = file_roots
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();

    let phrase: String = gather_value_routine(&term, "Auth passphrase (blank for a random key): ", Some(String::new()))?;
    let key = auth::hash_or_random(Some(phrase.trim()).filter(|p| !p.is_empty())).to_vec();

    let (server_stg, _instances) = ServerStg::new(
        SocketAddr::V4(addr),
        config_path,
        storage_path,
        file_roots,
        session_ttl_secs,
        shell,
        key,
    ).await?;

    term.write_line(format!("Initialized to {:#?}", server_stg.config_path).as_str())?;
    term.write_line(&pairing_advice(&server_stg.key, !phrase.trim().is_empty()))?;

    Ok(())
}

/// How to get this key into a client. A phrase-derived key can simply be
/// re-derived there; a random one has to be copied.
fn pairing_advice(key: &[u8], from_phrase: bool) -> String {
    if from_phrase {
        "Pair a client with: client keygen <the same phrase>".to_string()
    } else {
        format!(
            "This key is random, so nothing can re-derive it. Pair a client with:\n\
             client keygen --key {}",
            auth::to_hex(key),
        )
    }
}

/// Replace the key in an existing config. Existing clients stop working until
/// they are given the new one, which is the point of rotating it.
async fn _keygen(config_path: PathBuf, phrase: Option<String>, key: Option<String>) -> anyhow::Result<()> {
    use anyhow::Context;
    // Deliberately not via `ServerStg::load`: that refuses a config whose key
    // is missing or the wrong length, which is exactly what keygen repairs.
    let mut f = tokio::fs::File::options().read(true).open(&config_path).await
        .with_context(|| format!("loading config '{}' (run `init` first?)", config_path.display()))?;
    let mut stg = <ServerStg as bierpc::serialize::Deserialize>::deserialize(&mut f).await?;
    drop(f);

    let from_phrase = match key {
        Some(hex) => {
            stg.key = auth::from_hex(&hex).map_err(|e| anyhow::anyhow!("--key: {e}"))?;
            true // already shared with whoever printed it; no advice needed
        }
        None => {
            let phrase = phrase.filter(|p| !p.is_empty());
            stg.key = auth::hash_or_random(phrase.as_deref()).to_vec();
            phrase.is_some()
        }
    };
    stg.save().await?;

    println!("New key saved to {}.", config_path.display());
    println!("{}", pairing_advice(&stg.key, from_phrase));
    println!("Clients holding the old key are locked out until they are updated.");
    Ok(())
}

async fn _start(config_path: PathBuf) -> anyhow::Result<()> {
    use anyhow::Context;
    let (stg, instances) = ServerStg::load(config_path.clone()).await
        .with_context(|| format!("loading config '{}' (run `init` first?)", config_path.display()))?;
    let manager = InstanceManager::new(stg.clone(), instances);
    manager.autostart().await;
    let handler = Api::new(stg.clone(), manager.clone());

    println!("Starting server on {}", stg.addr);
    let server = RpcServer::<Request, Reply, _>::new(stg.addr, handler)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {}: {:?}", stg.addr, e))?;

    tokio::select! {
        _ = server.run(4) => {}
        _ = tokio::signal::ctrl_c() => {
            println!("Shutting down, stopping instances...");
            manager.shutdown_all().await;
        }
    }

    Ok(())
}

async fn _main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    let config_file = cli.config_file;

    if let Some(cmd) = cli.command {
        match cmd {
            Commands::Start { .. } => _start(config_file).await?,
            Commands::Init => _init(config_file).await?,
            Commands::Keygen { phrase, key } => _keygen(config_file, phrase, key).await?,
        }
    }
    Ok(())
}


#[tokio::main]
async fn main() {
    // Windows inherits an "ignore Ctrl+C" flag into child processes. If the
    // server was started from an environment that had it set (a script, a
    // service wrapper), every shell it spawns into a pty inherits it too —
    // and nothing in such a shell can ever be interrupted with ^C. Clearing
    // it restores the default behavior for us and for everything we spawn.
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(None, 0);
    }

    if let Err(e) = _main().await {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}
