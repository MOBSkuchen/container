use std::net::{SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::str::FromStr;
use bierpc::rpc::{RpcServer, ServerConfig};
use clap::Parser;
use console::Term;
use protocol::auth;
use server::api::Api;
use server::cli::{self, gather_value_routine, Commands};
use server::manager::InstanceManager;
use server::storage::{default_shell, ServerStg};

async fn _init(config_file: PathBuf) -> anyhow::Result<()> {
    let term = Term::stdout();

    // Loopback by default: the channel authenticates but does not encrypt, so
    // wider exposure should be a deliberate choice (see the prompt text).
    let addr: SocketAddrV4 = gather_value_routine(&term, "Server address (0.0.0.0 exposes every interface — trusted networks only): ", Some(SocketAddrV4::from_str("127.0.0.1:5000").unwrap()))?;
    let storage_path: PathBuf = gather_value_routine(&term, "Storage path: ", Some(PathBuf::from_str("ctchld").unwrap()))?;
    let config_path: PathBuf = gather_value_routine(&term, "Config file: ", Some(config_file))?;
    let file_roots: String = gather_value_routine(&term, "File roots (';'-separated, empty for none): ", Some(String::new()))?;
    let session_ttl_secs: u64 = gather_value_routine(&term, "Session TTL (seconds): ", Some(30))?;
    let shell: String = gather_value_routine(&term, "Terminal shell: ", Some(default_shell()))?;
    let bootstrap: bool = gather_value_routine(&term, "Allow bootstrapping (true/false): ", Some(false))?;

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
        bootstrap,
    ).await?;

    term.write_line(format!("Initialized to {:#?}", server_stg.config_path).as_str())?;
    term.write_line(&pairing_advice(if phrase.trim().is_empty() { EitherOr::A(&server_stg.key) } else { EitherOr::B(phrase) }))?;

    Ok(())
}

enum EitherOr<A, B> {
    A(A),
    B(B)
}

/// How to get this key into a client. A phrase-derived key can simply be
/// re-derived there; a random one has to be copied.
fn pairing_advice(key: EitherOr<&[u8], String>) -> String {
    match key {
        EitherOr::A(key) => format!(
            "This key is random, so nothing can re-derive it. Pair a client with:\n\
             `client keygen --key {}`",
            auth::to_hex(key),
        ),
        EitherOr::B(phrase) => format!("Pair a client with: `client keygen {phrase}`")
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

    let phrase = match key {
        Some(hex) => {
            stg.key = auth::from_hex(&hex).map_err(|e| anyhow::anyhow!("--key: {e}"))?;
            None // already shared with whoever printed it; no advice needed
        }
        None => {
            let phrase = phrase.filter(|p| !p.is_empty());
            stg.key = auth::hash_or_random(phrase.as_deref()).to_vec();
            phrase
        }
    };
    stg.save().await?;

    println!("New key saved to {}.", config_path.display());
    println!("{}", &pairing_advice(if let Some(phrase) = phrase { EitherOr::B(phrase) } else { EitherOr::A(&stg.key) }));
    println!("Clients holding the old key are locked out until they are updated.");
    Ok(())
}

async fn _start(config_path: PathBuf, bootstrap: bool) -> anyhow::Result<()> {
    use anyhow::Context;
    let (mut stg, instances) = ServerStg::load(&config_path).await
        .with_context(|| format!("loading config '{}' (run `init` first?)", config_path.display()))?;

    // The flag only grants for this run what the config withholds; it is
    // never persisted.
    if bootstrap {
        stg.bootstrap = true;
    }

    // Spawned by a bootstrapping predecessor: it is still draining, so wait
    // for it to release the address before claiming it.
    if std::env::var_os("CHLD_TAKEOVER").is_some() {
        for _ in 0..40 {
            match tokio::net::TcpListener::bind(stg.addr).await {
                Ok(probe) => { drop(probe); break }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
            }
        }
    }

    let manager = InstanceManager::new(stg.clone(), instances);
    let handler = Api::new(stg.clone(), manager.clone());

    // TLS identity derived from the shared key: the client pins it, so a peer
    // without the key cannot even complete the handshake.
    let tls = protocol::tls::Identity::derive(&stg.key).server_config()
        .map_err(|e| anyhow::anyhow!("building the TLS identity: {e}"))?;

    println!("Starting server on {}", stg.addr);
    let server = RpcServer::new(stg.addr, handler)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {}: {:?}", stg.addr, e))?
        // Bounded so stalled peers hold a slot only until the idle/request
        // timeouts reclaim it, instead of wedging the server.
        .with_config(ServerConfig {
            max_connections: 64,
            request_timeout: Some(std::time::Duration::from_secs(30)),
            tls: Some(tls),
            ..Default::default()
        });

    // After the bind: during a takeover the predecessor may still be
    // stopping the very instances autostart would launch.
    manager.autostart().await;

    tokio::select! {
        _ = server.run() => {}
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
            Commands::Start { bootstrap } => _start(config_file, bootstrap).await?,
            Commands::Init => _init(config_file).await?,
            Commands::Keygen { phrase, key } => _keygen(config_file, phrase, key).await?,
            Commands::PurgeInstances => _purge_instances(&config_file).await?,
            Commands::StopRunaway => _stop_runaway(config_file).await?,
        }
    }
    Ok(())
}

async fn _purge_instances(config_path: &PathBuf) -> anyhow::Result<()> {
    ServerStg::purge_instances(config_path).await?;
    println!("Removed instances file.");
    Ok(())
}

/// Kill whatever other server process runs with this config — typically a
/// bootstrapped one, which has no console to Ctrl+C in.
async fn _stop_runaway(config_path: PathBuf) -> anyhow::Result<()> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};

    let target = std::path::absolute(&config_path).unwrap_or_else(|_| config_path.clone());
    let my_pid = std::process::id();
    let my_exe = std::env::current_exe().ok()
        .and_then(|p| p.file_name().map(|n| n.to_os_string()));

    // A runaway may have been started with a relative config path, so every
    // candidate's arguments are resolved against that process's own cwd.
    // Both sides go through `absolute`, which also normalizes the mixed
    // separators a bash-started process carries in its arguments.
    let matches_config = |process: &sysinfo::Process| {
        process.cmd().iter().skip(1).any(|arg| {
            let arg = std::path::Path::new(arg);
            let joined = if arg.is_absolute() {
                arg.to_path_buf()
            } else if let Some(cwd) = process.cwd() {
                cwd.join(arg)
            } else {
                return false;
            };
            let abs = std::path::absolute(&joined).unwrap_or(joined);
            abs.to_string_lossy().eq_ignore_ascii_case(&target.to_string_lossy())
        })
    };

    let sys = System::new_with_specifics(RefreshKind::nothing().with_processes(
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::Always)
            .with_exe(UpdateKind::Always)
            .with_cwd(UpdateKind::Always),
    ));

    let mut found = false;
    for (pid, process) in sys.processes() {
        if pid.as_u32() == my_pid {
            continue;
        }
        let same_binary = process.exe()
            .and_then(|p| p.file_name())
            .is_some_and(|name| Some(name.to_os_string()) == my_exe);
        if !same_binary || !matches_config(process) {
            continue;
        }
        found = true;
        if process.kill() {
            println!("Killed the runaway server (pid {}).", pid.as_u32());
        } else {
            println!("Found a runaway server (pid {}) but could not kill it.", pid.as_u32());
        }
    }
    if !found {
        println!("No other server is running with '{}'.", target.display());
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
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
