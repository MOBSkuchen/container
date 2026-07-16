use std::net::{SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::str::FromStr;
use bierpc::RpcServer;
use clap::Parser;
use console::Term;
use child::api::{Action, Api, Response};
use child::cli::{self, gather_value_routine, Commands};
use child::manager::InstanceManager;
use child::storage::{default_shell, ChildStg};

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

    let (child_stg, _instances) = ChildStg::new(
        SocketAddr::V4(addr),
        config_path,
        storage_path,
        file_roots,
        session_ttl_secs,
        shell,
    ).await?;

    term.write_line(format!("Initialized to {:#?}", child_stg.config_path).as_str())?;

    Ok(())
}

async fn _start(config_path: PathBuf) -> anyhow::Result<()> {
    let (stg, instances) = ChildStg::load(config_path).await?;
    let manager = InstanceManager::new(stg.clone(), instances);
    manager.autostart().await;
    let handler = Api::new(stg.clone(), manager.clone());

    println!("Starting server on {}", stg.addr);
    let server = RpcServer::<Action, Response, _>::new(stg.addr, handler)
        .await
        .expect("Failed to bind server");

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
            Commands::Init => _init(config_file).await?
        }
    }
    Ok(())
}


#[tokio::main]
async fn main() {
    let result = _main().await;
    match result {
        Ok(_) => {}
        Err(e) => {
            print!("Error: {:#?}", e);
        }
    }
}
