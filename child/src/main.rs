use std::fmt::format;
use std::net::{SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::str::FromStr;
use bierpc::RpcServer;
use clap::Parser;
use console::{style, Term};
use crate::api::{Action, Api, Response};
use crate::cli::{gather_value_routine, Commands};
use crate::storage::ChildStg;

mod api;
mod cli;
mod storage;
mod manager;

async fn _init(config_file: PathBuf) -> anyhow::Result<()> {

    let term = Term::stdout();

    let addr: SocketAddrV4 = gather_value_routine(&term, "Server address: ", Some(SocketAddrV4::from_str("0.0.0.0:5000").unwrap()))?;
    let storage_path: PathBuf = gather_value_routine(&term, "Storage path: ", Some(PathBuf::from_str("ctchld").unwrap()))?;
    let config_path: PathBuf = gather_value_routine(&term, "Config file: ", Some(config_file))?;

    let (child_stg, objects) = ChildStg::new(
        SocketAddr::V4(addr),
        config_path,
        storage_path,
    ).await?;

    term.write_line(format!("Initialized to {:#?}", child_stg.config_path).as_str())?;
    
    Ok(())
}

async fn _start(config_path: PathBuf) -> anyhow::Result<()> {
    let (stg, objects) = ChildStg::load(config_path).await?;
    let handler = Api::new();

    println!("Starting server on {}", stg.addr);
    let server = RpcServer::<Action, Response, _>::new(stg.addr, handler)
        .await
        .expect("Failed to bind server");

    server.run(4).await;

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
