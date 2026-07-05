use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::str::FromStr;
use clap::Parser;
use console::{style, Term};
use crate::cli::{gather_value_routine, Commands};

mod api;
mod cli;
mod storage;

fn _init(config_file: PathBuf) -> anyhow::Result<()> {

    let term = Term::stdout();

    let addr: SocketAddrV4 = gather_value_routine(&term, "Server address: ", Some(SocketAddrV4::from_str("0.0.0.0:5000").unwrap()))?;
    let config_file: PathBuf = gather_value_routine(&term, "Config file: ", Some(config_file))?;
    
    
    
    Ok(())
}


fn main() {
    let cli = cli::Cli::parse();

    let config_file = cli.config_file;

    if let Some(cmd) = cli.command {
        match cmd {
            Commands::Start { .. } => {}
            Commands::Init => _init(config_file).expect("Fuck")
        }
    }
}
