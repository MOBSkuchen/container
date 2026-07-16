//! Test-only: create a server config non-interactively (the `init` command is
//! interactive, which automated tests can't drive).
//!
//! Usage: mkconfig <addr> <config-path> <storage-path> [file-root ...]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use child::storage::{default_shell, ChildStg};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let addr = SocketAddr::from_str(&args.next().expect("addr")).expect("bad addr");
    let config = PathBuf::from(args.next().expect("config path"));
    let storage = PathBuf::from(args.next().expect("storage path"));
    let roots: Vec<PathBuf> = args.map(PathBuf::from).collect();
    ChildStg::new(addr, config, storage, roots, 30, default_shell())
        .await
        .expect("init failed");
    println!("config written");
}
