//! Test-only: create a server config non-interactively (the `init` command is
//! interactive, which automated tests can't drive).
//!
//! Usage: mkconfig <addr> <config-path> <storage-path> <auth-phrase> [file-root ...]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use protocol::auth;
use server::storage::{default_shell, ServerStg};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let addr = SocketAddr::from_str(&args.next().expect("addr")).expect("bad addr");
    let config = PathBuf::from(args.next().expect("config path"));
    let storage = PathBuf::from(args.next().expect("storage path"));
    let phrase = args.next().expect("auth phrase");
    let roots: Vec<PathBuf> = args.map(PathBuf::from).collect();

    let key = auth::hash_or_random(Some(phrase.as_str()).filter(|p| !p.is_empty())).to_vec();
    // Test configs allow bootstrapping so smoke can exercise it.
    ServerStg::new(addr, config, storage, roots, 30, default_shell(), key, true)
        .await
        .expect("init failed");
    println!("config written");
}
