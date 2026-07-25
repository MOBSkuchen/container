//! Persistent storage for the client

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use bier_derive::{Deserialize, Serialize};
use bierpc::rpc::Target;
use bierpc::serialize::{Deserialize, Serialize};
use protocol::auth;
use tokio::fs;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerEntry {
    /// local identity
    pub id: u128,
    pub name: String,
    pub addr: Target,
    /// Per-server key. When empty, the default key is used.
    pub key: Vec<u8>,
}

impl ServerEntry {
    pub fn new(name: String, addr: Target) -> Self {
        Self { id: rand::random::<u128>(), name, addr, key: Vec::new() }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Book {
    /// Default key
    pub key: Vec<u8>,
    pub servers: Vec<ServerEntry>,
}

impl Book {
    /// The key to sign requests to `entry` with, or `None` if neither it nor
    /// the book has one — in which case the user has not run `keygen` yet.
    pub fn key_for<'a>(&'a self, entry: &'a ServerEntry) -> Option<&'a [u8]> {
        [entry.key.as_slice(), self.key.as_slice()]
            .into_iter()
            .find(|k| k.len() == auth::KEY_LEN)
    }

    /// The addressed, keyed endpoint for a server, if it has a key.
    pub fn endpoint_for(&self, entry: &ServerEntry) -> Option<crate::net::Endpoint> {
        self.key_for(entry).map(|key| crate::net::Endpoint::new(entry.addr, key.to_vec()))
    }

    /// Same, but never fails: an empty key defers to `NoKey` at call time
    pub fn endpoint_or_keyless(&self, entry: &ServerEntry) -> crate::net::Endpoint {
        self.endpoint_for(entry)
            .unwrap_or_else(|| crate::net::Endpoint::new(entry.addr, Vec::new()))
    }

    pub fn entry(&self, id: u128) -> Option<&ServerEntry> {
        self.servers.iter().find(|s| s.id == id)
    }

    pub fn find_by_name(&self, name: &str) -> Option<&ServerEntry> {
        self.servers.iter().find(|s| s.name.eq_ignore_ascii_case(name))
    }
}

/// Default config location
pub fn default_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("container-client").join("servers.chld")
}

/// Missing file = empty book; first run.
pub async fn load(path: &Path) -> anyhow::Result<Book> {
    if !path.exists() {
        return Ok(Book::default());
    }
    let mut f = fs::File::open(path).await?;
    Ok(Book::deserialize(&mut f).await?)
}

/// Save book via tmp file to avoid corruption.
pub async fn save(path: &Path, book: &Book) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let tmp = path.with_extension("chld.tmp");
    {
        let mut f = fs::File::options().create(true).truncate(true).write(true).open(&tmp).await?;
        book.serialize(&mut f).await?;
        use tokio::io::AsyncWriteExt;
        f.flush().await?;
    }
    if path.exists() {
        fs::remove_file(path).await?;
    }
    fs::rename(&tmp, path).await?;
    Ok(())
}
