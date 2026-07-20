//! The client's persistent state: which servers it knows, and the keys it
//! talks to them with. Instances are never cached; they come from the servers
//! live.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use bier_derive::{Deserialize, Serialize};
use bierpc::serialize::{Deserialize, Serialize};
use protocol::auth;
use tokio::fs;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerEntry {
    /// Stable local identity. Snapshots are keyed by this rather than by list
    /// position, so removing a server can never misattribute another's data.
    pub id: u128,
    pub name: String,
    pub addr: SocketAddr,
    /// Per-server key. Empty means "use the book's default key", which is the
    /// common case: one phrase shared across a fleet.
    pub key: Vec<u8>,
}

impl ServerEntry {
    pub fn new(name: String, addr: SocketAddr) -> Self {
        Self { id: rand::random::<u128>(), name, addr, key: Vec::new() }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Book {
    /// Used for any server without a key of its own.
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

    /// Same, but never fails: an endpoint with an empty key produces a clear
    /// `NetError::NoKey` at call time rather than silently skipping the server.
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

/// Default location, overridable with `-c`.
pub fn default_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("container-client").join("servers.chld")
}

/// Missing file = empty book; that is the first-run case, not an error.
pub async fn load(path: &Path) -> anyhow::Result<Book> {
    if !path.exists() {
        return Ok(Book::default());
    }
    let mut f = fs::File::open(path).await?;
    Ok(Book::deserialize(&mut f).await?)
}

/// Write via a temp file so an interrupted save cannot truncate the book.
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
