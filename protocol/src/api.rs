use std::collections::HashMap;
use std::path::PathBuf;
use bier_derive::{Deserialize, Serialize};
use bierpc::serialize::{Deserialize, Serialize};
use crate::instance::{ConsoleLine, InstanceStatResponse, InstanceStatus, RetryPolicy};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum ErrorCode {
    NotFound,
    AlreadyRunning,
    NotRunning,
    Provisioning,
    GitError,
    AccessDenied,
    Conflict,
    Internal,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiError {
    pub code: ErrorCode,
    pub msg: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.msg)
    }
}

impl std::error::Error for ApiError {}

#[derive(Serialize, Deserialize, Debug)]
pub enum TerminalMode {
    /// Bridge to the running instance's stdin/stdout (`docker attach`-style).
    /// Pipe-based and line-oriented, like the supervised process itself.
    Attach(u128),
    /// A fresh shell in the instance's repo dir (`docker exec`-style), run
    /// under a real PTY. `cols`/`rows` size it at startup; the client resizes
    /// it later over the session's own framing (see `protocol::term`).
    Shell { id: u128, cols: u16, rows: u16 },
}

/// One entry of a `ListDir` result.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// Modification time as seconds since the unix epoch, when available.
    pub modified_secs: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Action {
    Ping,
    Stat,
    CreateInstance {
        name: String,
        repo_url: String,
        branch: Option::<String>,
        command: String,
        args: Vec::<String>,
        env: HashMap::<String, String>,
        autostart: bool,
        retry_policy: RetryPolicy,
    },
    UpdateInstance {
        id: u128,
        name: Option::<String>,
        repo_url: Option::<String>,
        branch: Option::<Option<String>>,
        command: Option::<String>,
        args: Option::<Vec<String>>,
        env: Option::<HashMap<String, String>>,
        autostart: Option::<bool>,
        retry_policy: Option::<RetryPolicy>,
    },
    /// Re-clone the configured branch and swap it in (instance must be stopped).
    UpdateRepo { id: u128 },
    RunInstance { id: u128 },
    /// Graceful stop (terminate → grace → kill on Unix; job terminate on Windows).
    StopInstance { id: u128 },
    /// Hard kill, no grace period.
    KillInstance { id: u128 },
    RemoveInstance { id: u128, delete_files: bool },
    CheckInstance { id: u128 },
    ListInstances,
    OpenTerminal { mode: TerminalMode },
    /// Client will push a file to `dest` over the returned session.
    UploadFile { dest: PathBuf },
    /// Client will pull `src` over the returned session.
    DownloadFile { src: PathBuf },
    /// Directory listing, subject to the same path jail as file transfers.
    ListDir { path: PathBuf },
    /// The tail of an instance's captured console output, newest last.
    TailConsole { id: u128, lines: u32 },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Pong,
    /// Generic success for actions with no payload.
    Done,
    StatResponse {
        total_stg: u64,
        free_stg: u64,

        total_ram: u64,
        free_ram: u64,

        network_recv: u64,
        network_trans: u64,

        cpu_usage: f64,

        instances: HashMap::<u128, InstanceStatResponse>,
    },
    InstanceCreated { id: u128 },
    InstanceStatus(InstanceStatus),
    InstanceList(Vec<InstanceStatResponse>),
    /// Connect to the same host on `port` within `ttl_secs`, send `token` as
    /// the first 32 bytes, then wait for a 1-byte ack. `size` is the file
    /// length for downloads.
    SessionOpened {
        port: u16,
        token: Vec::<u8>,
        ttl_secs: u64,
        size: Option::<u64>,
    },
    /// `path` is the resolved absolute directory that was listed.
    DirListing { path: PathBuf, entries: Vec::<DirEntry> },
    /// `dropped` counts lines already evicted from the ring buffer, so the
    /// client can say "earlier output was discarded" rather than imply the
    /// instance started here.
    Console { lines: Vec::<ConsoleLine>, dropped: u64 },
    Error(ApiError),
}
