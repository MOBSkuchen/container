use std::collections::HashMap;
use std::path::PathBuf;
use bier_derive::{Deserialize, Serialize};
use bierpc::serialize::{Deserialize, Serialize};
use crate::instance::{ConsoleLine, InstanceStatResponse, InstanceStatus, RetryPolicy, Source};

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
        f.write_str(&self.msg)
    }
}

impl std::error::Error for ApiError {}

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
        source: Source,
        command: String,
        args: Vec::<String>,
        env: HashMap::<String, String>,
        autostart: bool,
        retry_policy: RetryPolicy,
    },
    UpdateInstance {
        id: u128,
        name: Option::<String>,
        source: Option::<Source>,
        command: Option::<String>,
        args: Option::<Vec<String>>,
        env: Option::<HashMap<String, String>>,
        autostart: Option::<bool>,
        retry_policy: Option::<RetryPolicy>,
    },
    /// Re-materialize the source and swap it in (instance must be stopped).
    /// Upload sources are refreshed with `Session::UploadSource` instead.
    UpdateRepo { id: u128 },
    RunInstance { id: u128 },
    /// Stop (if running) and start again. On the self-managed instance this
    /// restarts the server itself: it hands over to a fresh process.
    RestartInstance { id: u128 },
    /// Graceful stop (terminate → grace → kill on Unix; job terminate on Windows).
    StopInstance { id: u128 },
    /// Hard kill, no grace period.
    KillInstance { id: u128 },
    RemoveInstance { id: u128, delete_files: bool },
    CheckInstance { id: u128 },
    ListInstances,
    /// Directory listing, subject to the same path jail as file transfers.
    ListDir { path: PathBuf },
    /// The tail of an instance's captured console output, newest last.
    TailConsole { id: u128, lines: u32 },
    /// Hand the server over to itself: it records a self-managed instance,
    /// spawns a replacement process and exits. Only honored when the server
    /// config enables bootstrapping.
    Bootstrap,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Pong,
    /// Generic success for actions with no payload.
    Done,
    StatResponse {
        version: u32,

        total_stg: u64,
        free_stg: u64,

        total_ram: u64,
        free_ram: u64,

        network_recv: u64,
        network_trans: u64,

        cpu_usage: f64,

        instances: HashMap::<u128, InstanceStatResponse>,

        /// Whether `Bootstrap` would be honored right now (enabled in the
        /// server config and not already done).
        bootstrap: bool,
    },
    InstanceCreated { id: u128 },
    InstanceStatus(InstanceStatus),
    InstanceList(Vec<InstanceStatResponse>),
    /// `path` is the resolved absolute directory that was listed.
    DirListing { path: PathBuf, entries: Vec::<DirEntry> },
    /// `dropped` counts lines already evicted from the ring buffer, so the
    /// client can say "earlier output was discarded" rather than imply the
    /// instance started here.
    Console { lines: Vec::<ConsoleLine>, dropped: u64 },
    Error(ApiError),
}
