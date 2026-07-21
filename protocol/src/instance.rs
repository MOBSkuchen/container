use std::collections::HashMap;
use std::path::PathBuf;
use bier_derive::{Deserialize, Serialize};
use bierpc::serialize::{Deserialize, Serialize};

/// What to do when a supervised process ends.
///
/// The decision itself lives server-side (`manager::should_restart`) because it
/// inspects processkit's `Outcome`, which is not a wire type.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RetryPolicy {
    Never,
    OnCrash,
    Always,
    Retry(u32),
}

/// Wire-format mirror of the server's internal `State` (processkit's `Outcome`
/// is not serializable).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum RunState {
    NotRunning,
    Starting,
    Running { pids: Vec::<u32>, restarts: u32 },
    Backoff { delay_ms: u64, restarts: u32 },
    Exited { code: Option::<i32>, signal: Option::<i32>, restarts: u32 },
    Stopped,
    Failed(String),
}

impl RunState {
    /// Whether the instance is doing something right now (so stop/kill/attach
    /// make sense and repo mutation does not).
    pub fn is_active(&self) -> bool {
        matches!(self, RunState::Starting | RunState::Running { .. } | RunState::Backoff { .. })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum RepoState {
    /// Clone/update in progress; the instance cannot run yet.
    Provisioning,
    Ready,
    CloneFailed(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GroupStats {
    pub processes: u64,
    pub cpu_time_ms: Option<u64>,
    pub peak_memory_bytes: Option<u64>,
}

/// Full definition of an instance: a public git repo plus how to run it.
/// This is what the server persists to its instance index.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InstanceConfig {
    pub id: u128,
    pub name: String,
    pub repo_url: String,
    pub branch: Option<String>,
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub autostart: bool,
    pub retry_policy: RetryPolicy,
    /// This instance *is* the server process (created by `Bootstrap`). It is
    /// reported as running rather than supervised, and cannot be operated on.
    pub self_managed: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InstanceStatus {
    pub config: InstanceConfig,
    pub repo: RepoState,
    pub run: RunState,
    pub stats: Option<GroupStats>,
    /// Absolute path of the instance's checkout on the server; the root the
    /// client's file browser starts from.
    pub repo_dir: PathBuf,
}

/// Which of the child's streams a console line came from.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// One line of an instance's captured console output.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConsoleLine {
    /// Milliseconds since the unix epoch, stamped when the server read it.
    pub at_ms: u64,
    pub stream: Stream,
    pub text: String,
}

/// Compact per-instance entry used in `Stat` / `ListInstances`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InstanceStatResponse {
    pub id: u128,
    pub name: String,
    pub repo: RepoState,
    pub run: RunState,
    pub self_managed: bool,
}
