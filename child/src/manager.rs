use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use bier_derive::{Deserialize, Serialize};
use bierpc::serialize::{Serialize, Deserialize};
use futures::StreamExt;
use processkit::{CancellationToken, Command, LineTerminator, Outcome, ProcessGroup, ProcessStdin};
use tokio::sync::{broadcast, watch, Mutex};
use tokio::task::JoinHandle;
use crate::api::{ApiError, ErrorCode};
use crate::gitops;
use crate::storage::{ChildStg, InstanceConfig};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum RetryPolicy {
    Never,
    OnCrash,
    Always,
    Retry(u32),
}

impl RetryPolicy {
    pub fn should_restart(&self, outcome: &Outcome, restarts: u32) -> bool {
        match self {
            RetryPolicy::Never => false,
            RetryPolicy::OnCrash => !matches!(outcome, Outcome::Exited(0)),
            RetryPolicy::Always => true,
            RetryPolicy::Retry(n) => restarts < *n,
        }
    }
}

fn backoff_delay(restarts: u32) -> Duration {
    let ms = 100u64.saturating_mul(1u64 << restarts.min(8));
    Duration::from_millis(ms.min(30_000))
}

#[derive(Clone, Debug, PartialEq)]
pub enum State {
    Starting,
    /// `pids` is the whole tree, not just the direct child.
    Running { pids: Vec<u32>, restarts: u32 },
    Backoff { delay: Duration, restarts: u32 },
    /// Terminal: exited and will not be restarted (policy said so, or budget spent).
    Exited { outcome: Outcome, restarts: u32 },
    /// Terminal: killed by us.
    Stopped,
    /// Terminal: the spawn itself failed (bad binary, permissions, etc.).
    Failed { error: String },
}

impl State {
    pub fn is_terminal(&self) -> bool {
        matches!(self, State::Exited { .. } | State::Stopped | State::Failed { .. })
    }
}

/// Wire-format mirror of `State` (processkit's `Outcome` is not serializable).
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

impl From<&State> for RunState {
    fn from(s: &State) -> Self {
        match s {
            State::Starting => RunState::Starting,
            State::Running { pids, restarts } => RunState::Running { pids: pids.clone(), restarts: *restarts },
            State::Backoff { delay, restarts } => RunState::Backoff { delay_ms: delay.as_millis() as u64, restarts: *restarts },
            State::Exited { outcome, restarts } => {
                let (code, signal) = match outcome {
                    Outcome::Exited(c) => (Some(*c), None),
                    Outcome::Signalled(s) => (None, *s),
                    _ => (None, None),
                };
                RunState::Exited { code, signal, restarts: *restarts }
            }
            State::Stopped => RunState::Stopped,
            State::Failed { error } => RunState::Failed(error.clone()),
        }
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

#[derive(Serialize, Deserialize, Debug)]
pub struct InstanceStatus {
    pub config: InstanceConfig,
    pub repo: RepoState,
    pub run: RunState,
    pub stats: Option<GroupStats>,
}

/// Compact per-instance entry used in `Stat` / `ListInstances`.
#[derive(Serialize, Deserialize, Debug)]
pub struct InstanceStatResponse {
    pub id: u128,
    pub name: String,
    pub repo: RepoState,
    pub run: RunState,
}

/// A live (or finished-but-not-cleared) supervised run of one instance.
struct Service {
    group: Arc<ProcessGroup>,
    state: watch::Receiver<State>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
    /// Terminal-attach hook: the current process's stdin, if running.
    stdin: Arc<Mutex<Option<ProcessStdin>>>,
    /// Terminal-attach hook: merged stdout+stderr lines (with `\n` re-added).
    output_tx: broadcast::Sender<Vec<u8>>,
}

struct ManagedInstance {
    config: InstanceConfig,
    repo: RepoState,
    service: Option<Service>,
}

impl ManagedInstance {
    fn run_state(&self) -> RunState {
        match &self.service {
            Some(svc) => RunState::from(&*svc.state.borrow()),
            None => RunState::NotRunning,
        }
    }

    fn is_active(&self) -> bool {
        self.service.as_ref().is_some_and(|s| !s.state.borrow().is_terminal())
    }
}

/// Fields of `Action::UpdateInstance` that may be patched; `None` = unchanged.
pub struct InstancePatch {
    pub name: Option<String>,
    pub repo_url: Option<String>,
    pub branch: Option<Option<String>>,
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
    pub autostart: Option<bool>,
    pub retry_policy: Option<RetryPolicy>,
}

pub struct InstanceManager {
    stg: ChildStg,
    instances: Mutex<HashMap<u128, ManagedInstance>>,
}

fn err(code: ErrorCode, msg: impl Into<String>) -> ApiError {
    ApiError { code, msg: msg.into() }
}

impl InstanceManager {
    pub fn new(stg: ChildStg, configs: Vec<InstanceConfig>) -> Arc<Self> {
        let mut instances = HashMap::new();
        for config in configs {
            let repo = if stg.repo_dir(config.id).exists() {
                RepoState::Ready
            } else {
                RepoState::CloneFailed("repo directory missing; run UpdateRepo".to_string())
            };
            instances.insert(config.id, ManagedInstance { config, repo, service: None });
        }
        Arc::new(Self { stg, instances: Mutex::new(instances) })
    }

    /// Start every instance flagged `autostart` whose repo is present.
    pub async fn autostart(self: &Arc<Self>) {
        let ids: Vec<u128> = {
            let instances = self.instances.lock().await;
            instances.values()
                .filter(|mi| mi.config.autostart && matches!(mi.repo, RepoState::Ready))
                .map(|mi| mi.config.id)
                .collect()
        };
        for id in ids {
            if let Err(e) = self.run(id).await {
                eprintln!("autostart of instance {id:032x} failed: {}", e.msg);
            }
        }
    }

    async fn persist(&self, instances: &HashMap<u128, ManagedInstance>) -> Result<(), ApiError> {
        let configs: Vec<InstanceConfig> = instances.values().map(|mi| mi.config.clone()).collect();
        self.stg.save_instances(&configs).await
            .map_err(|e| err(ErrorCode::Internal, format!("persisting instances: {e}")))
    }

    pub async fn create(self: &Arc<Self>, config_template: InstanceConfig) -> Result<u128, ApiError> {
        let mut config = config_template;
        config.id = rand::random::<u128>();
        let id = config.id;

        {
            let mut instances = self.instances.lock().await;
            if instances.values().any(|mi| mi.config.name == config.name) {
                return Err(err(ErrorCode::Conflict, format!("an instance named '{}' already exists", config.name)));
            }
            instances.insert(id, ManagedInstance { config, repo: RepoState::Provisioning, service: None });
            self.persist(&instances).await?;
        }

        self.spawn_clone(id, false);
        Ok(id)
    }

    /// Background clone/update; flips the instance's `RepoState` when done.
    fn spawn_clone(self: &Arc<Self>, id: u128, is_update: bool) {
        let mgr = self.clone();
        tokio::spawn(async move {
            let (url, branch) = {
                let instances = mgr.instances.lock().await;
                let Some(mi) = instances.get(&id) else { return };
                (mi.config.repo_url.clone(), mi.config.branch.clone())
            };
            let repo_dir = mgr.stg.repo_dir(id);
            let result = if is_update {
                gitops::update(url, branch, repo_dir).await
            } else {
                gitops::clone(url, branch, repo_dir).await
            };
            let mut instances = mgr.instances.lock().await;
            if let Some(mi) = instances.get_mut(&id) {
                mi.repo = match result {
                    Ok(()) => RepoState::Ready,
                    Err(e) => {
                        eprintln!("instance {id:032x}: clone/update failed: {e}");
                        RepoState::CloneFailed(e)
                    }
                };
            }
        });
    }

    pub async fn update_config(&self, id: u128, patch: InstancePatch) -> Result<(), ApiError> {
        let mut instances = self.instances.lock().await;
        if let Some(name) = &patch.name
            && instances.values().any(|mi| mi.config.id != id && &mi.config.name == name) {
            return Err(err(ErrorCode::Conflict, format!("an instance named '{name}' already exists")));
        }
        let mi = instances.get_mut(&id).ok_or_else(|| err(ErrorCode::NotFound, "no such instance"))?;

        let c = &mut mi.config;
        if let Some(v) = patch.name { c.name = v; }
        if let Some(v) = patch.repo_url { c.repo_url = v; }
        if let Some(v) = patch.branch { c.branch = v; }
        if let Some(v) = patch.command { c.command = v; }
        if let Some(v) = patch.args { c.args = v; }
        if let Some(v) = patch.env { c.env = v; }
        if let Some(v) = patch.autostart { c.autostart = v; }
        if let Some(v) = patch.retry_policy { c.retry_policy = v; }

        self.persist(&instances).await
    }

    /// Re-clone the configured branch and swap it in. The instance must not be
    /// running (on Windows the old tree can't be deleted under a live process).
    pub async fn update_repo(self: &Arc<Self>, id: u128) -> Result<(), ApiError> {
        {
            let mut instances = self.instances.lock().await;
            let mi = instances.get_mut(&id).ok_or_else(|| err(ErrorCode::NotFound, "no such instance"))?;
            if mi.is_active() {
                return Err(err(ErrorCode::Conflict, "instance is running; stop it before updating the repo"));
            }
            if matches!(mi.repo, RepoState::Provisioning) {
                return Err(err(ErrorCode::Provisioning, "a clone/update is already in progress"));
            }
            mi.repo = RepoState::Provisioning;
        }
        self.spawn_clone(id, true);
        Ok(())
    }

    pub async fn run(self: &Arc<Self>, id: u128) -> Result<(), ApiError> {
        let mut instances = self.instances.lock().await;
        let mi = instances.get_mut(&id).ok_or_else(|| err(ErrorCode::NotFound, "no such instance"))?;

        match &mi.repo {
            RepoState::Provisioning => return Err(err(ErrorCode::Provisioning, "repo clone still in progress")),
            RepoState::CloneFailed(e) => return Err(err(ErrorCode::GitError, format!("repo is not available: {e}"))),
            RepoState::Ready => {}
        }
        if mi.is_active() {
            return Err(err(ErrorCode::AlreadyRunning, "instance is already running"));
        }

        let group = Arc::new(ProcessGroup::new()
            .map_err(|e| err(ErrorCode::Internal, format!("creating process group: {e}")))?);
        let (state_tx, state_rx) = watch::channel(State::Starting);
        let cancel = CancellationToken::new();
        let stdin = Arc::new(Mutex::new(None));
        let (output_tx, _) = broadcast::channel(1024);

        let task = tokio::spawn(supervise(
            group.clone(),
            mi.config.clone(),
            self.stg.repo_dir(id),
            state_tx,
            cancel.clone(),
            stdin.clone(),
            output_tx.clone(),
        ));

        mi.service = Some(Service { group, state: state_rx, cancel, task, stdin, output_tx });
        Ok(())
    }

    /// Graceful stop; waits for the supervision loop to report a terminal state.
    pub async fn stop(&self, id: u128) -> Result<(), ApiError> {
        let mut state = {
            let instances = self.instances.lock().await;
            let mi = instances.get(&id).ok_or_else(|| err(ErrorCode::NotFound, "no such instance"))?;
            let svc = mi.service.as_ref().filter(|_| mi.is_active())
                .ok_or_else(|| err(ErrorCode::NotRunning, "instance is not running"))?;
            svc.cancel.cancel();
            svc.state.clone()
        };
        let wait = async {
            while !state.borrow().is_terminal() {
                if state.changed().await.is_err() { break }
            }
        };
        if tokio::time::timeout(Duration::from_secs(20), wait).await.is_err() {
            return Err(err(ErrorCode::Internal, "instance did not stop within 20s"));
        }
        Ok(())
    }

    /// Hard kill, no grace period.
    pub async fn kill(&self, id: u128) -> Result<(), ApiError> {
        let instances = self.instances.lock().await;
        let mi = instances.get(&id).ok_or_else(|| err(ErrorCode::NotFound, "no such instance"))?;
        let svc = mi.service.as_ref().filter(|_| mi.is_active())
            .ok_or_else(|| err(ErrorCode::NotRunning, "instance is not running"))?;
        svc.cancel.cancel();
        svc.group.kill_all()
            .map_err(|e| err(ErrorCode::Internal, format!("kill failed: {e}")))
    }

    /// Stop (if needed), drop the entry, persist, and optionally delete the
    /// instance's directory.
    pub async fn remove(&self, id: u128, delete_files: bool) -> Result<(), ApiError> {
        let svc = {
            let mut instances = self.instances.lock().await;
            let mi = instances.get_mut(&id).ok_or_else(|| err(ErrorCode::NotFound, "no such instance"))?;
            if matches!(mi.repo, RepoState::Provisioning) {
                return Err(err(ErrorCode::Provisioning, "wait for the running clone/update to finish first"));
            }
            let svc = mi.service.take();
            instances.remove(&id);
            self.persist(&instances).await?;
            svc
        };
        if let Some(svc) = svc {
            svc.cancel.cancel();
            let _ = svc.group.shutdown_ref().await;
            let _ = svc.task.await;
        }
        if delete_files {
            let dir = self.stg.instance_dir(id);
            if dir.exists() {
                tokio::fs::remove_dir_all(&dir).await
                    .map_err(|e| err(ErrorCode::Internal, format!("deleting instance files: {e}")))?;
            }
        }
        Ok(())
    }

    pub async fn check(&self, id: u128) -> Result<InstanceStatus, ApiError> {
        let instances = self.instances.lock().await;
        let mi = instances.get(&id).ok_or_else(|| err(ErrorCode::NotFound, "no such instance"))?;
        let stats = mi.service.as_ref()
            .filter(|_| mi.is_active())
            .and_then(|svc| svc.group.stats().ok())
            .map(|s| GroupStats {
                processes: s.active_process_count as u64,
                cpu_time_ms: s.total_cpu_time.map(|d| d.as_millis() as u64),
                peak_memory_bytes: s.peak_memory_bytes,
            });
        Ok(InstanceStatus {
            config: mi.config.clone(),
            repo: mi.repo.clone(),
            run: mi.run_state(),
            stats,
        })
    }

    pub async fn list(&self) -> HashMap<u128, InstanceStatResponse> {
        let instances = self.instances.lock().await;
        instances.values().map(|mi| (mi.config.id, InstanceStatResponse {
            id: mi.config.id,
            name: mi.config.name.clone(),
            repo: mi.repo.clone(),
            run: mi.run_state(),
        })).collect()
    }

    /// Terminal-attach hooks for a running instance: an output subscription and
    /// the shared stdin slot.
    pub async fn attach_handles(&self, id: u128)
        -> Result<(broadcast::Receiver<Vec<u8>>, Arc<Mutex<Option<ProcessStdin>>>), ApiError>
    {
        let instances = self.instances.lock().await;
        let mi = instances.get(&id).ok_or_else(|| err(ErrorCode::NotFound, "no such instance"))?;
        let svc = mi.service.as_ref().filter(|_| mi.is_active())
            .ok_or_else(|| err(ErrorCode::NotRunning, "instance is not running"))?;
        Ok((svc.output_tx.subscribe(), svc.stdin.clone()))
    }

    /// The repo dir for an existing instance (used by Shell terminals).
    pub async fn repo_dir_of(&self, id: u128) -> Result<PathBuf, ApiError> {
        let instances = self.instances.lock().await;
        let mi = instances.get(&id).ok_or_else(|| err(ErrorCode::NotFound, "no such instance"))?;
        let dir = self.stg.repo_dir(mi.config.id);
        if !dir.exists() {
            return Err(err(ErrorCode::GitError, "instance repo directory does not exist yet"));
        }
        Ok(dir)
    }

    /// Stop everything, in parallel. Called on server shutdown.
    pub async fn shutdown_all(&self) {
        let services: Vec<Service> = {
            let mut instances = self.instances.lock().await;
            instances.values_mut().filter_map(|mi| mi.service.take()).collect()
        };
        let futures = services.into_iter().map(|svc| async move {
            svc.cancel.cancel();
            let _ = svc.group.shutdown_ref().await;
            let _ = svc.task.await;
        });
        futures::future::join_all(futures).await;
    }
}

fn build_command(config: &InstanceConfig, repo_dir: &Path) -> Command {
    Command::new(&config.command)
        .args(&config.args)
        .envs(config.env.iter())
        .current_dir(repo_dir)
        .keep_stdin_open()
        .no_timeout()
        .line_terminator(LineTerminator::CarriageReturn)
        .create_no_window()
}

async fn supervise(
    group: Arc<ProcessGroup>,
    config: InstanceConfig,
    repo_dir: PathBuf,
    state: watch::Sender<State>,
    cancel: CancellationToken,
    stdin_slot: Arc<Mutex<Option<ProcessStdin>>>,
    output_tx: broadcast::Sender<Vec<u8>>,
) {
    let mut restarts: u32 = 0;
    let cmd = build_command(&config, &repo_dir);

    loop {
        if cancel.is_cancelled() {
            let _ = state.send(State::Stopped);
            return;
        }

        let _ = state.send(State::Starting);

        let mut run = match group.start(&cmd).await {
            Ok(run) => run,
            Err(e) => {
                // A spawn failure is not a crash — restarting a missing binary
                // just burns the budget. Fail loud and stop.
                eprintln!("instance {:032x} ('{}'): spawn failed: {e}", config.id, config.name);
                let _ = state.send(State::Failed { error: e.to_string() });
                return;
            }
        };

        *stdin_slot.lock().await = run.take_stdin();

        // The tree may already have forked children; `members()` sees all of them.
        let pids = group.members().unwrap_or_default();
        let _ = state.send(State::Running { pids, restarts });

        // Pump merged stdout/stderr lines to any attached terminals until the
        // streams close (process exit) or we're cancelled.
        let mut events = run.output_events().ok();
        let cancelled = loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break true,
                ev = async {
                    match events.as_mut() {
                        Some(e) => e.next().await,
                        None => None,
                    }
                } => {
                    match ev {
                        Some(event) => {
                            if output_tx.receiver_count() > 0
                                && let Some(text) = event.text() {
                                let mut chunk = text.as_bytes().to_vec();
                                chunk.push(b'\n');
                                let _ = output_tx.send(chunk);
                            }
                        }
                        None => break false,
                    }
                }
            }
        };
        drop(events);
        *stdin_slot.lock().await = None;

        if cancelled {
            let _ = group.shutdown_ref().await;
            let _ = state.send(State::Stopped);
            return;
        }

        let outcome = match run.finish().await {
            Ok(f) => f.outcome,
            Err(e) => {
                eprintln!("instance {:032x} ('{}'): reaping process failed: {e}", config.id, config.name);
                let _ = state.send(State::Failed { error: e.to_string() });
                return;
            }
        };

        if !config.retry_policy.should_restart(&outcome, restarts) {
            let _ = state.send(State::Exited { outcome, restarts });
            return;
        }

        restarts += 1;
        let delay = backoff_delay(restarts);
        let _ = state.send(State::Backoff { delay, restarts });

        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = state.send(State::Stopped);
                return;
            }
            _ = tokio::time::sleep(delay) => {}
        }
    }
}
