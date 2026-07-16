use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use bierpc::serialize::Deserialize;
use bierpc::serialize::Serialize;
use bier_derive::{Deserialize, Serialize};
use bierpc::error::RpcResult;
use bierpc::RpcServerHandler;
use sysinfo::{Disks, Networks, System};
use crate::manager::{InstanceManager, InstancePatch, InstanceStatResponse, InstanceStatus, RetryPolicy};
use crate::storage::{ChildStg, InstanceConfig};
use crate::{session, terminal, transfer};

// NOTE on named-field enum variants: bier_derive emits `Type::deserialize(...)`
// for them, so generic field types must be written turbofish-style
// (`Vec::<String>`), otherwise the generated code does not parse.

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

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiError {
    pub code: ErrorCode,
    pub msg: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TerminalMode {
    /// Bridge to the running instance's stdin/stdout (`docker attach`-style).
    Attach(u128),
    /// A fresh shell in the instance's repo dir (`docker exec`-style).
    Shell(u128),
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
    Error(ApiError),
}

type RR = RpcResult<Response>;

/// Collapse `Result<Response, ApiError>` into the wire response.
fn respond(result: Result<Response, ApiError>) -> RR {
    Ok(result.unwrap_or_else(Response::Error))
}

pub struct Api {
    stg: ChildStg,
    manager: Arc<InstanceManager>,
}

impl Api {
    pub fn new(stg: ChildStg, manager: Arc<InstanceManager>) -> Self {
        Self { stg, manager }
    }

    fn session_ttl(&self) -> Duration {
        Duration::from_secs(self.stg.session_ttl_secs)
    }

    pub async fn ping(&self) -> RR {
        Ok(Response::Pong)
    }

    pub async fn stat(&self) -> RR {
        let sys = System::new_all();
        let instances = self.manager.list().await;

        let mut total_stg = 0;
        let mut free_stg = 0;
        for disk in Disks::new_with_refreshed_list().iter() {
            total_stg += disk.total_space();
            free_stg += disk.available_space();
        }

        let mut recv = 0;
        let mut trans = 0;
        for (_, data) in &Networks::new_with_refreshed_list() {
            recv += data.received();
            trans += data.transmitted();
        }

        Ok(Response::StatResponse {
            total_stg,
            free_stg,
            total_ram: sys.total_memory(),
            free_ram: sys.free_memory(),
            cpu_usage: sys.global_cpu_usage() as f64,
            network_recv: recv,
            network_trans: trans,
            instances,
        })
    }

    async fn open_terminal(&self, mode: TerminalMode) -> Result<Response, ApiError> {
        let offer = match mode {
            TerminalMode::Attach(id) => {
                let (output_rx, stdin_slot) = self.manager.attach_handles(id).await?;
                session::open(self.session_ttl(), move |stream| {
                    terminal::attach_bridge(stream, output_rx, stdin_slot)
                }).await
            }
            TerminalMode::Shell(id) => {
                let cwd = self.manager.repo_dir_of(id).await?;
                let shell = self.stg.shell.clone();
                session::open(self.session_ttl(), move |stream| {
                    terminal::shell_bridge(stream, shell, cwd)
                }).await
            }
        }.map_err(|e| ApiError {
            code: ErrorCode::Internal,
            msg: format!("opening session listener: {e}"),
        })?;

        Ok(Response::SessionOpened {
            port: offer.port,
            token: offer.token,
            ttl_secs: offer.ttl_secs,
            size: None,
        })
    }

    async fn upload_file(&self, dest: PathBuf) -> Result<Response, ApiError> {
        let path = transfer::resolve_path(&self.stg, &dest)?;
        let offer = session::open(self.session_ttl(), move |stream| {
            transfer::receive_file(stream, path)
        }).await.map_err(|e| ApiError {
            code: ErrorCode::Internal,
            msg: format!("opening session listener: {e}"),
        })?;

        Ok(Response::SessionOpened {
            port: offer.port,
            token: offer.token,
            ttl_secs: offer.ttl_secs,
            size: None,
        })
    }

    async fn download_file(&self, src: PathBuf) -> Result<Response, ApiError> {
        let path = transfer::resolve_path(&self.stg, &src)?;
        let size = tokio::fs::metadata(&path).await
            .map_err(|e| ApiError {
                code: ErrorCode::NotFound,
                msg: format!("cannot read '{}': {e}", path.display()),
            })?
            .len();
        let offer = session::open(self.session_ttl(), move |stream| {
            transfer::send_file(stream, path)
        }).await.map_err(|e| ApiError {
            code: ErrorCode::Internal,
            msg: format!("opening session listener: {e}"),
        })?;

        Ok(Response::SessionOpened {
            port: offer.port,
            token: offer.token,
            ttl_secs: offer.ttl_secs,
            size: Some(size),
        })
    }
}

impl RpcServerHandler<Action, Response> for Api {
    async fn handle(&self, action: Action) -> RR {
        match action {
            Action::Ping => self.ping().await,
            Action::Stat => self.stat().await,
            Action::CreateInstance { name, repo_url, branch, command, args, env, autostart, retry_policy } => {
                let config = InstanceConfig {
                    id: 0, // assigned by the manager
                    name, repo_url, branch, command, args, env, autostart, retry_policy,
                };
                respond(self.manager.create(config).await.map(|id| Response::InstanceCreated { id }))
            }
            Action::UpdateInstance { id, name, repo_url, branch, command, args, env, autostart, retry_policy } => {
                let patch = InstancePatch { name, repo_url, branch, command, args, env, autostart, retry_policy };
                respond(self.manager.update_config(id, patch).await.map(|_| Response::Done))
            }
            Action::UpdateRepo { id } => respond(self.manager.update_repo(id).await.map(|_| Response::Done)),
            Action::RunInstance { id } => respond(self.manager.run(id).await.map(|_| Response::Done)),
            Action::StopInstance { id } => respond(self.manager.stop(id).await.map(|_| Response::Done)),
            Action::KillInstance { id } => respond(self.manager.kill(id).await.map(|_| Response::Done)),
            Action::RemoveInstance { id, delete_files } => {
                respond(self.manager.remove(id, delete_files).await.map(|_| Response::Done))
            }
            Action::CheckInstance { id } => {
                respond(self.manager.check(id).await.map(Response::InstanceStatus))
            }
            Action::ListInstances => {
                let list = self.manager.list().await.into_values().collect();
                Ok(Response::InstanceList(list))
            }
            Action::OpenTerminal { mode } => respond(self.open_terminal(mode).await),
            Action::UploadFile { dest } => respond(self.upload_file(dest).await),
            Action::DownloadFile { src } => respond(self.download_file(src).await),
        }
    }
}
