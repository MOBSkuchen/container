use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use bierpc::error::RpcResult;
use bierpc::RpcServerHandler;
use sysinfo::{CpuRefreshKind, Disks, MemoryRefreshKind, Networks, RefreshKind, System};
use tokio::sync::Mutex;
use protocol::auth;
use crate::manager::{InstanceManager, InstancePatch};
use crate::storage::{ServerStg, InstanceConfig};
use crate::{session, terminal, transfer};

// The wire types live in the `protocol` crate, shared with the client.
pub use protocol::api::{Action, ApiError, DirEntry, ErrorCode, Response, TerminalMode};
pub use protocol::auth::{Reply, Request};

type RR = RpcResult<Response>;

/// Collapse `Result<Response, ApiError>` into the wire response.
fn respond(result: Result<Response, ApiError>) -> RR {
    Ok(result.unwrap_or_else(Response::Error))
}

pub struct Api {
    stg: ServerStg,
    manager: Arc<InstanceManager>,
    /// The sampling state below is kept across calls on purpose: sysinfo
    /// reports CPU usage as the delta between two refreshes, so a `System`
    /// built per request can only ever return a meaningless first sample.
    sys: Mutex<System>,
    networks: Mutex<Networks>,
    disks: Mutex<Disks>,
    replay: auth::ReplayGuard,
}

impl Api {
    pub fn new(stg: ServerStg, manager: Arc<InstanceManager>) -> Self {
        // Only what `stat` reports — refreshing processes here would walk the
        // whole process table on every poll.
        let sys = System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
                .with_memory(MemoryRefreshKind::nothing().with_ram()),
        );
        Self {
            stg,
            manager,
            sys: Mutex::new(sys),
            networks: Mutex::new(Networks::new_with_refreshed_list()),
            disks: Mutex::new(Disks::new_with_refreshed_list()),
            replay: auth::ReplayGuard::new(),
        }
    }

    fn session_ttl(&self) -> Duration {
        Duration::from_secs(self.stg.session_ttl_secs)
    }

    pub async fn ping(&self) -> RR {
        Ok(Response::Pong)
    }

    pub async fn stat(&self) -> RR {
        let instances = self.manager.list().await;

        let (cpu_usage, total_ram, free_ram) = {
            let mut sys = self.sys.lock().await;
            sys.refresh_cpu_usage();
            sys.refresh_memory();
            // `available_memory` is what a caller can actually still use;
            // on Windows it is identical to `free_memory` anyway.
            (sys.global_cpu_usage() as f64, sys.total_memory(), sys.available_memory())
        };

        let (total_stg, free_stg) = {
            let mut disks = self.disks.lock().await;
            disks.refresh(true);
            disks.iter().fold((0, 0), |(total, free), disk| {
                (total + disk.total_space(), free + disk.available_space())
            })
        };

        // Cumulative counters, not per-refresh deltas: the client turns them
        // into rates itself, and `received()` would reset on every refresh.
        let (network_recv, network_trans) = {
            let mut networks = self.networks.lock().await;
            networks.refresh(true);
            networks.iter().fold((0, 0), |(recv, trans), (_, data)| {
                (recv + data.total_received(), trans + data.total_transmitted())
            })
        };

        Ok(Response::StatResponse {
            total_stg,
            free_stg,
            total_ram,
            free_ram,
            cpu_usage,
            network_recv,
            network_trans,
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
            TerminalMode::Shell { id, cols, rows } => {
                let cwd = self.manager.repo_dir_of(id).await?;
                let shell = self.stg.shell.clone();
                session::open(self.session_ttl(), move |stream| {
                    terminal::shell_bridge(stream, shell, cwd, cols, rows)
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

    async fn list_dir(&self, requested: PathBuf) -> Result<Response, ApiError> {
        let path = transfer::resolve_path(&self.stg, &requested)?;
        let entries = transfer::list_dir(&path).await?;
        Ok(Response::DirListing { path, entries })
    }

    async fn upload_archive(&self, dest: PathBuf) -> Result<Response, ApiError> {
        let dir = transfer::resolve_path(&self.stg, &dest)?;
        let offer = session::open(self.session_ttl(), move |stream| {
            transfer::receive_archive(stream, dir)
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

    async fn download_archive(&self, paths: Vec<PathBuf>) -> Result<Response, ApiError> {
        if paths.is_empty() {
            return Err(ApiError { code: ErrorCode::NotFound, msg: "nothing to download".to_string() });
        }
        let resolved = paths.iter()
            .map(|p| transfer::resolve_path(&self.stg, p))
            .collect::<Result<Vec<_>, _>>()?;
        let offer = session::open(self.session_ttl(), move |stream| {
            transfer::send_archive(stream, resolved)
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
}

/// Authenticate, dispatch, sign the reply.
///
/// A refusal is deliberately vague on the wire (`AuthFailure`) and detailed in
/// the log: the operator needs to know *why*, a caller holding the wrong key
/// does not.
impl RpcServerHandler<Request, Reply> for Api {
    async fn handle(&self, request: Request) -> RpcResult<Reply> {
        let payload = match auth::verify_request(&self.stg.key, &request, &self.replay) {
            Ok(payload) => payload,
            Err(failure) => {
                eprintln!("rejected a request: {failure:?}");
                return Ok(Reply::Rejected(failure));
            }
        };

        let action: Action = match auth::decode(payload).await {
            Ok(action) => action,
            Err(e) => {
                // Authentic but undecodable: a version mismatch, not an attack.
                eprintln!("could not decode an authenticated request: {e}");
                return Ok(Reply::Rejected(protocol::AuthFailure::Malformed));
            }
        };

        let response = self.dispatch(action).await?;
        let payload = auth::encode(&response).await
            .map_err(bierpc::error::RpcError::from)?;
        Ok(auth::sign_reply(&self.stg.key, &request.nonce, payload))
    }
}

impl Api {
    async fn dispatch(&self, action: Action) -> RR {
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
            Action::UploadArchive { dest } => respond(self.upload_archive(dest).await),
            Action::DownloadArchive { paths } => respond(self.download_archive(paths).await),
            Action::ListDir { path } => respond(self.list_dir(path).await),
            Action::TailConsole { id, lines } => {
                respond(self.manager.tail_console(id, lines as usize).await
                    .map(|(lines, dropped)| Response::Console { lines, dropped }))
            }
        }
    }
}
