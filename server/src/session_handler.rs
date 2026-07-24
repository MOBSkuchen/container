//! The persistent side of the RPC server: side-channel sessions.
//!
//! Runs on the same mutually-authenticated TLS connection as unary RPC, so a
//! session is authenticated by the transport alone (no per-request HMAC). Each
//! session first sends `Result<SessionStart, ApiError>` — the error arm is the
//! rejection the unary path used to return — then runs its bridge.

use std::path::PathBuf;
use std::sync::Arc;

use bierpc::error::{RpcError, RpcResult};
use bierpc::rpc::PersistentRpcServerHandler;
use bierpc::serialize::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use protocol::{ApiError, ErrorCode, Response, Session, SessionStart};
use crate::manager::InstanceManager;
use crate::storage::ServerStg;
use crate::{terminal, transfer};

pub struct SessionApi {
    stg: ServerStg,
    manager: Arc<InstanceManager>,
}

impl SessionApi {
    /// Built from the *same* manager as the unary `Api`, so a session sees
    /// instances created over the unary path and vice versa.
    pub fn new(stg: ServerStg, manager: Arc<InstanceManager>) -> Self {
        Self { stg, manager }
    }

    /// Refuse before any session bytes flow, carrying the reason both ways.
    async fn reject<S: AsyncWrite + Unpin + Send>(&self, s: &mut S, e: ApiError) -> RpcResult<Response> {
        self.send_start(s, Err(e.clone())).await?;
        Ok(Response::Error(e))
    }

    /// Accept: the session bytes follow.
    async fn accept<S: AsyncWrite + Unpin + Send>(&self, s: &mut S, info: SessionStart) -> RpcResult<()> {
        self.send_start(s, Ok(info)).await
    }

    async fn send_start<S: AsyncWrite + Unpin + Send>(&self, s: &mut S, start: Result<SessionStart, ApiError>) -> RpcResult<()> {
        // Flushed before the bridge blocks: the client reads this first.
        start.serialize(&mut *s).await.map_err(RpcError::from)?;
        s.flush().await.map_err(RpcError::from)?;
        Ok(())
    }

    async fn attach<S: AsyncRead + AsyncWrite + Unpin + Send>(&self, id: u128, s: &mut S) -> RpcResult<Response> {
        let (output_rx, stdin_slot) = match self.manager.attach_handles(id).await {
            Ok(handles) => handles,
            Err(e) => return self.reject(s, e).await,
        };
        self.accept(s, SessionStart { size: None }).await?;
        Ok(bridge_outcome("attach session", terminal::attach_bridge(s, output_rx, stdin_slot).await))
    }

    async fn shell<S: AsyncRead + AsyncWrite + Unpin + Send>(&self, id: u128, cols: u16, rows: u16, s: &mut S) -> RpcResult<Response> {
        let cwd = match self.manager.repo_dir_of(id).await {
            Ok(cwd) => cwd,
            Err(e) => return self.reject(s, e).await,
        };
        let shell = self.stg.shell.clone();
        self.accept(s, SessionStart { size: None }).await?;
        Ok(bridge_outcome("shell session", terminal::shell_bridge(s, shell, cwd, cols, rows).await))
    }

    async fn upload_file<S: AsyncRead + AsyncWrite + Unpin + Send>(&self, dest: PathBuf, s: &mut S) -> RpcResult<Response> {
        let path = match transfer::resolve_path(&self.stg, &dest) {
            Ok(path) => path,
            Err(e) => return self.reject(s, e).await,
        };
        self.accept(s, SessionStart { size: None }).await?;
        Ok(bridge_outcome(
            &format!("upload to '{}'", path.display()),
            transfer::receive_file(s, &path).await,
        ))
    }

    async fn download_file<S: AsyncRead + AsyncWrite + Unpin + Send>(&self, src: PathBuf, s: &mut S) -> RpcResult<Response> {
        let path = match transfer::resolve_path(&self.stg, &src) {
            Ok(path) => path,
            Err(e) => return self.reject(s, e).await,
        };
        let size = match tokio::fs::metadata(&path).await {
            Ok(meta) => meta.len(),
            Err(e) => return self.reject(s, ApiError {
                code: ErrorCode::NotFound,
                msg: format!("cannot read '{}': {e}", path.display()),
            }).await,
        };
        self.accept(s, SessionStart { size: Some(size) }).await?;
        Ok(bridge_outcome(
            &format!("download of '{}'", path.display()),
            transfer::send_file(s, &path).await,
        ))
    }

    async fn upload_archive<S: AsyncRead + AsyncWrite + Unpin + Send>(&self, dest: PathBuf, s: &mut S) -> RpcResult<Response> {
        let dir = match transfer::resolve_path(&self.stg, &dest) {
            Ok(dir) => dir,
            Err(e) => return self.reject(s, e).await,
        };
        self.accept(s, SessionStart { size: None }).await?;
        Ok(bridge_outcome(
            &format!("archive upload into '{}'", dir.display()),
            transfer::receive_archive(s, &dir).await,
        ))
    }

    async fn download_archive<S: AsyncRead + AsyncWrite + Unpin + Send>(&self, paths: Vec<PathBuf>, s: &mut S) -> RpcResult<Response> {
        if paths.is_empty() {
            return self.reject(s, ApiError { code: ErrorCode::NotFound, msg: "nothing to download".to_string() }).await;
        }
        let resolved = match paths.iter().map(|p| transfer::resolve_path(&self.stg, p)).collect::<Result<Vec<_>, _>>() {
            Ok(resolved) => resolved,
            Err(e) => return self.reject(s, e).await,
        };
        self.accept(s, SessionStart { size: None }).await?;
        Ok(bridge_outcome("archive download", transfer::send_archive(s, resolved).await))
    }

    async fn upload_source<S: AsyncRead + AsyncWrite + Unpin + Send>(&self, id: u128, s: &mut S) -> RpcResult<Response> {
        // The session only runs once the client has committed, so this both
        // validates and flips the instance to Provisioning in one step.
        let dir = match self.manager.begin_source_upload(id, true).await {
            Ok(dir) => dir,
            Err(e) => return self.reject(s, e).await,
        };
        self.accept(s, SessionStart { size: None }).await?;

        let result = transfer::receive_archive(s, &dir).await.map_err(|e| e.to_string());
        self.manager.finish_source_upload(id, result.clone()).await;
        Ok(match result {
            Ok(()) => Response::Done,
            Err(e) => Response::Error(ApiError { code: ErrorCode::Internal, msg: format!("source upload failed: {e}") }),
        })
    }
}

/// Map a bridge's `io::Result` to the persistent call's reply.
fn bridge_outcome(what: &str, result: std::io::Result<()>) -> Response {
    match result {
        Ok(()) => Response::Done,
        Err(e) => {
            eprintln!("{what} failed: {e}");
            Response::Error(ApiError { code: ErrorCode::Internal, msg: format!("{what} failed: {e}") })
        }
    }
}

impl PersistentRpcServerHandler for SessionApi {
    type Action = Session;
    type Response = Response;

    async fn handle<S: AsyncRead + AsyncWrite + Unpin + Send>(&self, action: Session, s: &mut S) -> RpcResult<Response> {
        match action {
            Session::Attach(id) => self.attach(id, s).await,
            Session::Shell { id, cols, rows } => self.shell(id, cols, rows, s).await,
            Session::UploadFile { dest } => self.upload_file(dest, s).await,
            Session::DownloadFile { src } => self.download_file(src, s).await,
            Session::UploadArchive { dest } => self.upload_archive(dest, s).await,
            Session::DownloadArchive { paths } => self.download_archive(paths, s).await,
            Session::UploadSource { id } => self.upload_source(id, s).await,
        }
    }
}
