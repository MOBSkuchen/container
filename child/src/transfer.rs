use std::path::{Component, Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::api::{ApiError, ErrorCode};
use crate::storage::ChildStg;

// Session protocol after the token handshake (both directions):
//   [u64 big-endian length][exactly that many bytes]
// Download: server sends; upload: client sends. The socket closes afterwards.

/// Validate a requested transfer path against the configured jail.
///
/// Allowed roots are `file_roots` from the server config plus the instances
/// dir. Relative paths resolve against the storage path. `..` components are
/// rejected outright, so a normalized prefix check suffices (symlinks inside
/// an allowed root are considered the operator's choice).
pub fn resolve_path(stg: &ChildStg, requested: &Path) -> Result<PathBuf, ApiError> {
    if requested.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(ApiError {
            code: ErrorCode::AccessDenied,
            msg: "path must not contain '..'".to_string(),
        });
    }

    let target = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        stg.storage_path.join(requested)
    };
    let target = std::path::absolute(&target).map_err(|e| ApiError {
        code: ErrorCode::AccessDenied,
        msg: format!("cannot resolve path: {e}"),
    })?;

    let mut roots = stg.file_roots.clone();
    roots.push(stg.instances_dir());
    for root in &roots {
        if let Ok(root) = std::path::absolute(root)
            && target.starts_with(&root) {
            return Ok(target);
        }
    }
    Err(ApiError {
        code: ErrorCode::AccessDenied,
        msg: "path is outside the configured file roots".to_string(),
    })
}

/// Session handler: stream `path` to the client, length-prefixed.
pub async fn send_file(mut stream: TcpStream, path: PathBuf) {
    let Ok(mut file) = fs::File::open(&path).await else { return };
    let Ok(meta) = file.metadata().await else { return };
    if stream.write_all(&meta.len().to_be_bytes()).await.is_err() {
        return;
    }
    let _ = tokio::io::copy(&mut file, &mut stream).await;
    let _ = stream.shutdown().await;
}

/// Session handler: receive a length-prefixed file into `path`. Data lands in
/// a `.part` file first so a dropped connection never leaves a truncated file
/// at the final path.
pub async fn receive_file(mut stream: TcpStream, path: PathBuf) {
    if let Some(parent) = path.parent()
        && fs::create_dir_all(parent).await.is_err() {
        return;
    }

    let mut len_buf = [0u8; 8];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return;
    }
    let len = u64::from_be_bytes(len_buf);

    let part = path.with_extension("part");
    let Ok(mut file) = fs::File::create(&part).await else { return };

    let mut limited = (&mut stream).take(len);
    let copied = tokio::io::copy(&mut limited, &mut file).await;
    let complete = matches!(copied, Ok(n) if n == len) && file.flush().await.is_ok();
    drop(file);

    if complete {
        if path.exists() && fs::remove_file(&path).await.is_err() {
            let _ = fs::remove_file(&part).await;
            return;
        }
        if fs::rename(&part, &path).await.is_ok() {
            // Ack so the client knows the file was committed, not just sent.
            let _ = stream.write_all(&[1u8]).await;
        }
    } else {
        let _ = fs::remove_file(&part).await;
    }
    let _ = stream.shutdown().await;
}
