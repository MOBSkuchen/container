use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::api::{ApiError, DirEntry, ErrorCode};
use crate::storage::ServerStg;

// Session protocol after the token handshake (both directions):
//   [u64 big-endian length][exactly that many bytes]
// Download: server sends; upload: client sends. The socket closes afterwards.

/// Validate a requested transfer path against the configured jail.
///
/// Allowed roots are `file_roots` from the server config plus the instances
/// dir. Relative paths resolve against the storage path. `..` components are
/// rejected outright, so a normalized prefix check suffices (symlinks inside
/// an allowed root are considered the operator's choice).
pub fn resolve_path(stg: &ServerStg, requested: &Path) -> Result<PathBuf, ApiError> {
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

/// List a directory that has already passed `resolve_path`. Entries that
/// cannot be stat'd (races, permissions) are skipped rather than failing the
/// whole listing; directories sort first, then names, case-insensitively.
pub async fn list_dir(path: &Path) -> Result<Vec<DirEntry>, ApiError> {
    let mut read_dir = fs::read_dir(path).await.map_err(|e| ApiError {
        code: ErrorCode::NotFound,
        msg: format!("cannot list '{}': {e}", path.display()),
    })?;

    let mut entries = Vec::new();
    while let Some(entry) = read_dir.next_entry().await.map_err(|e| ApiError {
        code: ErrorCode::Internal,
        msg: format!("reading '{}': {e}", path.display()),
    })? {
        let Ok(meta) = entry.metadata().await else { continue };
        entries.push(DirEntry {
            name: entry.file_name().to_string_lossy().into_owned(),
            is_dir: meta.is_dir(),
            size: meta.len(),
            modified_secs: meta.modified().ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs()),
        });
    }

    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir)
        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Ok(entries)
}

/// Session handler: stream `path` to the client, length-prefixed.
pub async fn send_file(stream: TcpStream, path: PathBuf) {
    if let Err(e) = send_inner(stream, &path).await {
        eprintln!("download of '{}' failed: {e}", path.display());
    }
}

async fn send_inner(mut stream: TcpStream, path: &Path) -> std::io::Result<()> {
    let mut file = fs::File::open(path).await?;
    let meta = file.metadata().await?;
    stream.write_all(&meta.len().to_be_bytes()).await?;
    tokio::io::copy(&mut file, &mut stream).await?;
    stream.shutdown().await?;
    Ok(())
}

/// Session handler: receive a length-prefixed file into `path`. Data lands in
/// a `.part` file first so a dropped connection never leaves a truncated file
/// at the final path.
pub async fn receive_file(stream: TcpStream, path: PathBuf) {
    if let Err(e) = receive_inner(stream, &path).await {
        eprintln!("upload to '{}' failed: {e}", path.display());
    }
}

/// Read one length-prefixed payload into `into`, verifying the byte count.
async fn receive_payload(stream: &mut TcpStream, into: &Path) -> std::io::Result<()> {
    let mut len_buf = [0u8; 8];
    stream.read_exact(&mut len_buf).await?;
    let len = u64::from_be_bytes(len_buf);

    let mut file = fs::File::create(into).await?;
    let mut limited = (&mut *stream).take(len);
    let copied = tokio::io::copy(&mut limited, &mut file).await?;
    if copied != len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("connection closed after {copied} of {len} bytes"),
        ));
    }
    file.flush().await
}

async fn receive_inner(mut stream: TcpStream, path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }

    let part = path.with_extension("part");
    let received = receive_payload(&mut stream, &part).await;

    let swapped = match received {
        Ok(()) => async {
            if path.exists() {
                fs::remove_file(path).await?;
            }
            fs::rename(&part, path).await
        }.await,
        Err(e) => Err(e),
    };
    if let Err(e) = swapped {
        let _ = fs::remove_file(&part).await;
        return Err(e);
    }

    // Ack so the client knows the file was committed, not just sent. The file
    // is already in place, so an ack failure is only worth a note.
    if let Err(e) = stream.write_all(&[1u8]).await {
        eprintln!("upload to '{}': committed, but the client ack failed: {e}", path.display());
    }
    let _ = stream.shutdown().await;
    Ok(())
}

fn tmp_archive_path() -> PathBuf {
    std::env::temp_dir().join(format!("chld-transfer-{:016x}.tar.gz", rand::random::<u64>()))
}

/// Session handler: receive a tar.gz and unpack it into `dest`, acking only
/// after the unpack so the client knows the files exist, not just the bytes.
pub async fn receive_archive(mut stream: TcpStream, dest: PathBuf) -> std::io::Result<()> {
    let tmp = tmp_archive_path();
    let result = async {
        fs::create_dir_all(&dest).await?;
        receive_payload(&mut stream, &tmp).await?;
        let (archive, into) = (tmp.clone(), dest.clone());
        tokio::task::spawn_blocking(move || unpack_blocking(&archive, &into))
            .await
            .map_err(|e| std::io::Error::other(format!("unpack task panicked: {e}")))?
    }.await;
    let _ = fs::remove_file(&tmp).await;

    match result {
        Ok(()) => {
            let _ = stream.write_all(&[1u8]).await;
            let _ = stream.shutdown().await;
            Ok(())
        }
        Err(e) => {
            eprintln!("archive upload into '{}' failed: {e}", dest.display());
            Err(e)
        }
    }
}

fn unpack_blocking(archive: &Path, dest: &Path) -> std::io::Result<()> {
    let file = std::fs::File::open(archive)?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    // The tar crate refuses entries that would escape `dest` on its own.
    tar.unpack(dest)
}

/// Session handler: pack `paths` into a tar.gz, then stream it
/// length-prefixed. Packing happens here rather than during the RPC so a
/// large tree cannot run into the client's RPC timeout.
pub async fn send_archive(stream: TcpStream, paths: Vec<PathBuf>) {
    let tmp = tmp_archive_path();
    let packed = {
        let tmp = tmp.clone();
        tokio::task::spawn_blocking(move || pack_blocking(&paths, &tmp))
            .await
            .map_err(|e| std::io::Error::other(format!("pack task panicked: {e}")))
            .and_then(|r| r)
    };
    let result = match packed {
        Ok(()) => send_inner(stream, &tmp).await,
        Err(e) => Err(e),
    };
    let _ = fs::remove_file(&tmp).await;
    if let Err(e) = result {
        eprintln!("archive download failed: {e}");
    }
}

/// Entries are named by their final path component, so unpacking yields them
/// directly inside the destination directory.
fn pack_blocking(paths: &[PathBuf], tmp: &Path) -> std::io::Result<()> {
    let file = std::fs::File::create(tmp)?;
    let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(file, flate2::Compression::default()));
    for path in paths {
        let name = path.file_name()
            .ok_or_else(|| std::io::Error::other(format!("'{}' has no file name", path.display())))?;
        if path.is_dir() {
            tar.append_dir_all(name, path)?;
        } else {
            tar.append_path_with_name(path, name)?;
        }
    }
    tar.into_inner()?.finish()?.sync_all()
}
