//! Client side of archive transfers.
//!
//! Both directions move one tar.gz over a side-channel session: pack, stream,
//! unpack. Progress goes out over a watch channel — the TUI redraws on its
//! own tick, so nobody needs to be woken per chunk.

use std::path::{Path, PathBuf};

use anyhow::Context;
use protocol::Session;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

use crate::net::{self, Endpoint};

/// (bytes done, total if known yet)
pub type Progress = watch::Sender<(u64, Option<u64>)>;

const CHUNK: usize = 64 * 1024;

fn tmp_archive_path() -> PathBuf {
    std::env::temp_dir().join(format!("chld-transfer-{:016x}.tar.gz", rand::random::<u64>()))
}

/// Pack `sources` (files or directories) and push them into the remote
/// directory `dest`. Returns once the server has unpacked and acked.
pub async fn upload(
    endpoint: &Endpoint,
    sources: Vec<PathBuf>,
    dest: PathBuf,
    progress: Progress,
) -> anyhow::Result<()> {
    let tmp = tmp_archive_path();
    let packed = {
        let tmp = tmp.clone();
        tokio::task::spawn_blocking(move || pack_blocking(&sources, &tmp))
            .await
            .context("pack task panicked")?
    };
    let result = match packed {
        Ok(()) => upload_archive(endpoint, &tmp, Session::UploadArchive { dest }, Some(progress)).await,
        Err(e) => Err(e).context("packing the selection"),
    };
    let _ = tokio::fs::remove_file(&tmp).await;
    result
}

/// Push the content of an Upload-source instance (a dir, archive or plain
/// file, packed like any other transfer). No progress reporting — this runs
/// behind a toast, not the browser.
pub async fn upload_source(endpoint: &Endpoint, id: u128, path: PathBuf) -> anyhow::Result<()> {
    let tmp = tmp_archive_path();
    let packed = {
        let tmp = tmp.clone();
        tokio::task::spawn_blocking(move || pack_blocking(&[path], &tmp))
            .await
            .context("pack task panicked")?
    };
    let result = match packed {
        Ok(()) => upload_archive(endpoint, &tmp, Session::UploadSource { id }, None).await,
        Err(e) => Err(e).context("packing the content"),
    };
    let _ = tokio::fs::remove_file(&tmp).await;
    result
}

async fn upload_archive(
    endpoint: &Endpoint,
    archive: &Path,
    session: Session,
    progress: Option<Progress>,
) -> anyhow::Result<()> {
    let total = tokio::fs::metadata(archive).await.context("reading the packed archive")?.len();
    if let Some(progress) = &progress {
        let _ = progress.send((0, Some(total)));
    }

    let archive = archive.to_path_buf();
    // Session success means the server unpacked and committed — its reply is
    // the ack the old protocol sent as a byte.
    net::session(endpoint, session, async move |_start, stream| {
        let mut file = tokio::fs::File::open(&archive).await.context("opening the packed archive")?;
        stream.write_all(&total.to_be_bytes()).await.context("sending the archive size")?;
        let mut sent = 0u64;
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = file.read(&mut buf).await.context("reading the packed archive")?;
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.context("the connection dropped mid-transfer")?;
            sent += n as u64;
            if let Some(progress) = &progress {
                let _ = progress.send((sent, Some(total)));
            }
        }
        stream.flush().await.context("flushing the upload")?;
        Ok(())
    }).await
}

/// Pull `sources` (remote files or directories) into the local directory
/// `dest`. The total becomes known once the server has finished packing.
pub async fn download(
    endpoint: &Endpoint,
    sources: Vec<PathBuf>,
    dest: PathBuf,
    progress: Progress,
) -> anyhow::Result<()> {
    let tmp = tmp_archive_path();
    let received = {
        let tmp = tmp.clone();
        net::session(endpoint, Session::DownloadArchive { paths: sources }, async move |_start, stream| {
            // The archive is packed live, so its size arrives as the stream's
            // length prefix rather than in SessionStart.
            let mut len_buf = [0u8; 8];
            stream.read_exact(&mut len_buf).await.context("waiting for the server to pack")?;
            let total = u64::from_be_bytes(len_buf);
            let _ = progress.send((0, Some(total)));

            let mut file = tokio::fs::File::create(&tmp).await.context("creating a temp archive")?;
            let mut done = 0u64;
            let mut buf = vec![0u8; CHUNK];
            while done < total {
                let want = CHUNK.min((total - done) as usize);
                let n = stream.read(&mut buf[..want]).await.context("the connection dropped mid-transfer")?;
                if n == 0 {
                    anyhow::bail!("connection closed after {done} of {total} bytes");
                }
                file.write_all(&buf[..n]).await.context("writing the temp archive")?;
                done += n as u64;
                let _ = progress.send((done, Some(total)));
            }
            file.flush().await.context("writing the temp archive")
        }).await
    };

    let result = match received {
        Ok(()) => {
            let (archive, into) = (tmp.clone(), dest);
            tokio::task::spawn_blocking(move || unpack_blocking(&archive, &into))
                .await
                .context("unpack task panicked")?
                .context("unpacking the archive")
        }
        Err(e) => Err(e),
    };
    let _ = tokio::fs::remove_file(&tmp).await;
    result
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

fn unpack_blocking(archive: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    let file = std::fs::File::open(archive)?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    // The tar crate refuses entries that would escape `dest` on its own.
    tar.unpack(dest)
}
