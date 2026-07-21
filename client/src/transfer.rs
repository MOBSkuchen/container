//! Client side of archive transfers.
//!
//! Both directions move one tar.gz over a side-channel session: pack, stream,
//! unpack. Progress goes out over a watch channel — the TUI redraws on its
//! own tick, so nobody needs to be woken per chunk.

use std::path::{Path, PathBuf};

use anyhow::Context;
use protocol::Action;
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
        Ok(()) => upload_archive(endpoint, &tmp, dest, &progress).await,
        Err(e) => Err(e).context("packing the selection"),
    };
    let _ = tokio::fs::remove_file(&tmp).await;
    result
}

async fn upload_archive(
    endpoint: &Endpoint,
    archive: &Path,
    dest: PathBuf,
    progress: &Progress,
) -> anyhow::Result<()> {
    let total = tokio::fs::metadata(archive).await.context("reading the packed archive")?.len();
    let _ = progress.send((0, Some(total)));

    let mut stream = net::open_session(endpoint, Action::UploadArchive { dest }).await?;
    let mut file = tokio::fs::File::open(archive).await.context("opening the packed archive")?;

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
        let _ = progress.send((sent, Some(total)));
    }

    // The ack arrives only after the server has unpacked, so success here
    // means the files exist, not just that the bytes were sent.
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await.context("the server did not confirm the unpack")?;
    Ok(())
}

/// Pull `sources` (remote files or directories) into the local directory
/// `dest`. The total becomes known once the server has finished packing.
pub async fn download(
    endpoint: &Endpoint,
    sources: Vec<PathBuf>,
    dest: PathBuf,
    progress: Progress,
) -> anyhow::Result<()> {
    let mut stream = net::open_session(endpoint, Action::DownloadArchive { paths: sources }).await?;

    let mut len_buf = [0u8; 8];
    stream.read_exact(&mut len_buf).await.context("waiting for the server to pack")?;
    let total = u64::from_be_bytes(len_buf);
    let _ = progress.send((0, Some(total)));

    let tmp = tmp_archive_path();
    let received = async {
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
    }.await;

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
