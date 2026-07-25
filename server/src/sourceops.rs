//! Materializing an instance's source into its repo dir.
//!
//! Git goes through `gitops`; URLs are downloaded here. Upload sources have
//! no remote — their content arrives over an `UploadSource` session — so both
//! entry points refuse them.

use std::path::{Path, PathBuf};
use protocol::Source;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use crate::gitops;

/// Fetch `source` into `dest` (which need not exist yet).
pub async fn materialize(source: &Source, dest: PathBuf) -> Result<(), String> {
    match source {
        Source::Git { url, branch } => gitops::clone(url.clone(), branch.clone(), dest).await,
        Source::Url { url } => fetch_url(url, &dest).await,
        Source::Upload { .. } => Err("content is uploaded from a client; push it instead".to_string()),
        Source::None => Err("this instance has no source".to_string()),
        Source ::Empty => Ok(())
    }
}

/// Refresh into a temp dir and swap it in, so failure never leaves a
/// half-updated tree (mirrors `gitops::update`).
pub async fn update(source: &Source, repo_dir: PathBuf) -> Result<(), String> {
    match source {
        Source::Git { url, branch } => gitops::update(url.clone(), branch.clone(), repo_dir).await,
        Source::Url { url } => {
            let tmp = repo_dir.with_extension("tmp");
            if tmp.exists() {
                fs::remove_dir_all(&tmp).await.map_err(|e| format!("clearing stale temp dir: {e}"))?;
            }
            fetch_url(url, &tmp).await?;
            if repo_dir.exists() {
                fs::remove_dir_all(&repo_dir).await.map_err(|e| format!("removing old content: {e}"))?;
            }
            fs::rename(&tmp, &repo_dir).await.map_err(|e| format!("swapping in new content: {e}"))?;
            Ok(())
        }
        other => materialize(other, repo_dir).await,
    }
}

/// The last path segment of a URL, query and fragment stripped.
fn url_file_name(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let name = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    if name.is_empty() { "download".to_string() } else { name.to_string() }
}

enum ArchiveKind {
    TarGz,
    Tar,
    Zip,
    /// Not an archive: keep it as a single file.
    Plain,
}

impl ArchiveKind {
    fn of(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
            ArchiveKind::TarGz
        } else if lower.ends_with(".tar") {
            ArchiveKind::Tar
        } else if lower.ends_with(".zip") {
            ArchiveKind::Zip
        } else {
            ArchiveKind::Plain
        }
    }
}

/// Download `url` into `dest`: archives are unpacked there, anything else is
/// stored as `dest/<name>`.
async fn fetch_url(url: &str, dest: &Path) -> Result<(), String> {
    let name = url_file_name(url);

    let response = reqwest::get(url).await
        .map_err(|e| format!("requesting '{url}': {e}"))?
        .error_for_status()
        .map_err(|e| format!("requesting '{url}': {e}"))?;

    fs::create_dir_all(dest).await.map_err(|e| format!("creating '{}': {e}", dest.display()))?;

    // Streamed through a temp file: archives need a second, seekable pass,
    // and a plain file must not appear at its final name half-written.
    let tmp = std::env::temp_dir().join(format!("chld-fetch-{:016x}", rand::random::<u64>()));
    let downloaded = async {
        let mut file = fs::File::create(&tmp).await.map_err(|e| format!("creating a temp file: {e}"))?;
        let mut response = response;
        while let Some(chunk) = response.chunk().await.map_err(|e| format!("downloading '{url}': {e}"))? {
            file.write_all(&chunk).await.map_err(|e| format!("writing the download: {e}"))?;
        }
        file.flush().await.map_err(|e| format!("writing the download: {e}"))
    }.await;

    let result = match downloaded {
        Err(e) => Err(e),
        Ok(()) => {
            let (archive, dest, target) = (tmp.clone(), dest.to_path_buf(), dest.join(&name));
            tokio::task::spawn_blocking(move || match ArchiveKind::of(&name) {
                ArchiveKind::Plain => std::fs::copy(&archive, &target).map(|_| ())
                    .map_err(|e| format!("storing '{}': {e}", target.display())),
                kind => unpack(&archive, kind, &dest),
            })
            .await
            .map_err(|e| format!("unpack task panicked: {e}"))
            .and_then(|r| r)
        }
    };
    let _ = fs::remove_file(&tmp).await;
    result
}

// Via `crate::unpack`: a downloaded archive is untrusted input, and link
// entries pointing outside the repo dir must be refused.
fn unpack(archive: &Path, kind: ArchiveKind, dest: &Path) -> Result<(), String> {
    let file = std::fs::File::open(archive).map_err(|e| format!("reopening the download: {e}"))?;
    match kind {
        ArchiveKind::TarGz => crate::unpack::untar(tar::Archive::new(flate2::read::GzDecoder::new(file)), dest)
            .map_err(|e| format!("unpacking tar.gz: {e}")),
        ArchiveKind::Tar => crate::unpack::untar(tar::Archive::new(file), dest)
            .map_err(|e| format!("unpacking tar: {e}")),
        ArchiveKind::Zip => zip::ZipArchive::new(file)
            .map_err(|e| format!("unpacking zip: {e}"))
            .and_then(|zip| crate::unpack::unzip(zip, dest).map_err(|e| format!("unpacking zip: {e}"))),
        ArchiveKind::Plain => unreachable!("plain files are copied, not unpacked"),
    }
}
