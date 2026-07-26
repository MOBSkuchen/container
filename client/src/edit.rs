//! Editing a browsed file in the user's editor.
//!
//! The TUI steps aside for the editor exactly like it does for a shell or
//! attach session. A local file opens in place; a remote one is pulled over a
//! `DownloadFile` session into a temp dir, opened, and pushed back over
//! `UploadFile` — but only when the editor actually changed it, so closing
//! without saving cannot clobber the file on the server.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Context;

use crate::browse::Side;
use crate::net::Endpoint;
use crate::transfer;

/// Everything the edit flow needs once the TUI has stepped aside.
pub struct EditRequest {
    pub endpoint: Endpoint,
    /// Which panel the file came from; decides open-in-place vs round-trip.
    pub side: Side,
    /// The file's full path on its own side.
    pub path: PathBuf,
    /// The file name, for messages.
    pub name: String,
}

/// Runs with the terminal restored to normal mode. Returns the toast text.
pub async fn run(request: &EditRequest) -> anyhow::Result<String> {
    match request.side {
        Side::Local => {
            let before = fingerprint(&request.path).await;
            open_editor(&request.path, &request.name).await?;
            Ok(if fingerprint(&request.path).await == before {
                format!("'{}' unchanged", request.name)
            } else {
                format!("edited '{}'", request.name)
            })
        }
        Side::Remote => {
            let dir = std::env::temp_dir().join(format!("chld-edit-{:016x}", rand::random::<u64>()));
            tokio::fs::create_dir_all(&dir).await.context("creating a temp dir")?;
            let result = edit_remote(request, &dir).await;
            let _ = tokio::fs::remove_dir_all(&dir).await;
            result
        }
    }
}

async fn edit_remote(request: &EditRequest, dir: &Path) -> anyhow::Result<String> {
    // Kept under its real name so the editor can pick its mode from it.
    let local = dir.join(&request.name);
    transfer::download_file(&request.endpoint, request.path.clone(), &local).await
        .context("fetching the file")?;

    let before = fingerprint(&local).await;
    open_editor(&local, &request.name).await?;
    if fingerprint(&local).await == before {
        return Ok(format!("'{}' unchanged — nothing uploaded", request.name));
    }

    transfer::upload_file(&request.endpoint, &local, request.path.clone()).await
        .context("pushing the edited file back")?;
    Ok(format!("uploaded changes to '{}'", request.name))
}

/// Size and mtime: enough to tell "saved" from "closed without saving".
async fn fingerprint(path: &Path) -> Option<(u64, SystemTime)> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    Some((meta.len(), meta.modified().ok()?))
}

/// Block on the user's editor until it is done with the file.
async fn open_editor(path: &Path, name: &str) -> anyhow::Result<()> {
    println!("editing '{name}' — save and quit the editor to continue…");
    let status = editor_command(path).status().await.context("starting the editor")?;
    anyhow::ensure!(status.success(), "the editor exited with {status}");
    Ok(())
}

/// `$VISUAL`/`$EDITOR` win; otherwise each OS falls back to its default way
/// of opening a text file such that the launch can be waited on.
fn editor_command(path: &Path) -> tokio::process::Command {
    let configured = std::env::var("VISUAL").ok()
        .or_else(|| std::env::var("EDITOR").ok())
        .filter(|e| !e.trim().is_empty());
    let mut cmd = match configured {
        // "code --wait"-style values: the first word is the program.
        Some(editor) => {
            let mut parts = editor.split_whitespace();
            let mut cmd = tokio::process::Command::new(parts.next().unwrap_or_default());
            cmd.args(parts);
            cmd
        }
        None if cfg!(windows) => {
            // The file association's program; `start /WAIT` blocks on it.
            let mut cmd = tokio::process::Command::new("cmd");
            cmd.args(["/C", "start", "", "/WAIT"]);
            cmd
        }
        None if cfg!(target_os = "macos") => {
            // The default text editor, as a fresh instance `-W` can wait on.
            let mut cmd = tokio::process::Command::new("open");
            cmd.args(["-t", "-W", "-n"]);
            cmd
        }
        None => tokio::process::Command::new("vi"),
    };
    cmd.arg(path);
    cmd
}
