use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use tokio::fs;

/// Render an error with its full source chain — gix errors bury the useful
/// part (e.g. the HTTP failure) several levels down.
fn chain(prefix: &str, e: impl std::error::Error) -> String {
    let mut msg = format!("{prefix}: {e}");
    let mut src = e.source();
    while let Some(s) = src {
        msg.push_str(&format!(": {s}"));
        src = s.source();
    }
    msg
}

/// Clone a public repo (optionally a specific branch) into `dest`.
/// gix is blocking, so the whole operation runs on the blocking pool.
pub async fn clone(url: String, branch: Option<String>, dest: PathBuf) -> Result<(), String> {
    tokio::task::spawn_blocking(move || clone_blocking(&url, branch.as_deref(), &dest))
        .await
        .map_err(|e| format!("clone task panicked: {e}"))?
}

fn clone_blocking(url: &str, branch: Option<&str>, dest: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dest).map_err(|e| format!("creating clone dir: {e}"))?;
    // Canonicalizing yields a `\\?\`-prefixed path on Windows, lifting the
    // 260-char MAX_PATH limit for every path gix derives from it (pack files
    // in `.git/objects/pack/` easily blow past it under a deep storage dir).
    let dest = std::fs::canonicalize(dest).map_err(|e| format!("resolving clone dir: {e}"))?;
    let interrupt = AtomicBool::new(false);

    let mut prepare = gix::prepare_clone(url, dest)
        .map_err(|e| format!("preparing clone: {e}"))?;
    if let Some(branch) = branch {
        prepare = prepare
            .with_ref_name(Some(branch))
            .map_err(|e| format!("invalid branch name '{branch}': {e}"))?;
    }

    let (mut checkout, _outcome) = prepare
        .fetch_then_checkout(gix::progress::Discard, &interrupt)
        .map_err(|e| chain(&format!("fetching '{url}'"), e))?;
    checkout
        .main_worktree(gix::progress::Discard, &interrupt)
        .map_err(|e| chain("checking out worktree", e))?;
    Ok(())
}

/// Update an instance's repo by cloning fresh into a temp dir and swapping it
/// in. Always yields a clean tree matching the remote branch head; never
/// leaves a half-updated worktree behind on failure.
pub async fn update(url: String, branch: Option<String>, repo_dir: PathBuf) -> Result<(), String> {
    let tmp = repo_dir.with_extension("tmp");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).await.map_err(|e| format!("clearing stale temp dir: {e}"))?;
    }

    clone(url, branch, tmp.clone()).await?;

    if repo_dir.exists() {
        fs::remove_dir_all(&repo_dir).await.map_err(|e| format!("removing old repo: {e}"))?;
    }
    fs::rename(&tmp, &repo_dir).await.map_err(|e| format!("swapping in new repo: {e}"))?;
    Ok(())
}
