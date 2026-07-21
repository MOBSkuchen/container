//! State for the dual-pane file browser: local filesystem on one side, an
//! instance's checkout on the other. Pure state — fetching and transfers are
//! driven from `app`, rendering from `ui`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use protocol::DirEntry;
use tokio::sync::watch;

#[derive(Clone, Copy, PartialEq)]
pub enum Side {
    Local,
    Remote,
}

impl Side {
    pub fn other(self) -> Side {
        match self {
            Side::Local => Side::Remote,
            Side::Remote => Side::Local,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Side::Local => "local",
            Side::Remote => "remote",
        }
    }
}

pub struct Panel {
    pub cwd: PathBuf,
    pub entries: Vec<DirEntry>,
    pub cursor: usize,
    pub selected: HashSet<String>,
    pub error: Option<String>,
    pub loading: bool,
    /// Names an active transfer is writing here; shown as ghosts until the
    /// post-transfer refresh delivers the real entries.
    pub incoming: Vec<String>,
}

impl Panel {
    fn new(cwd: PathBuf) -> Self {
        Self {
            cwd,
            entries: Vec::new(),
            cursor: 0,
            selected: HashSet::new(),
            error: None,
            loading: true,
            incoming: Vec::new(),
        }
    }

    /// A fresh listing for `cwd` (the resolved spelling replaces the
    /// requested one). Selection keeps only names that still exist.
    pub fn apply(&mut self, cwd: PathBuf, result: Result<Vec<DirEntry>, String>) {
        self.cwd = cwd;
        self.loading = false;
        match result {
            Ok(entries) => {
                self.selected.retain(|name| entries.iter().any(|e| &e.name == name));
                self.cursor = self.cursor.min(entries.len().saturating_sub(1));
                self.entries = entries;
                self.error = None;
            }
            Err(e) => {
                self.entries.clear();
                self.selected.clear();
                self.cursor = 0;
                self.error = Some(e);
            }
        }
    }

    /// Start loading `cwd`; the previous listing stays visible until then.
    pub fn navigate(&mut self, cwd: PathBuf) {
        self.cwd = cwd;
        self.cursor = 0;
        self.selected.clear();
        self.loading = true;
    }

    pub fn under_cursor(&self) -> Option<&DirEntry> {
        self.entries.get(self.cursor)
    }

    pub fn toggle_selected(&mut self) {
        let Some(entry) = self.under_cursor() else { return };
        let name = entry.name.clone();
        if !self.selected.remove(&name) {
            self.selected.insert(name);
        }
    }

    /// What a copy would take: the marked names, or the cursor entry.
    pub fn picked(&self) -> Vec<String> {
        if self.selected.is_empty() {
            return self.under_cursor().map(|e| vec![e.name.clone()]).unwrap_or_default();
        }
        // Listing order, not hash order.
        self.entries.iter()
            .filter(|e| self.selected.contains(&e.name))
            .map(|e| e.name.clone())
            .collect()
    }
}

/// A running transfer, as the UI sees it.
pub struct Transfer {
    pub label: String,
    pub progress: watch::Receiver<(u64, Option<u64>)>,
}

pub struct Browse {
    pub server: u128,
    pub instance: u128,
    /// Floor of remote navigation: the instance's checkout.
    pub remote_root: PathBuf,
    pub local: Panel,
    pub remote: Panel,
    pub focus: Side,
    pub transfer: Option<Transfer>,
}

impl Browse {
    pub fn new(server: u128, instance: u128, local_cwd: PathBuf, remote_root: PathBuf) -> Self {
        Self {
            server,
            instance,
            local: Panel::new(local_cwd),
            remote: Panel::new(remote_root.clone()),
            remote_root,
            focus: Side::Local,
            transfer: None,
        }
    }

    pub fn panel(&self, side: Side) -> &Panel {
        match side {
            Side::Local => &self.local,
            Side::Remote => &self.remote,
        }
    }

    pub fn panel_mut(&mut self, side: Side) -> &mut Panel {
        match side {
            Side::Local => &mut self.local,
            Side::Remote => &mut self.remote,
        }
    }

    /// The parent to navigate to, unless the panel is at its floor.
    pub fn parent_of(&self, side: Side) -> Option<PathBuf> {
        let cwd = &self.panel(side).cwd;
        if side == Side::Remote && *cwd == self.remote_root {
            return None;
        }
        cwd.parent().map(Path::to_path_buf)
    }
}

/// Local counterpart of the server's `list_dir`: same skip-on-error, same
/// dirs-first ordering, so both panels behave identically.
pub fn read_local_dir(path: &Path) -> Result<Vec<DirEntry>, String> {
    let read = std::fs::read_dir(path).map_err(|e| format!("cannot list '{}': {e}", path.display()))?;
    let mut entries = Vec::new();
    for entry in read {
        let Ok(entry) = entry else { continue };
        let Ok(meta) = entry.metadata() else { continue };
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
