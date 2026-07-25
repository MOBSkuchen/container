//! Application state and the event loop.
//!
//! The loop owns all state and never awaits an RPC inline: every action is
//! handed to a background task that reports back as an `AppEvent`. An
//! unreachable server therefore slows nothing down.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use bierpc::rpc::Target;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures::{Stream, StreamExt};
use ratatui::Terminal;
use ratatui::backend::Backend;
use tokio::sync::{mpsc, watch, Notify};

use protocol::{Action, ConsoleLine, DirEntry, InstanceStatResponse, InstanceStatus, Source};

use crate::book::{self, Book, ServerEntry};
use crate::browse::{self, Browse, Side, Transfer};
use crate::form::{Field, Form, FormOutcome};
use crate::instance_form;
use crate::net::{self, Endpoint, NetError, Vitals};
use crate::{transfer, ui};

pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
const TICK: Duration = Duration::from_millis(250);
const TOAST_TTL: Duration = Duration::from_secs(6);

/// How many console lines the manage screen keeps in view.
pub const CONSOLE_TAIL: u32 = 400;

pub enum AppEvent {
    Snapshot { server: u128, result: Result<Vitals, NetError> },
    /// Full status of the instance the manage screen is focused on.
    Detail { server: u128, instance: u128, result: Result<InstanceStatus, String> },
    /// Console tail for the instance the manage screen is focused on.
    Console {
        server: u128,
        instance: u128,
        result: Result<(Vec<ConsoleLine>, u64), String>,
    },
    /// Outcome of a one-shot action; `desc` is what the user asked for.
    ActionDone { desc: String, result: Result<(), String> },
    /// Listing of a local directory for the browser.
    LocalDir { path: PathBuf, result: Result<Vec<DirEntry>, String> },
    /// Listing of a remote directory; `requested` is what was asked for,
    /// the result carries the server's resolved spelling.
    RemoteDir {
        server: u128,
        requested: PathBuf,
        result: Result<(PathBuf, Vec<DirEntry>), String>,
    },
    /// A transfer finished; `desc` describes it for the toast.
    TransferDone { server: u128, result: Result<String, String> },
}

pub struct ServerState {
    pub vitals: Option<Vitals>,
    pub error: Option<NetError>,
    pub last_ok: Option<Instant>,
    pub rate_recv: f64,
    pub rate_trans: f64,
    pub collapsed: bool,
    /// Previous counters, for turning monotonic totals into rates
    prev_net: Option<(u64, u64, Instant)>,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            vitals: None, error: None, last_ok: None,
            rate_recv: 0.0, rate_trans: 0.0,
            collapsed: false, prev_net: None,
        }
    }
}

impl ServerState {
    fn apply(&mut self, result: Result<Vitals, NetError>) {
        match result {
            Ok(vitals) => {
                let now = Instant::now();
                if let Some((recv, trans, at)) = self.prev_net {
                    let secs = now.duration_since(at).as_secs_f64();
                    // Counters can go backwards when the server restarts;
                    // saturating_sub turns that into a 0 rate, not a spike.
                    if secs > 0.05 {
                        self.rate_recv = vitals.network_recv.saturating_sub(recv) as f64 / secs;
                        self.rate_trans = vitals.network_trans.saturating_sub(trans) as f64 / secs;
                    }
                }
                self.prev_net = Some((vitals.network_recv, vitals.network_trans, now));
                self.vitals = Some(vitals);
                self.error = None;
                self.last_ok = Some(now);
            }
            Err(e) => {
                // Keep the last good vitals so the UI can show stale data
                // rather than going blank.
                self.error = Some(e);
                self.rate_recv = 0.0;
                self.rate_trans = 0.0;
                self.prev_net = None;
            }
        }
    }

    pub fn is_up(&self) -> bool {
        self.error.is_none() && self.vitals.is_some()
    }
}

/// A row of the landing page's flattened server/instance tree
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Row {
    Server { server: usize },
    Instance { server: usize, instance: usize },
}

/// Screens form a stack; `Esc` pops. Only the top one draws and takes keys
pub enum Screen {
    Landing,
    Manage(Manage),
    Browse(Browse),
}

pub struct Manage {
    pub server: u128,
    pub instance: u128,
    pub detail: Option<InstanceStatus>,
    pub detail_error: Option<String>,
    pub console: Vec<ConsoleLine>,
    /// Lines the server has already discarded from its ring buffer
    pub console_dropped: u64,
    pub console_error: Option<String>,
    /// Lines scrolled back from the bottom. 0 = following the newest output
    pub console_scroll: usize,
}

impl Manage {
    fn new(server: u128, instance: u128) -> Self {
        Self {
            server, instance,
            detail: None, detail_error: None,
            console: Vec::new(), console_dropped: 0, console_error: None,
            console_scroll: 0,
        }
    }

    pub fn following(&self) -> bool {
        self.console_scroll == 0
    }
}

/// A copy the confirm modal is sitting on. `names` are top-level entries in
/// `src_dir`; `conflicts` is the subset already present in `dest_dir`.
pub struct TransferPlan {
    pub server: u128,
    /// Which side is the source; the other side receives.
    pub from: Side,
    pub src_dir: PathBuf,
    pub dest_dir: PathBuf,
    pub names: Vec<String>,
    pub conflicts: Vec<String>,
}

pub enum Pending {
    RemoveServer(u128),
    KillInstance { server: u128, instance: u128 },
    RemoveInstance { server: u128, instance: u128 },
    Transfer(TransferPlan),
    Bootstrap(u128),
    /// Restart the self-managed instance, i.e. the server itself.
    RestartServer { server: u128, instance: u128 },
}

#[derive(Clone, Copy)]
pub enum SessionKind {
    Shell,
    Attach,
}

impl SessionKind {
    pub fn verb(self) -> &'static str {
        match self {
            SessionKind::Shell => "shell",
            SessionKind::Attach => "attach",
        }
    }
}

/// Everything the session runner needs once the TUI has stepped aside.
pub struct SessionRequest {
    pub kind: SessionKind,
    pub endpoint: Endpoint,
    pub instance: u128,
    pub label: String,
}

/// Why `run` returned: for good, or to lend the console to a session.
pub enum RunOutcome {
    Quit,
    Session(SessionRequest),
}

pub struct ConfirmToggle {
    pub label: String,
    pub value: bool,
}

pub enum Modal {
    /// `editing` is `None` for a new server, otherwise the entry's id.
    ServerForm { form: Form, editing: Option<u128> },
    /// `editing` is `None` for a new instance, otherwise the instance's id.
    /// `upload_desc` is the recorded upload description when editing an
    /// Upload instance — leaving the location at it keeps the content.
    InstanceForm {
        form: Form,
        server: u128,
        editing: Option<u128>,
        upload_desc: Option<String>,
    },
    Confirm {
        title: String,
        message: String,
        toggle: Option<ConfirmToggle>,
        pending: Pending,
    },
    /// Informational popup; any key dismisses it.
    Notice { title: String, message: String },
    Help,
}

#[derive(PartialEq)]
pub enum ToastKind {
    Info,
    Error,
}

pub struct Toast {
    pub text: String,
    pub kind: ToastKind,
    pub until: Instant,
}

pub struct App {
    pub book: Book,
    pub states: HashMap<u128, ServerState>,
    pub screens: Vec<Screen>,
    pub cursor: usize,
    pub modal: Option<Modal>,
    pub toast: Option<Toast>,
    pub should_quit: bool,
    /// A shell/attach request the run loop hands back to `main` to execute.
    pub pending_session: Option<SessionRequest>,
    /// Servers added this session: the first poll that says they support
    /// bootstrapping triggers a one-time offer.
    bootstrap_offers: HashSet<u128>,
    /// Servers added this session whose protocol version has not been
    /// compared against ours yet; the first successful poll does it.
    version_checks: HashSet<u128>,

    config_path: PathBuf,
    book_tx: watch::Sender<Book>,
    refresh: Arc<Notify>,
    events_tx: mpsc::Sender<AppEvent>,
}

impl App {
    pub fn new(
        book: Book,
        config_path: PathBuf,
        book_tx: watch::Sender<Book>,
        refresh: Arc<Notify>,
        events_tx: mpsc::Sender<AppEvent>,
    ) -> Self {
        let states = book.servers.iter().map(|s| (s.id, ServerState::default())).collect();
        Self {
            book, states, screens: vec![Screen::Landing], cursor: 0,
            modal: None, toast: None, should_quit: false, pending_session: None,
            bootstrap_offers: HashSet::new(), version_checks: HashSet::new(),
            config_path, book_tx, refresh, events_tx,
        }
    }

    /// Shorthand: the server list is read far more often than the rest.
    pub fn servers(&self) -> &[ServerEntry] {
        &self.book.servers
    }

    pub fn screen(&self) -> &Screen {
        self.screens.last().expect("the screen stack is never empty")
    }

    pub fn manage(&self) -> Option<&Manage> {
        match self.screen() {
            Screen::Manage(m) => Some(m),
            _ => None,
        }
    }

    pub fn browse(&self) -> Option<&Browse> {
        match self.screen() {
            Screen::Browse(b) => Some(b),
            _ => None,
        }
    }

    fn browse_mut(&mut self) -> Option<&mut Browse> {
        match self.screens.last_mut() {
            Some(Screen::Browse(b)) => Some(b),
            _ => None,
        }
    }

    /// The landing tree, flattened. Rebuilt per frame and per keypress so it
    /// can never disagree with the state it is drawn from.
    pub fn rows(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        for (server, entry) in self.book.servers.iter().enumerate() {
            rows.push(Row::Server { server });
            let state = &self.states[&entry.id];
            if state.collapsed {
                continue;
            }
            if let Some(vitals) = &state.vitals {
                for instance in 0..vitals.instances.len() {
                    rows.push(Row::Instance { server, instance });
                }
            }
        }
        rows
    }

    pub fn selected_row(&self) -> Option<Row> {
        self.rows().get(self.cursor).copied()
    }

    /// The server owning the cursor, whichever row kind it is on.
    fn selected_server(&self) -> Option<usize> {
        match self.selected_row()? {
            Row::Server { server } | Row::Instance { server, .. } => Some(server),
        }
    }

    pub fn state_of(&self, entry: &ServerEntry) -> &ServerState {
        &self.states[&entry.id]
    }

    pub fn entry(&self, server: u128) -> Option<&ServerEntry> {
        self.book.servers.iter().find(|s| s.id == server)
    }

    pub fn instances_of(&self, server: u128) -> &[InstanceStatResponse] {
        self.states.get(&server)
            .and_then(|s| s.vitals.as_ref())
            .map(|v| v.instances.as_slice())
            .unwrap_or(&[])
    }

    pub fn info(&mut self, text: impl Into<String>) {
        self.toast = Some(Toast { text: text.into(), kind: ToastKind::Info, until: Instant::now() + TOAST_TTL });
    }

    pub fn error(&mut self, text: impl Into<String>) {
        self.toast = Some(Toast { text: text.into(), kind: ToastKind::Error, until: Instant::now() + TOAST_TTL });
    }

    fn publish_servers(&mut self) {
        let _ = self.book_tx.send(self.book.clone());
        let path = self.config_path.clone();
        let book = self.book.clone();
        let tx = self.events_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = book::save(&path, &book).await {
                let _ = tx.send(AppEvent::ActionDone {
                    desc: "saving the server list".to_string(),
                    result: Err(e.to_string()),
                }).await;
            }
        });
    }

    fn add_server(&mut self, name: String, addr: Target) {
        let entry = ServerEntry::new(name, addr);
        self.states.insert(entry.id, ServerState::default());
        self.bootstrap_offers.insert(entry.id);
        self.version_checks.insert(entry.id);
        self.book.servers.push(entry);
        self.publish_servers();
        self.refresh.notify_one();
    }

    fn remove_server(&mut self, id: u128) {
        self.book.servers.retain(|s| s.id != id);
        self.states.remove(&id);
        self.publish_servers();
        self.clamp_cursor();
    }

    fn clamp_cursor(&mut self) {
        let len = self.rows().len();
        self.cursor = self.cursor.min(len.saturating_sub(1));
    }

    /// The addressed, keyed endpoint for a server.
    pub fn endpoint(&self, server: u128) -> Option<Endpoint> {
        self.entry(server).map(|e| self.book.endpoint_or_keyless(e))
    }

    /// Save an instance's config, then push its new content; one toast for
    /// the pair, since the user asked for one thing.
    fn spawn_save_and_upload(&mut self, server: u128, id: u128, name: String, action: Action, path: PathBuf) {
        let Some(endpoint) = self.endpoint(server) else { return };
        let tx = self.events_tx.clone();
        let refresh = self.refresh.clone();
        tokio::spawn(async move {
            let result = match net::done(&endpoint, action).await {
                Ok(()) => transfer::upload_source(&endpoint, id, path).await.map_err(|e| format!("{e:#}")),
                Err(e) => Err(e.to_string()),
            };
            refresh.notify_one();
            let _ = tx.send(AppEvent::ActionDone { desc: format!("save '{name}'"), result }).await;
        });
    }

    /// Fire an action at a server and report the outcome as a toast.
    fn spawn_action(&mut self, desc: impl Into<String>, server: u128, action: Action) {
        let desc = desc.into();
        let Some(endpoint) = self.endpoint(server) else { return };
        let tx = self.events_tx.clone();
        let refresh = self.refresh.clone();
        tokio::spawn(async move {
            let result = net::done(&endpoint, action).await.map_err(|e| e.to_string());
            // Show the consequence immediately rather than up to a poll later.
            refresh.notify_one();
            let _ = tx.send(AppEvent::ActionDone { desc, result }).await;
        });
    }

    fn fetch_detail(&self, server: u128, instance: u128) {
        let Some(endpoint) = self.endpoint(server) else { return };
        let tx = self.events_tx.clone();
        tokio::spawn(async move {
            let detail = net::check(&endpoint, instance).await.map_err(|e| e.to_string());
            let _ = tx.send(AppEvent::Detail { server, instance, result: detail }).await;

            let console = net::tail_console(&endpoint, instance, CONSOLE_TAIL).await
                .map_err(|e| e.to_string());
            let _ = tx.send(AppEvent::Console { server, instance, result: console }).await;
        });
    }

    fn open_manage(&mut self, server: u128, instance: u128) {
        self.screens.push(Screen::Manage(Manage::new(server, instance)));
        self.fetch_detail(server, instance);
    }

    fn pop_screen(&mut self) {
        if self.screens.len() > 1 {
            self.screens.pop();
        } else {
            self.should_quit = true;
        }
    }

    pub fn on_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Snapshot { server, result } => {
                if let Some(state) = self.states.get_mut(&server) {
                    state.apply(result);
                }
                self.clamp_cursor();
                self.sync_manage(server);
                self.check_version(server);
                self.offer_bootstrap(server);
            }
            AppEvent::Detail { server, instance, result } => {
                // A late reply for an instance we have since navigated away
                // from must not overwrite the current one.
                if let Some(Screen::Manage(m)) = self.screens.last_mut()
                    && m.server == server && m.instance == instance {
                    match result {
                        Ok(detail) => {
                            m.detail = Some(detail);
                            m.detail_error = None;
                        }
                        Err(e) => m.detail_error = Some(e),
                    }
                }
            }
            AppEvent::Console { server, instance, result } => {
                if let Some(Screen::Manage(m)) = self.screens.last_mut()
                    && m.server == server && m.instance == instance {
                    match result {
                        Ok((lines, dropped)) => {
                            // Scrolled back: hold position against the new
                            // lines that arrived below, so reading does not
                            // get yanked around by a chatty instance.
                            if !m.following() {
                                // `dropped + len` is the absolute stream
                                // position; raw lengths stop growing once the
                                // ring buffer is full and would let the view
                                // drift.
                                let grew = (dropped + lines.len() as u64)
                                    .saturating_sub(m.console_dropped + m.console.len() as u64);
                                m.console_scroll = m.console_scroll
                                    .saturating_add(grew as usize)
                                    .min(lines.len());
                            }
                            m.console = lines;
                            m.console_dropped = dropped;
                            m.console_error = None;
                        }
                        Err(e) => m.console_error = Some(e),
                    }
                }
            }
            AppEvent::ActionDone { desc, result } => match result {
                Ok(()) => self.info(format!("{desc}: ok")),
                Err(e) => self.error(format!("{desc} failed — {e}")),
            },
            AppEvent::LocalDir { path, result } => {
                // Stale guard: only the listing for where the panel is now.
                if let Some(Screen::Browse(b)) = self.screens.last_mut()
                    && b.local.cwd == path {
                    b.local.apply(path, result);
                }
            }
            AppEvent::RemoteDir { server, requested, result } => {
                if let Some(Screen::Browse(b)) = self.screens.last_mut()
                    && b.server == server && b.remote.cwd == requested {
                    match result {
                        Ok((resolved, entries)) => {
                            // Adopt the server's spelling, keeping the floor
                            // comparable when this was the root itself.
                            if b.remote.cwd == b.remote_root {
                                b.remote_root = resolved.clone();
                            }
                            b.remote.apply(resolved, Ok(entries));
                        }
                        Err(e) => b.remote.apply(requested, Err(e)),
                    }
                }
            }
            AppEvent::TransferDone { server, result } => {
                if let Some(Screen::Browse(b)) = self.screens.last_mut()
                    && b.server == server {
                    b.transfer = None;
                    b.local.incoming.clear();
                    b.remote.incoming.clear();
                }
                match result {
                    Ok(desc) => self.info(desc),
                    Err(e) => self.error(format!("transfer failed — {e}")),
                }
                self.browse_refresh();
            }
        }
    }

    /// Keep the manage screen honest when its subject changes underneath it,
    /// and refresh its detail on the same cadence as the poll.
    fn sync_manage(&mut self, server: u128) {
        let Some(m) = self.manage() else { return };
        if m.server != server {
            return;
        }
        let (managed_server, managed_instance) = (m.server, m.instance);

        let gone = self.entry(managed_server).is_none()
            || (self.states.get(&managed_server).is_some_and(|s| s.is_up())
                && !self.instances_of(managed_server).iter().any(|i| i.id == managed_instance));

        if gone {
            self.pop_screen();
            self.error("that instance is no longer on the server");
        } else {
            self.fetch_detail(managed_server, managed_instance);
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return; // Windows also reports Release/Repeat.
        }
        if self.modal.is_some() {
            self.on_key_modal(key);
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
            self.should_quit = true;
            return;
        }
        match self.screen() {
            Screen::Landing => self.on_key_landing(key),
            Screen::Manage(_) => self.on_key_manage(key),
            Screen::Browse(_) => self.on_key_browse(key),
        }
    }

    fn on_key_landing(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('?') => self.modal = Some(Modal::Help),

            KeyCode::Up | KeyCode::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                let len = self.rows().len();
                self.cursor = (self.cursor + 1).min(len.saturating_sub(1));
            }
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.rows().len().saturating_sub(1),

            KeyCode::Enter | KeyCode::Char(' ') => self.activate(),
            KeyCode::Char('a') => self.open_server_form(None),
            KeyCode::Char('n') => self.open_instance_form_for_selection(),
            KeyCode::Char('e') => {
                let target = self.selected_server().map(|i| self.book.servers[i].id);
                match target {
                    Some(id) => self.open_server_form(Some(id)),
                    None => self.error("nothing selected"),
                }
            }
            KeyCode::Char('d') => self.confirm_remove_server(),
            KeyCode::Char('B') => self.request_bootstrap(),
            KeyCode::Char('r') => {
                self.refresh.notify_one();
                self.info("refreshing");
            }
            _ => {}
        }
    }

    fn activate(&mut self) {
        match self.selected_row() {
            Some(Row::Server { server }) => {
                let id = self.book.servers[server].id;
                if let Some(state) = self.states.get_mut(&id) {
                    state.collapsed = !state.collapsed;
                }
                self.clamp_cursor();
            }
            Some(Row::Instance { server, instance }) => {
                let server = self.book.servers[server].id;
                let Some(inst) = self.instances_of(server).get(instance) else { return };
                let id = inst.id;
                self.open_manage(server, id);
            }
            None => {}
        }
    }

    fn on_key_manage(&mut self, key: KeyEvent) {
        let Some(m) = self.manage() else { return };
        let (server, instance) = (m.server, m.instance);

        match key.code {
            KeyCode::Esc | KeyCode::Backspace => self.pop_screen(),
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => self.modal = Some(Modal::Help),

            KeyCode::Up | KeyCode::Char('[') => self.step_instance(-1),
            KeyCode::Down | KeyCode::Char(']') => self.step_instance(1),

            KeyCode::PageUp => self.scroll_console(10),
            KeyCode::PageDown => self.scroll_console(-10),
            KeyCode::End => self.scroll_console(isize::MIN),
            KeyCode::Home => self.scroll_console(isize::MAX),

            KeyCode::Char('r') => self.spawn_action("start", server, Action::RunInstance { id: instance }),
            KeyCode::Char('R') => self.request_restart(),
            KeyCode::Char('x') => self.spawn_action("stop", server, Action::StopInstance { id: instance }),
            KeyCode::Char('u') => self.spawn_action("update repo", server, Action::UpdateRepo { id: instance }),
            KeyCode::Char('k') => self.confirm_kill(server, instance),
            KeyCode::Char('D') => self.confirm_remove_instance(server, instance),
            KeyCode::Char('e') => self.open_instance_form(server, Some(instance)),
            KeyCode::Char('n') => self.open_instance_form(server, None),
            KeyCode::Char('s') => self.request_session(SessionKind::Shell),
            KeyCode::Char('a') => self.request_session(SessionKind::Attach),
            KeyCode::Char('b') => self.open_browse_for_manage(),
            _ => {}
        }
    }

    /// Hand the console over to a shell/attach session on the managed
    /// instance. The run loop returns it to `main`, which owns the terminal.
    fn request_session(&mut self, kind: SessionKind) {
        let Some(m) = self.manage() else { return };
        let (server, instance) = (m.server, m.instance);
        let Some(endpoint) = self.endpoint(server) else { return };
        let label = format!(
            "{}/{}",
            self.entry(server).map(|e| e.name.clone()).unwrap_or_default(),
            self.instance_name(server, instance),
        );
        self.pending_session = Some(SessionRequest { kind, endpoint, instance, label });
    }

    /// `R`: restart. On the self instance that means the whole server, so it
    /// gets a confirm; a normal instance just stops and starts.
    fn request_restart(&mut self) {
        let Some(m) = self.manage() else { return };
        let (server, instance) = (m.server, m.instance);
        let is_self = self.instances_of(server).iter().any(|i| i.id == instance && i.self_managed);
        if !is_self {
            self.spawn_action("restart", server, Action::RestartInstance { id: instance });
            return;
        }
        let name = self.entry(server).map(|e| e.name.clone()).unwrap_or_default();
        self.modal = Some(Modal::Confirm {
            title: "Restart server".to_string(),
            message: format!(
                "Restart '{name}' itself?\n\
                 It hands over to a fresh process; connections drop for a moment.",
            ),
            toggle: None,
            pending: Pending::RestartServer { server, instance },
        });
    }

    fn open_browse_for_manage(&mut self) {
        let Some(m) = self.manage() else { return };
        let (server, instance) = (m.server, m.instance);
        let Some(root) = m.detail.as_ref().map(|d| d.repo_dir.clone()) else {
            self.error("still loading this instance's checkout path — try again in a moment");
            return;
        };
        self.open_browse(server, instance, root);
    }

    pub fn open_browse(&mut self, server: u128, instance: u128, remote_root: PathBuf) {
        let local_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        self.screens.push(Screen::Browse(Browse::new(server, instance, local_cwd.clone(), remote_root.clone())));
        self.fetch_local(local_cwd);
        self.fetch_remote(server, remote_root);
    }

    fn fetch_local(&self, path: PathBuf) {
        let tx = self.events_tx.clone();
        tokio::task::spawn_blocking(move || {
            let result = browse::read_local_dir(&path);
            let _ = tx.blocking_send(AppEvent::LocalDir { path, result });
        });
    }

    fn fetch_remote(&self, server: u128, path: PathBuf) {
        let Some(endpoint) = self.endpoint(server) else { return };
        let tx = self.events_tx.clone();
        tokio::spawn(async move {
            let result = net::list_dir(&endpoint, path.clone()).await.map_err(|e| e.to_string());
            let _ = tx.send(AppEvent::RemoteDir { server, requested: path, result }).await;
        });
    }

    fn on_key_browse(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.pop_screen(),
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => self.modal = Some(Modal::Help),

            KeyCode::Tab => {
                if let Some(b) = self.browse_mut() {
                    b.focus = b.focus.other();
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.browse_move(-1),
            KeyCode::Down | KeyCode::Char('j') => self.browse_move(1),
            KeyCode::Home => self.browse_move(isize::MIN),
            KeyCode::End => self.browse_move(isize::MAX),
            KeyCode::Enter => self.browse_enter(),
            KeyCode::Backspace => self.browse_parent(),
            KeyCode::Char(' ') => {
                if let Some(b) = self.browse_mut() {
                    let focus = b.focus;
                    b.panel_mut(focus).toggle_selected();
                }
            }
            KeyCode::Char('c') | KeyCode::F(5) => self.plan_transfer(),
            KeyCode::Char('r') => self.browse_refresh(),
            _ => {}
        }
    }

    fn browse_move(&mut self, delta: isize) {
        let Some(b) = self.browse_mut() else { return };
        let focus = b.focus;
        let panel = b.panel_mut(focus);
        let len = panel.entries.len();
        if len == 0 {
            return;
        }
        panel.cursor = match delta {
            isize::MIN => 0,
            isize::MAX => len - 1,
            d if d < 0 => panel.cursor.saturating_sub(d.unsigned_abs()),
            d => (panel.cursor + d as usize).min(len - 1),
        };
    }

    fn browse_enter(&mut self) {
        let Some(b) = self.browse_mut() else { return };
        let (focus, server) = (b.focus, b.server);
        let panel = b.panel_mut(focus);
        let Some(entry) = panel.under_cursor() else { return };
        if !entry.is_dir {
            return;
        }
        let next = panel.cwd.join(&entry.name);
        panel.navigate(next.clone());
        match focus {
            Side::Local => self.fetch_local(next),
            Side::Remote => self.fetch_remote(server, next),
        }
    }

    fn browse_parent(&mut self) {
        let Some(b) = self.browse_mut() else { return };
        let (focus, server) = (b.focus, b.server);
        let Some(parent) = b.parent_of(focus) else { return };
        b.panel_mut(focus).navigate(parent.clone());
        match focus {
            Side::Local => self.fetch_local(parent),
            Side::Remote => self.fetch_remote(server, parent),
        }
    }

    fn browse_refresh(&mut self) {
        let Some(b) = self.browse_mut() else { return };
        let server = b.server;
        let (local, remote) = (b.local.cwd.clone(), b.remote.cwd.clone());
        b.local.loading = true;
        b.remote.loading = true;
        self.fetch_local(local);
        self.fetch_remote(server, remote);
    }

    /// Work out what a copy would do and put it up for confirmation.
    fn plan_transfer(&mut self) {
        let Some(b) = self.browse() else { return };
        if b.transfer.is_some() {
            self.error("a transfer is already running");
            return;
        }
        let from = b.focus;
        let src = b.panel(from);
        let names = src.picked();
        if names.is_empty() {
            self.error("nothing selected");
            return;
        }
        let dest = b.panel(from.other());
        let conflicts: Vec<String> = names.iter()
            .filter(|n| dest.entries.iter().any(|e| &&e.name == n))
            .cloned()
            .collect();
        let plan = TransferPlan {
            server: b.server,
            from,
            src_dir: src.cwd.clone(),
            dest_dir: dest.cwd.clone(),
            names,
            conflicts,
        };

        let mut message = format!(
            "Copy {} to the {} directory\n{}?",
            describe(&plan.names), from.other().name(), plan.dest_dir.display(),
        );
        let toggle = (!plan.conflicts.is_empty()).then(|| {
            message.push_str(&format!(
                "\n\nAlready there: {}",
                sample(&plan.conflicts),
            ));
            ConfirmToggle { label: "overwrite them (off: they are skipped)".to_string(), value: false }
        });
        self.modal = Some(Modal::Confirm {
            title: "Copy files".to_string(),
            message,
            toggle,
            pending: Pending::Transfer(plan),
        });
    }

    fn start_transfer(&mut self, plan: TransferPlan, overwrite: bool) {
        let TransferPlan { server, from, src_dir, dest_dir, names, conflicts } = plan;
        let names: Vec<String> = if overwrite {
            names
        } else {
            names.into_iter().filter(|n| !conflicts.contains(n)).collect()
        };
        if names.is_empty() {
            self.info("everything already exists there — nothing copied");
            return;
        }
        let Some(endpoint) = self.endpoint(server) else { return };

        let (progress_tx, progress_rx) = watch::channel((0u64, None));
        let what = describe(&names);
        if let Some(b) = self.browse_mut() {
            b.transfer = Some(Transfer {
                label: format!("{what} → {}", from.other().name()),
                progress: progress_rx,
            });
            b.panel_mut(from.other()).incoming = names.clone();
        }

        let sources: Vec<PathBuf> = names.iter().map(|n| src_dir.join(n)).collect();
        let tx = self.events_tx.clone();
        tokio::spawn(async move {
            let result = match from {
                Side::Local => transfer::upload(&endpoint, sources, dest_dir, progress_tx).await,
                Side::Remote => transfer::download(&endpoint, sources, dest_dir, progress_tx).await,
            };
            let result = result.map(|_| format!("copied {what}")).map_err(|e| format!("{e:#}"));
            let _ = tx.send(AppEvent::TransferDone { server, result }).await;
        });
    }

    /// Positive scrolls back into history; `isize::MIN` returns to following
    fn scroll_console(&mut self, delta: isize) {
        let Some(Screen::Manage(m)) = self.screens.last_mut() else { return };
        let max = m.console.len();
        m.console_scroll = match delta {
            isize::MIN => 0,
            d if d < 0 => m.console_scroll.saturating_sub(d.unsigned_abs()),
            d => (m.console_scroll + d as usize).min(max),
        };
    }

    fn step_instance(&mut self, delta: isize) {
        let Some(m) = self.manage() else { return };
        let (server, current) = (m.server, m.instance);
        let instances = self.instances_of(server);
        if instances.len() < 2 {
            return;
        }
        let Some(at) = instances.iter().position(|i| i.id == current) else { return };
        let len = instances.len() as isize;
        let next = instances[(((at as isize + delta) % len + len) % len) as usize].id;

        if let Some(Screen::Manage(m)) = self.screens.last_mut() {
            *m = Manage::new(server, next);
        }
        self.fetch_detail(server, next);
    }

    fn open_server_form(&mut self, editing: Option<u128>) {
        let existing = editing.and_then(|id| self.book.servers.iter().find(|s| s.id == id));
        let (title, name, addr) = match existing {
            Some(e) => ("Edit server", e.name.clone(), e.addr.to_string()),
            None => ("Add server", String::new(), "127.0.0.1:5000".to_string()),
        };
        let form = Form::new(title, vec![
            Field::text("Name", name).hint("shown in the list"),
            Field::text("Address", addr).hint("host:port"),
        ]);
        self.modal = Some(Modal::ServerForm { form, editing });
    }

    fn open_instance_form_for_selection(&mut self) {
        match self.selected_server() {
            Some(idx) => {
                let server = self.book.servers[idx].id;
                self.open_instance_form(server, None);
            }
            None => self.error("select a server first"),
        }
    }

    fn open_instance_form(&mut self, server: u128, editing: Option<u128>) {
        // Editing needs the full config, which only `CheckInstance` returns.
        let config = editing.and_then(|id| match self.manage() {
            Some(m) if m.instance == id => m.detail.as_ref().map(|d| &d.config),
            _ => None,
        });
        if editing.is_some() && config.is_none() {
            self.error("still loading this instance's configuration — try again in a moment");
            return;
        }
        let upload_desc = config.and_then(|c| match &c.source {
            Source::Upload { desc } => Some(desc.clone()),
            _ => None,
        });
        let form = instance_form::build(config);
        self.modal = Some(Modal::InstanceForm { form, server, editing, upload_desc });
    }

    fn confirm_remove_server(&mut self) {
        let Some(idx) = self.selected_server() else {
            self.error("nothing selected");
            return;
        };
        let entry = &self.book.servers[idx];
        self.modal = Some(Modal::Confirm {
            title: "Remove server".to_string(),
            message: format!(
                "Remove '{}' ({}) from this client?\nThe server itself and its instances are left untouched.",
                entry.name, entry.addr,
            ),
            toggle: None,
            pending: Pending::RemoveServer(entry.id),
        });
    }

    fn confirm_kill(&mut self, server: u128, instance: u128) {
        let name = self.instance_name(server, instance);
        self.modal = Some(Modal::Confirm {
            title: "Kill instance".to_string(),
            message: format!("Kill '{name}' immediately?\nNo grace period — the process tree is terminated outright."),
            toggle: None,
            pending: Pending::KillInstance { server, instance },
        });
    }

    fn confirm_remove_instance(&mut self, server: u128, instance: u128) {
        let name = self.instance_name(server, instance);
        self.modal = Some(Modal::Confirm {
            title: "Remove instance".to_string(),
            message: format!("Remove '{name}' from the server?\nIt is stopped first if it is running."),
            toggle: Some(ConfirmToggle {
                label: "also delete its files on the server".to_string(),
                value: false,
            }),
            pending: Pending::RemoveInstance { server, instance },
        });
    }

    fn instance_name(&self, server: u128, instance: u128) -> String {
        self.instances_of(server).iter()
            .find(|i| i.id == instance)
            .map(|i| i.name.clone())
            .unwrap_or_else(|| format!("{instance:032x}"))
    }

    /// Compare protocol versions once for a freshly added server. A mismatch
    /// warrants a modal — unlike the bootstrap hint below it must not be
    /// missable — but never on top of another one: while something else is
    /// open the server stays in the set and the next poll retries.
    fn check_version(&mut self, server: u128) {
        if !self.version_checks.contains(&server) || self.modal.is_some() {
            return;
        }
        let Some(vitals) = self.states.get(&server).and_then(|s| s.vitals.as_ref()) else { return };
        let theirs = vitals.version;
        self.version_checks.remove(&server);
        if theirs == protocol::VERSION {
            return;
        }
        let name = self.entry(server).map(|e| e.name.clone()).unwrap_or_default();
        let advice = if theirs > protocol::VERSION {
            "The client is older — update this client to manage that server."
        } else {
            "The server is older — update the server before managing it from here."
        };
        self.modal = Some(Modal::Notice {
            title: "Version mismatch".to_string(),
            message: format!(
                "'{name}' speaks protocol version {theirs}, this client version {}.\n{advice}",
                protocol::VERSION,
            ),
        });
    }

    /// Point out bootstrapping once for a freshly added server that supports
    /// it. A toast, deliberately not a modal: a dialog popping up on a poll
    /// event could swallow a keypress meant for the tree.
    fn offer_bootstrap(&mut self, server: u128) {
        if !self.bootstrap_offers.contains(&server) {
            return;
        }
        let Some(vitals) = self.states.get(&server).and_then(|s| s.vitals.as_ref()) else { return };
        self.bootstrap_offers.remove(&server);
        if vitals.bootstrap {
            let name = self.entry(server).map(|e| e.name.clone()).unwrap_or_default();
            self.info(format!("'{name}' supports bootstrapping — press B on it to set that up"));
        }
    }

    /// `B` on the landing screen: confirm-and-bootstrap the selected server.
    fn request_bootstrap(&mut self) {
        let Some(idx) = self.selected_server() else {
            self.error("nothing selected");
            return;
        };
        let entry = &self.book.servers[idx];
        let (server, name) = (entry.id, entry.name.clone());
        let available = self.states.get(&server)
            .and_then(|s| s.vitals.as_ref())
            .is_some_and(|v| v.bootstrap);
        if !available {
            self.error(format!("'{name}' does not offer bootstrapping (not enabled, already done, or unreachable)"));
            return;
        }
        self.modal = Some(Modal::Confirm {
            title: "Bootstrap server".to_string(),
            message: format!(
                "Hand '{name}' over to itself?\n\
                 It records itself as an instance, restarts once, and then \
                 appears in its own instance list.",
            ),
            toggle: None,
            pending: Pending::Bootstrap(server),
        });
    }

    /// What a confirmed modal asked for. `checked` is its toggle, whatever
    /// that meant for the pending action.
    fn confirm_accept(&mut self, pending: Pending, checked: bool) {
        match pending {
            Pending::RemoveServer(id) => {
                let name = self.book.servers.iter().find(|s| s.id == id)
                    .map(|s| s.name.clone()).unwrap_or_default();
                self.remove_server(id);
                self.info(format!("removed '{name}'"));
            }
            Pending::KillInstance { server, instance } => {
                self.spawn_action("kill", server, Action::KillInstance { id: instance });
            }
            Pending::RemoveInstance { server, instance } => {
                // Its screen is about to describe something gone.
                if self.manage().is_some_and(|m| m.instance == instance) {
                    self.pop_screen();
                }
                self.spawn_action(
                    "remove instance", server,
                    Action::RemoveInstance { id: instance, delete_files: checked },
                );
            }
            Pending::Transfer(plan) => self.start_transfer(plan, checked),
            Pending::Bootstrap(server) => {
                self.spawn_action("bootstrap", server, Action::Bootstrap);
            }
            Pending::RestartServer { server, instance } => {
                self.spawn_action("restart server", server, Action::RestartInstance { id: instance });
            }
        }
    }

    fn on_key_modal(&mut self, key: KeyEvent) {
        // Accepting a confirm consumes the modal: a transfer plan moves out.
        if matches!(self.modal, Some(Modal::Confirm { .. }))
            && matches!(key.code, KeyCode::Char('y') | KeyCode::Enter) {
            if let Some(Modal::Confirm { toggle, pending, .. }) = self.modal.take() {
                self.confirm_accept(pending, toggle.is_some_and(|t| t.value));
            }
            return;
        }

        match self.modal.as_mut() {
            Some(Modal::Help) | Some(Modal::Notice { .. }) => self.modal = None,

            Some(Modal::Confirm { toggle, .. }) => match key.code {
                KeyCode::Char(' ') => {
                    if let Some(toggle) = toggle {
                        toggle.value = !toggle.value;
                    }
                }
                KeyCode::Char('n') | KeyCode::Esc => self.modal = None,
                _ => {}
            },

            Some(Modal::ServerForm { form, editing }) => match form.handle_key(key) {
                FormOutcome::Cancel => self.modal = None,
                FormOutcome::Idle => {}
                FormOutcome::Submit => {
                    let name = form.field(0).text_value().trim().to_string();
                    let addr_text = form.field(1).text_value().trim().to_string();
                    let editing = *editing;

                    if name.is_empty() {
                        form.error = Some("a name is required".to_string());
                        return;
                    }
                    let addr = match addr_text.parse::<Target>() {
                        Ok(a) => a,
                        Err(e) => {
                            form.error = Some(format!("'{addr_text}' is not a host:port address ({e})"));
                            return;
                        }
                    };

                    self.modal = None;
                    match editing {
                        Some(id) => {
                            if let Some(entry) = self.book.servers.iter_mut().find(|s| s.id == id) {
                                entry.name = name.clone();
                                // A new address may be a whole different
                                // server, so its version is unknown again.
                                if entry.addr != addr {
                                    self.version_checks.insert(id);
                                }
                                entry.addr = addr;
                            }
                            // Rates from the old address are meaningless now.
                            self.states.insert(id, ServerState::default());
                            self.publish_servers();
                            self.refresh.notify_one();
                            self.info(format!("updated '{name}'"));
                        }
                        None => {
                            self.add_server(name.clone(), addr);
                            self.info(format!("added '{name}' — checking reachability"));
                        }
                    }
                }
            },

            Some(Modal::InstanceForm { form, server, editing, upload_desc }) => match form.handle_key(key) {
                FormOutcome::Cancel => self.modal = None,
                FormOutcome::Idle => {}
                FormOutcome::Submit => {
                    let (server, editing) = (*server, *editing);
                    let parsed = match instance_form::parse(form, upload_desc.as_deref()) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            form.error = Some(e);
                            return;
                        }
                    };
                    self.modal = None;

                    let name = parsed.name.clone();
                    // A fresh local path means content to push after saving.
                    let upload_path = parsed.source.upload_path();
                    match editing {
                        // Every field is sent: the server treats `None` as
                        // "unchanged", and the form always carries the whole
                        // config, so there is nothing to leave out.
                        Some(id) => {
                            let action = Action::UpdateInstance {
                                id,
                                name: Some(parsed.name),
                                source: Some(parsed.source.to_source()),
                                command: Some(parsed.command),
                                args: Some(parsed.args),
                                env: Some(parsed.env),
                                autostart: Some(parsed.autostart),
                                retry_policy: Some(parsed.retry_policy),
                            };
                            match upload_path {
                                None => self.spawn_action(format!("save '{name}'"), server, action),
                                Some(path) => self.spawn_save_and_upload(server, id, name, action, path),
                            }
                        }
                        None => {
                            let Some(endpoint) = self.endpoint(server) else { return };
                            let tx = self.events_tx.clone();
                            let refresh = self.refresh.clone();
                            tokio::spawn(async move {
                                let result = match net::create(&endpoint, parsed).await {
                                    Ok(id) => match upload_path {
                                        Some(path) => transfer::upload_source(&endpoint, id, path).await
                                            .map_err(|e| format!("{e:#}")),
                                        None => Ok(()),
                                    },
                                    Err(e) => Err(e.to_string()),
                                };
                                refresh.notify_one();
                                let _ = tx.send(AppEvent::ActionDone {
                                    desc: format!("create '{name}'"), result,
                                }).await;
                            });
                        }
                    }
                }
            },

            None => {}
        }
    }

    /// Generic over backend and input source so a headless driver can supply
    /// a `TestBackend` and a scripted key stream.
    ///
    /// Borrows rather than consumes: a `Session` return suspends the TUI and
    /// the same app (and event channel) resumes afterwards.
    pub async fn run<B, I>(
        &mut self,
        terminal: &mut Terminal<B>,
        events: &mut mpsc::Receiver<AppEvent>,
        input: &mut I,
    ) -> anyhow::Result<RunOutcome>
    where
        B: Backend,
        B::Error: std::error::Error + Send + Sync + 'static,
        I: Stream<Item = std::io::Result<Event>> + Unpin,
    {
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            if let Some(toast) = &self.toast
                && Instant::now() >= toast.until {
                self.toast = None;
            }
            terminal.draw(|frame| ui::draw(frame, self))?;

            tokio::select! {
                Some(event) = events.recv() => self.on_event(event),
                _ = ticker.tick() => {}
                Some(Ok(event)) = input.next() => {
                    match event {
                        Event::Key(key) => self.on_key(key),
                        // Resize and the rest just need the redraw above.
                        _ => {}
                    }
                }
            }

            if self.should_quit {
                return Ok(RunOutcome::Quit);
            }
            if let Some(request) = self.pending_session.take() {
                return Ok(RunOutcome::Session(request));
            }
        }
    }
}

fn describe(names: &[String]) -> String {
    match names.len() {
        1 => format!("'{}'", names[0]),
        n => format!("{n} items"),
    }
}

fn sample(names: &[String]) -> String {
    let mut text = names.iter().take(4).cloned().collect::<Vec<_>>().join(", ");
    if names.len() > 4 {
        text.push_str(&format!(" (+{} more)", names.len() - 4));
    }
    text
}

/// Poll every known server on an interval, or immediately when nudged
pub fn spawn_poller(
    mut book_rx: watch::Receiver<Book>,
    events_tx: mpsc::Sender<AppEvent>,
    refresh: Arc<Notify>,
) {
    tokio::spawn(async move {
        let inflight: Arc<Mutex<HashSet<u128>>> = Arc::new(Mutex::new(HashSet::new()));
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            let book = book_rx.borrow_and_update().clone();
            for entry in &book.servers {
                if !inflight.lock().unwrap().insert(entry.id) {
                    continue;
                }
                // A keyless endpoint still gets polled, so the landing page
                // says "no key" rather than leaving the row blank forever.
                let endpoint = book.endpoint_or_keyless(entry);
                let id = entry.id;
                let events_tx = events_tx.clone();
                let inflight = inflight.clone();
                tokio::spawn(async move {
                    let result = net::stat(&endpoint).await;
                    inflight.lock().unwrap().remove(&id);
                    let _ = events_tx.send(AppEvent::Snapshot { server: id, result }).await;
                });
            }

            tokio::select! {
                _ = ticker.tick() => {}
                _ = refresh.notified() => {}
            }
        }
    });
}
