//! Rendering. Pure functions of `&App`

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Wrap};

use crate::app::{App, ConfirmToggle, Manage, Modal, Row, Screen, ServerState, ToastKind};
use crate::browse::{Browse, Side};
use crate::form::{FieldKind, Form};
use crate::instance_form;
use protocol::{
    ConsoleLine, DirEntry, InstanceStatResponse, InstanceStatus, RepoState, RetryPolicy, RunState,
    Stream,
};

const ACCENT: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;

pub fn draw(frame: &mut Frame, app: &App) {
    let [header, body, status, keys] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ]).areas(frame.area());

    draw_header(frame, app, header);
    match app.screen() {
        Screen::Landing => {
            draw_tree(frame, app, body);
            draw_keys(frame, keys, LANDING_KEYS);
        }
        Screen::Manage(manage) => {
            draw_manage(frame, app, manage, body);
            draw_keys(frame, keys, MANAGE_KEYS);
        }
        Screen::Browse(browse) => {
            draw_browse(frame, browse, body);
            draw_keys(frame, keys, BROWSE_KEYS);
        }
    }
    draw_status(frame, app, status);

    match &app.modal {
        Some(Modal::Help) => draw_help(frame, app),
        Some(Modal::ServerForm { form, .. }) | Some(Modal::InstanceForm { form, .. }) => draw_form(frame, form),
        Some(Modal::Confirm { title, message, toggle, .. }) => {
            draw_confirm(frame, title, message, toggle.as_ref())
        }
        None => {}
    }
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![
        Span::styled(" container ", Style::new().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
    ];
    match app.screen() {
        Screen::Landing => {
            let up = app.book.servers.iter().filter(|s| app.state_of(s).is_up()).count();
            spans.push(Span::styled(
                format!("{up}/{} servers up", app.book.servers.len()),
                Style::new().fg(DIM),
            ));
        }
        Screen::Manage(m) => {
            let server = app.entry(m.server).map(|e| e.name.clone()).unwrap_or_default();
            spans.push(Span::styled(server, Style::new().fg(DIM)));
            spans.push(Span::styled(" / ", Style::new().fg(DIM)));
            spans.push(Span::styled(
                app.instances_of(m.server).iter().find(|i| i.id == m.instance)
                    .map(|i| i.name.clone())
                    .unwrap_or_else(|| format!("{:032x}", m.instance)),
                Style::new().add_modifier(Modifier::BOLD),
            ));
        }
        Screen::Browse(b) => {
            let server = app.entry(b.server).map(|e| e.name.clone()).unwrap_or_default();
            spans.push(Span::styled(server, Style::new().fg(DIM)));
            spans.push(Span::styled(" / ", Style::new().fg(DIM)));
            spans.push(Span::styled(
                app.instances_of(b.server).iter().find(|i| i.id == b.instance)
                    .map(|i| i.name.clone())
                    .unwrap_or_else(|| format!("{:032x}", b.instance)),
                Style::new().add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(" · files", Style::new().fg(DIM)));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_tree(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(DIM));

    if app.book.servers.is_empty() {
        let empty = Paragraph::new(vec![
            Line::raw(""),
            Line::from("  No servers yet.").style(Style::new().fg(DIM)),
            Line::raw(""),
            Line::from(vec![
                Span::raw("  Press "),
                Span::styled("a", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
                Span::raw(" to add one."),
            ]),
        ]).block(block);
        frame.render_widget(empty, area);
        return;
    }

    let width = area.width.saturating_sub(4) as usize;
    let items: Vec<ListItem> = app.rows().into_iter()
        .map(|row| ListItem::new(render_row(app, row, width)))
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(Style::new().bg(Color::Rgb(38, 42, 52)).add_modifier(Modifier::BOLD));

    let mut state = ListState::default().with_selected(Some(app.cursor));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_row(app: &App, row: Row, width: usize) -> Line<'static> {
    match row {
        Row::Server { server } => {
            let entry = &app.book.servers[server];
            let state = app.state_of(entry);
            let (glyph, glyph_style) = if state.is_up() {
                ("●", Style::new().fg(Color::Green))
            } else {
                ("✗", Style::new().fg(Color::Red))
            };
            let arrow = if state.collapsed { "▸" } else { "▾" };

            let left = format!(" {arrow} {glyph} {}", entry.name);
            let right = server_summary(state, entry.addr.to_string());

            let pad = width.saturating_sub(left.chars().count() + right.chars().count() + 1);
            Line::from(vec![
                Span::styled(format!(" {arrow} "), Style::new().fg(DIM)),
                Span::styled(glyph, glyph_style),
                Span::raw(" "),
                Span::styled(entry.name.clone(), Style::new().add_modifier(Modifier::BOLD)),
                Span::raw(" ".repeat(pad + 1)),
                Span::styled(right, Style::new().fg(DIM)),
            ])
        }
        Row::Instance { server, instance } => {
            let entry = &app.book.servers[server];
            let state = app.state_of(entry);
            let Some(inst) = state.vitals.as_ref().and_then(|v| v.instances.get(instance)) else {
                return Line::raw("");
            };
            let (glyph, label, style) = instance_status(inst);

            // Status starts at a fixed column so a column of instances can be
            // scanned vertically; flush-right would scatter it by name length.
            const NAME_COL: usize = 30;
            let name_len = inst.name.chars().count();
            let pad = NAME_COL.saturating_sub(name_len).max(1);
            Line::from(vec![
                Span::raw("     "),
                Span::styled(glyph, style),
                Span::raw(" "),
                Span::raw(inst.name.clone()),
                Span::raw(" ".repeat(pad)),
                Span::styled(label, style.add_modifier(Modifier::DIM)),
            ])
        }
    }
}

fn server_summary(state: &ServerState, addr: String) -> String {
    match (&state.error, &state.vitals) {
        (None, Some(v)) => format!(
            "{addr}   cpu {:>3.0}%  ram {}/{}  ↓{}/s ↑{}/s",
            v.cpu_usage,
            fmt_bytes(v.total_ram.saturating_sub(v.free_ram)),
            fmt_bytes(v.total_ram),
            fmt_bytes(state.rate_recv as u64),
            fmt_bytes(state.rate_trans as u64),
        ),
        (Some(e), _) => match state.last_ok {
            Some(at) => format!("{addr}   {} · last seen {} ago", e.short(), fmt_ago(at)),
            None => format!("{addr}   {}", e.short()),
        },
        (None, None) => format!("{addr}   connecting…"),
    }
}

/// Glyph, one-line label and colour for an instance, repo state taking
/// precedence: a half-cloned instance cannot meaningfully be "stopped".
fn instance_status(inst: &InstanceStatResponse) -> (&'static str, String, Style) {
    match &inst.repo {
        RepoState::Provisioning => return ("⋯", "cloning…".to_string(), Style::new().fg(ACCENT)),
        RepoState::CloneFailed(e) => return ("✗", format!("clone failed: {}", first_line(e)), Style::new().fg(Color::Red)),
        RepoState::Ready => {}
    }
    match &inst.run {
        RunState::NotRunning => ("■", "stopped".to_string(), Style::new().fg(DIM)),
        RunState::Starting => ("↻", "starting…".to_string(), Style::new().fg(Color::Yellow)),
        RunState::Running { pids, restarts } => {
            let pid = pids.first().map(|p| format!("pid {p}")).unwrap_or_else(|| "no pids".to_string());
            let label = if *restarts > 0 {
                format!("running ({pid}, {restarts} restarts)")
            } else {
                format!("running ({pid})")
            };
            ("▶", label, Style::new().fg(Color::Green))
        }
        RunState::Backoff { delay_ms, restarts } => (
            "↻",
            format!("restarting in {:.1}s ({restarts} restarts)", *delay_ms as f64 / 1000.0),
            Style::new().fg(Color::Yellow),
        ),
        RunState::Exited { code, signal, .. } => match (code, signal) {
            (Some(0), _) => ("■", "exited (0)".to_string(), Style::new().fg(DIM)),
            (Some(c), _) => ("✗", format!("exited ({c})"), Style::new().fg(Color::Red)),
            (None, Some(s)) => ("✗", format!("killed by signal {s}"), Style::new().fg(Color::Red)),
            (None, None) => ("✗", "exited".to_string(), Style::new().fg(Color::Red)),
        },
        RunState::Stopped => ("■", "stopped".to_string(), Style::new().fg(DIM)),
        RunState::Failed(e) => ("✗", format!("failed: {}", first_line(e)), Style::new().fg(Color::Red)),
    }
}

fn draw_manage(frame: &mut Frame, app: &App, manage: &Manage, area: Rect) {
    let [side, main] = Layout::horizontal([Constraint::Length(30), Constraint::Min(20)]).areas(area);
    let [vitals, list] = Layout::vertical([Constraint::Length(8), Constraint::Min(3)]).areas(side);
    // Detail is a fixed shape; give the rest to the console, which is the
    // part you actually sit and watch.
    let [detail, console] = Layout::vertical([Constraint::Length(16), Constraint::Min(4)]).areas(main);

    draw_vitals(frame, app, manage, vitals);
    draw_sidebar_instances(frame, app, manage, list);
    draw_detail(frame, app, manage, detail);
    draw_console(frame, manage, console);
}

fn draw_console(frame: &mut Frame, manage: &Manage, area: Rect) {
    let title = if manage.following() {
        " console ".to_string()
    } else {
        format!(" console · scrolled back {} ", manage.console_scroll)
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if manage.following() { DIM } else { ACCENT }))
        .title(Span::styled(title, Style::new().fg(if manage.following() { DIM } else { ACCENT })));

    if let Some(e) = &manage.console_error {
        let text = Paragraph::new(Line::styled(format!("no console: {e}"), Style::new().fg(Color::Red)));
        frame.render_widget(text.block(block), area);
        return;
    }

    // Two rows of border, and one for the "discarded" note when there is one.
    let rows = area.height.saturating_sub(2) as usize;
    let note = (manage.console_dropped > 0).then(|| {
        Line::styled(
            format!("… {} earlier lines discarded", manage.console_dropped),
            Style::new().fg(DIM).add_modifier(Modifier::ITALIC),
        )
    });
    let capacity = rows.saturating_sub(note.is_some() as usize);

    // `console_scroll` counts lines back from the newest.
    let end = manage.console.len().saturating_sub(manage.console_scroll);
    let start = end.saturating_sub(capacity);

    let mut lines: Vec<Line> = note.into_iter().collect();
    if manage.console.is_empty() {
        lines.push(Line::styled("no output yet", Style::new().fg(DIM)));
    }
    lines.extend(manage.console[start..end].iter().map(console_line));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn console_line(line: &ConsoleLine) -> Line<'static> {
    let style = match line.stream {
        Stream::Stdout => Style::new(),
        Stream::Stderr => Style::new().fg(Color::Red),
    };
    Line::from(vec![
        Span::styled(format!("{} ", fmt_clock(line.at_ms)), Style::new().fg(DIM)),
        Span::styled(line.text.clone(), style),
    ])
}

/// `hh:mm:ss` **UTC** from a unix-epoch millisecond stamp — done by hand,
/// since the client has no date library and only needs a time of day. It is
/// the server's stamp, so a local-time conversion here would be a guess.
fn fmt_clock(at_ms: u64) -> String {
    let secs = at_ms / 1000 % 86_400;
    format!("{:02}:{:02}:{:02}", secs / 3600, secs % 3600 / 60, secs % 60)
}

fn draw_vitals(frame: &mut Frame, app: &App, manage: &Manage, area: Rect) {
    let name = app.entry(manage.server).map(|e| e.name.clone()).unwrap_or_default();
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(DIM))
        .title(Span::styled(format!(" {name} "), Style::new().add_modifier(Modifier::BOLD)));

    let Some(state) = app.states.get(&manage.server) else {
        frame.render_widget(block, area);
        return;
    };

    let lines = match (&state.error, &state.vitals) {
        (_, Some(v)) => {
            let ram_used = v.total_ram.saturating_sub(v.free_ram);
            let stg_used = v.total_stg.saturating_sub(v.free_stg);
            let mut lines = vec![
                meter("cpu", v.cpu_usage / 100.0, format!("{:.0}%", v.cpu_usage)),
                meter("ram", ratio(ram_used, v.total_ram), format!("{}/{}", fmt_bytes(ram_used), fmt_bytes(v.total_ram))),
                meter("dsk", ratio(stg_used, v.total_stg), format!("{}/{}", fmt_bytes(stg_used), fmt_bytes(v.total_stg))),
                Line::from(vec![
                    Span::styled("net  ", Style::new().fg(DIM)),
                    Span::raw(format!("↓{}/s ↑{}/s", fmt_bytes(state.rate_recv as u64), fmt_bytes(state.rate_trans as u64))),
                ]),
            ];
            if state.error.is_some() {
                lines.push(Line::styled("stale — server unreachable", Style::new().fg(Color::Red)));
            }
            lines
        }
        (Some(e), None) => vec![Line::styled(e.short(), Style::new().fg(Color::Red))],
        (None, None) => vec![Line::styled("connecting…", Style::new().fg(DIM))],
    };

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn ratio(used: u64, total: u64) -> f64 {
    if total == 0 { 0.0 } else { used as f64 / total as f64 }
}

/// A labelled text bar. Drawn as text rather than as a `Gauge` so the label,
/// bar and figure stay on one line at this width.
fn meter(label: &str, ratio: f64, value: String) -> Line<'static> {
    const WIDTH: usize = 8;
    let filled = (ratio.clamp(0.0, 1.0) * WIDTH as f64).round() as usize;
    let color = match ratio {
        r if r >= 0.9 => Color::Red,
        r if r >= 0.75 => Color::Yellow,
        _ => Color::Green,
    };
    Line::from(vec![
        Span::styled(format!("{label:<5}"), Style::new().fg(DIM)),
        Span::styled("▓".repeat(filled), Style::new().fg(color)),
        Span::styled("░".repeat(WIDTH - filled), Style::new().fg(DIM)),
        Span::raw(format!(" {value}")),
    ])
}

fn draw_sidebar_instances(frame: &mut Frame, app: &App, manage: &Manage, area: Rect) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(DIM))
        .title(Span::styled(" instances ", Style::new().fg(DIM)));

    let instances = app.instances_of(manage.server);
    let items: Vec<ListItem> = instances.iter()
        .map(|inst| {
            let (glyph, _, style) = instance_status(inst);
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {glyph} "), style),
                Span::raw(inst.name.clone()),
            ]))
        })
        .collect();

    let selected = instances.iter().position(|i| i.id == manage.instance);
    let list = List::new(items)
        .block(block)
        .highlight_style(Style::new().bg(Color::Rgb(38, 42, 52)).add_modifier(Modifier::BOLD));
    let mut state = ListState::default().with_selected(selected);
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_detail(frame: &mut Frame, app: &App, manage: &Manage, area: Rect) {
    let name = app.instances_of(manage.server).iter()
        .find(|i| i.id == manage.instance)
        .map(|i| i.name.clone())
        .unwrap_or_else(|| format!("{:032x}", manage.instance));

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(DIM))
        .title(Span::styled(format!(" {name} "), Style::new().add_modifier(Modifier::BOLD)));

    let lines = match (&manage.detail, &manage.detail_error) {
        (Some(detail), _) => detail_lines(app, manage, detail),
        (None, Some(e)) => vec![Line::styled(format!("could not read this instance: {e}"), Style::new().fg(Color::Red))],
        (None, None) => vec![Line::styled("loading…", Style::new().fg(DIM))],
    };

    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
}

fn detail_lines(app: &App, manage: &Manage, detail: &InstanceStatus) -> Vec<Line<'static>> {
    let config = &detail.config;
    let mut lines = Vec::new();

    let branch = config.branch.clone().unwrap_or_else(|| "default branch".to_string());
    lines.push(field("repo", format!("{} ({branch})", config.repo_url)));

    let (repo_label, repo_style) = match &detail.repo {
        RepoState::Ready => ("ready".to_string(), Style::new().fg(Color::Green)),
        RepoState::Provisioning => ("cloning…".to_string(), Style::new().fg(ACCENT)),
        RepoState::CloneFailed(e) => (format!("clone failed: {e}"), Style::new().fg(Color::Red)),
    };
    lines.push(styled_field("checkout", repo_label, repo_style));

    let command = if config.args.is_empty() {
        config.command.clone()
    } else {
        format!("{} {}", config.command, instance_form::fmt_args(&config.args))
    };
    lines.push(field("command", command));

    let (glyph, run_label, run_style) = run_summary(&detail.run);
    lines.push(styled_field("state", format!("{glyph} {run_label}"), run_style));

    if let RunState::Running { pids, .. } = &detail.run
        && !pids.is_empty() {
        lines.push(field("pids", pids.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")));
    }

    if let Some(stats) = &detail.stats {
        let cpu = stats.cpu_time_ms.map(|ms| format!(" · cpu {:.1}s", ms as f64 / 1000.0)).unwrap_or_default();
        let mem = stats.peak_memory_bytes.map(|b| format!(" · peak {}", fmt_bytes(b))).unwrap_or_default();
        lines.push(field("usage", format!("{} processes{cpu}{mem}", stats.processes)));
    }

    let policy = match &config.retry_policy {
        RetryPolicy::Never => "never restart".to_string(),
        RetryPolicy::OnCrash => "restart on crash".to_string(),
        RetryPolicy::Always => "always restart".to_string(),
        RetryPolicy::Retry(n) => format!("restart up to {n}×"),
    };
    let autostart = if config.autostart { "autostart on" } else { "autostart off" };
    lines.push(field("policy", format!("{policy} · {autostart}")));

    if !config.env.is_empty() {
        lines.push(field("env", instance_form::fmt_env(&config.env)));
    }

    let label = format!(
        "{}/{}",
        app.entry(manage.server).map(|e| e.name.clone()).unwrap_or_default(),
        config.name,
    );
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("terminals — ", Style::new().fg(DIM)),
        Span::styled("s", Style::new().fg(ACCENT)),
        Span::styled(" shell · ", Style::new().fg(DIM)),
        Span::styled("a", Style::new().fg(ACCENT)),
        Span::styled(" attach, or from another console:", Style::new().fg(DIM)),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(format!("client shell {label}"), Style::new().fg(ACCENT)),
        Span::styled("    new shell in the checkout", Style::new().fg(DIM)),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(format!("client attach {label}"), Style::new().fg(ACCENT)),
        Span::styled("   the running process", Style::new().fg(DIM)),
    ]));

    // Last: it is the one field long enough to wrap, and wrapping here
    // cannot shove anything more useful down the pane.
    lines.push(Line::raw(""));
    lines.push(field("dir", detail.repo_dir.display().to_string()));

    lines
}

fn field(label: &str, value: String) -> Line<'static> {
    styled_field(label, value, Style::new())
}

fn styled_field(label: &str, value: String, style: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<10}"), Style::new().fg(DIM)),
        Span::styled(value, style),
    ])
}

fn run_summary(run: &RunState) -> (&'static str, String, Style) {
    match run {
        RunState::NotRunning => ("■", "not running".to_string(), Style::new().fg(DIM)),
        RunState::Starting => ("↻", "starting…".to_string(), Style::new().fg(Color::Yellow)),
        RunState::Running { restarts, .. } => {
            let label = if *restarts > 0 {
                format!("running after {restarts} restarts")
            } else {
                "running".to_string()
            };
            ("▶", label, Style::new().fg(Color::Green))
        }
        RunState::Backoff { delay_ms, restarts } => (
            "↻",
            format!("restarting in {:.1}s ({restarts} restarts)", *delay_ms as f64 / 1000.0),
            Style::new().fg(Color::Yellow),
        ),
        RunState::Exited { code, signal, restarts } => {
            let how = match (code, signal) {
                (Some(0), _) => "exited cleanly".to_string(),
                (Some(c), _) => format!("exited with code {c}"),
                (None, Some(s)) => format!("killed by signal {s}"),
                (None, None) => "exited".to_string(),
            };
            let style = if matches!(code, Some(0)) { Style::new().fg(DIM) } else { Style::new().fg(Color::Red) };
            let glyph = if matches!(code, Some(0)) { "■" } else { "✗" };
            (glyph, format!("{how} after {restarts} restarts"), style)
        }
        RunState::Stopped => ("■", "stopped".to_string(), Style::new().fg(DIM)),
        RunState::Failed(e) => ("✗", format!("failed to start: {e}"), Style::new().fg(Color::Red)),
    }
}

fn draw_browse(frame: &mut Frame, browse: &Browse, area: Rect) {
    let [panes, foot] = Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(area);
    let [left, right] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(panes);
    draw_panel(frame, browse, Side::Local, left);
    draw_panel(frame, browse, Side::Remote, right);
    draw_transfer(frame, browse, foot);
}

fn draw_panel(frame: &mut Frame, browse: &Browse, side: Side, area: Rect) {
    let panel = browse.panel(side);
    let focused = browse.focus == side;
    let color = if focused { ACCENT } else { DIM };

    let mut title = format!(" {} · {} ", side.name(), shorten_path(&panel.cwd, area.width.saturating_sub(14) as usize));
    if panel.loading {
        title.push_str("… ");
    }
    let mut block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(color))
        .title(Span::styled(title, Style::new().fg(color).add_modifier(if focused { Modifier::BOLD } else { Modifier::empty() })));
    if !panel.selected.is_empty() {
        block = block.title_bottom(Span::styled(
            format!(" {} marked ", panel.selected.len()),
            Style::new().fg(ACCENT),
        ));
    }

    if let Some(e) = &panel.error {
        let text = Paragraph::new(Line::styled(first_line(e), Style::new().fg(Color::Red)))
            .block(block)
            .wrap(Wrap { trim: false });
        frame.render_widget(text, area);
        return;
    }

    let width = area.width.saturating_sub(4) as usize;
    let mut items: Vec<ListItem> = panel.entries.iter()
        .map(|entry| ListItem::new(panel_row(entry, panel.selected.contains(&entry.name), width)))
        .collect();
    // Ghosts of an incoming copy, until the refresh delivers the real thing.
    for name in &panel.incoming {
        if !panel.entries.iter().any(|e| &e.name == name) {
            items.push(ListItem::new(Line::styled(
                format!("⇣ {name}"),
                Style::new().fg(DIM).add_modifier(Modifier::ITALIC),
            )));
        }
    }
    if items.is_empty() {
        items.push(ListItem::new(Line::styled(
            if panel.loading { "loading…" } else { "empty" },
            Style::new().fg(DIM),
        )));
    }

    let list = List::new(items)
        .block(block)
        .highlight_style(Style::new().bg(Color::Rgb(38, 42, 52)).add_modifier(Modifier::BOLD));
    let mut state = ListState::default()
        .with_selected((focused && !panel.entries.is_empty()).then_some(panel.cursor));
    frame.render_stateful_widget(list, area, &mut state);
}

fn panel_row(entry: &DirEntry, marked: bool, width: usize) -> Line<'static> {
    let marker = if marked { "▪" } else { " " };
    let name = if entry.is_dir { format!("{}/", entry.name) } else { entry.name.clone() };
    let size = if entry.is_dir { String::new() } else { fmt_bytes(entry.size) };
    let pad = width.saturating_sub(2 + name.chars().count() + size.chars().count()).max(1);
    Line::from(vec![
        Span::styled(format!("{marker} "), Style::new().fg(ACCENT)),
        Span::styled(name, if entry.is_dir { Style::new().fg(ACCENT) } else { Style::new() }),
        Span::raw(" ".repeat(pad)),
        Span::styled(size, Style::new().fg(DIM)),
    ])
}

fn draw_transfer(frame: &mut Frame, browse: &Browse, area: Rect) {
    let Some(transfer) = &browse.transfer else {
        let hint = Line::styled(
            " tab switches panels · space marks · c copies to the other panel",
            Style::new().fg(DIM),
        );
        frame.render_widget(Paragraph::new(hint), area);
        return;
    };

    let (done, total) = *transfer.progress.borrow();
    let line = match total {
        Some(total) if total > 0 => {
            const WIDTH: usize = 24;
            let ratio = (done as f64 / total as f64).clamp(0.0, 1.0);
            let filled = (ratio * WIDTH as f64).round() as usize;
            let tail = if done >= total {
                "unpacking…".to_string()
            } else {
                format!("{}/{}", fmt_bytes(done), fmt_bytes(total))
            };
            Line::from(vec![
                Span::styled(format!(" {}  ", transfer.label), Style::new().fg(ACCENT)),
                Span::styled("▓".repeat(filled), Style::new().fg(ACCENT)),
                Span::styled("░".repeat(WIDTH - filled), Style::new().fg(DIM)),
                Span::raw(format!(" {:>3.0}%  {tail}", ratio * 100.0)),
            ])
        }
        _ => Line::styled(format!(" {}  packing…", transfer.label), Style::new().fg(ACCENT)),
    };
    frame.render_widget(Paragraph::new(line), area);
}

/// Keep the tail of a long path; the head is the least informative part.
fn shorten_path(path: &std::path::Path, max: usize) -> String {
    let text = path.display().to_string();
    let count = text.chars().count();
    if count <= max.max(8) {
        return text;
    }
    let keep = max.max(8) - 1;
    format!("…{}", text.chars().skip(count - keep).collect::<String>())
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let line = match &app.toast {
        Some(toast) => {
            let (marker, color) = match toast.kind {
                ToastKind::Info => ("·", ACCENT),
                ToastKind::Error => ("!", Color::Red),
            };
            Line::from(vec![
                Span::styled(format!(" {marker} "), Style::new().fg(color).add_modifier(Modifier::BOLD)),
                Span::styled(toast.text.replace('\n', " "), Style::new().fg(color)),
            ])
        }
        None => Line::raw(""),
    };
    frame.render_widget(Paragraph::new(line), area);
}

const LANDING_KEYS: &[(&str, &str)] = &[
    ("↑↓", "move"), ("enter", "open"), ("a", "add server"), ("n", "new instance"),
    ("e", "edit"), ("d", "remove"), ("r", "refresh"), ("?", "help"), ("q", "quit"),
];

const MANAGE_KEYS: &[(&str, &str)] = &[
    ("↑↓", "instance"), ("pgup/pgdn", "console"), ("r", "start"), ("x", "stop"),
    ("k", "kill"), ("u", "update repo"), ("s", "shell"), ("a", "attach"),
    ("b", "files"), ("e", "edit"), ("D", "remove"), ("?", "help"), ("esc", "back"),
];

const BROWSE_KEYS: &[(&str, &str)] = &[
    ("tab", "panel"), ("↑↓", "move"), ("enter", "open"), ("bksp", "up"),
    ("space", "mark"), ("c", "copy"), ("r", "reload"), ("?", "help"), ("esc", "back"),
];

fn draw_keys(frame: &mut Frame, area: Rect, keys: &[(&str, &str)]) {
    let mut spans = vec![Span::raw(" ")];
    for (key, label) in keys.iter().copied() {
        spans.push(Span::styled(key, Style::new().fg(ACCENT)));
        spans.push(Span::styled(format!(" {label}   "), Style::new().fg(DIM)));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn modal_area(frame: &Frame, width: u16, height: u16) -> Rect {
    let area = frame.area();
    let [area] = Layout::horizontal([Constraint::Length(width.min(area.width))])
        .flex(Flex::Center).areas(area);
    let [area] = Layout::vertical([Constraint::Length(height.min(area.height))])
        .flex(Flex::Center).areas(area);
    area
}

fn modal_block(title: &str) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(ACCENT))
        .title(Span::styled(format!(" {title} "), Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)))
}

fn draw_form(frame: &mut Frame, form: &Form) {
    let height = form.fields.len() as u16 * 2 + 5;
    let area = modal_area(frame, 64, height);
    frame.render_widget(Clear, area);
    frame.render_widget(modal_block(&form.title), area);

    let inner = area.inner(ratatui::layout::Margin::new(2, 1));
    let mut lines: Vec<Line> = Vec::new();
    for (i, field) in form.fields.iter().enumerate() {
        let focused = i == form.focus;
        let label_style = if focused {
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(DIM)
        };
        let mut label = vec![Span::styled(field.label.clone(), label_style)];
        if let Some(hint) = &field.hint {
            label.push(Span::styled(format!("  {hint}"), Style::new().fg(DIM)));
        }
        lines.push(Line::from(label));

        let value = match &field.kind {
            // A block cursor drawn in-line: the real cursor stays hidden, so
            // it cannot disagree with what the modal shows.
            FieldKind::Text { value, cursor } => {
                let text: String = value.iter().collect();
                if focused {
                    let (before, after) = text.split_at(
                        value.iter().take(*cursor).map(|c| c.len_utf8()).sum(),
                    );
                    let (at, rest) = match after.chars().next() {
                        Some(c) => (c.to_string(), &after[c.len_utf8()..]),
                        None => (" ".to_string(), ""),
                    };
                    Line::from(vec![
                        Span::raw(before.to_string()),
                        Span::styled(at, Style::new().add_modifier(Modifier::REVERSED)),
                        Span::raw(rest.to_string()),
                    ])
                } else {
                    Line::raw(text)
                }
            }
            FieldKind::Toggle(b) => Line::from(vec![
                Span::styled(if *b { "[x] yes" } else { "[ ] no" },
                    if *b { Style::new().fg(Color::Green) } else { Style::new().fg(DIM) }),
                Span::styled("   space toggles", Style::new().fg(DIM)),
            ]),
            FieldKind::Select { options, index } => {
                let mut spans = Vec::new();
                for (n, opt) in options.iter().enumerate() {
                    let style = if n == *index {
                        Style::new().fg(Color::Black).bg(ACCENT)
                    } else {
                        Style::new().fg(DIM)
                    };
                    spans.push(Span::styled(format!(" {opt} "), style));
                    spans.push(Span::raw(" "));
                }
                Line::from(spans)
            }
        };
        lines.push(value);
    }

    lines.push(Line::raw(""));
    lines.push(match &form.error {
        Some(e) => Line::styled(e.clone(), Style::new().fg(Color::Red)),
        None => Line::styled("tab/↑↓ field   enter save   esc cancel", Style::new().fg(DIM)),
    });

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn draw_confirm(frame: &mut Frame, title: &str, message: &str, toggle: Option<&ConfirmToggle>) {
    let height = message.lines().count() as u16 + if toggle.is_some() { 7 } else { 5 };
    let area = modal_area(frame, 66, height);
    frame.render_widget(Clear, area);
    frame.render_widget(modal_block(title), area);

    let inner = area.inner(ratatui::layout::Margin::new(2, 1));
    let mut lines: Vec<Line> = message.lines().map(Line::raw).collect();

    if let Some(toggle) = toggle {
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled(
                if toggle.value { "[x] " } else { "[ ] " },
                if toggle.value { Style::new().fg(Color::Red) } else { Style::new().fg(DIM) },
            ),
            Span::raw(toggle.label.clone()),
            Span::styled("   (space)", Style::new().fg(DIM)),
        ]));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("y", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled(" confirm    ", Style::new().fg(DIM)),
        Span::styled("n/esc", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled(" cancel", Style::new().fg(DIM)),
    ]));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn draw_help(frame: &mut Frame, app: &App) {
    let entries: &[(&str, &str)] = match app.screen() {
        Screen::Landing => &[
            ("↑ ↓ / k j", "move the cursor"),
            ("enter / space", "expand or collapse a server; open an instance"),
            ("a", "add a server"),
            ("n", "create an instance on the selected server"),
            ("e", "edit the selected server"),
            ("d", "remove the selected server from this client"),
            ("r", "poll every server now"),
            ("q / esc", "quit"),
        ],
        Screen::Manage(_) => &[
            ("↑ ↓ / [ ]", "switch instance on this server"),
            ("pgup / pgdn", "scroll the console"),
            ("home / end", "oldest line / back to following"),
            ("r", "start"),
            ("x", "stop, with a grace period"),
            ("k", "kill, no grace period"),
            ("u", "re-clone the repo — the instance must be stopped"),
            ("s", "open a shell in the checkout (the TUI steps aside)"),
            ("a", "attach to the running process (the TUI steps aside)"),
            ("b", "browse files — copy between here and the checkout"),
            ("e", "edit this instance's configuration"),
            ("n", "create another instance on this server"),
            ("D", "remove this instance from the server"),
            ("esc", "back to the server list"),
        ],
        Screen::Browse(_) => &[
            ("tab", "switch between the local and remote panel"),
            ("↑ ↓ / k j", "move the cursor"),
            ("enter", "open the directory under the cursor"),
            ("backspace", "go to the parent directory"),
            ("space", "mark / unmark the entry under the cursor"),
            ("c / F5", "copy the marked entries into the other panel"),
            ("r", "reload both panels"),
            ("esc", "back"),
        ],
    };

    let footer: &[&str] = match app.screen() {
        Screen::Landing => &["Servers are polled every 2s."],
        Screen::Manage(_) => &[
            "Terminals also run as commands in another console:",
            "  client shell <server>/<instance>    a new shell in the checkout",
            "  client attach <server>/<instance>   the running process",
            "Ctrl+C ends a session; an attached instance keeps running.",
        ],
        Screen::Browse(_) => &[
            "With nothing marked, c copies the entry under the cursor.",
            "Copies are packed, streamed, then unpacked; existing files",
            "prompt for overwrite-or-skip before anything moves.",
        ],
    };

    let area = modal_area(frame, 76, (entries.len() + footer.len()) as u16 + 6);
    frame.render_widget(Clear, area);
    frame.render_widget(modal_block("Keys"), area);

    let inner = area.inner(ratatui::layout::Margin::new(2, 1));
    let mut lines: Vec<Line> = entries.iter()
        .map(|(key, what)| Line::from(vec![
            Span::styled(format!("{key:<16}"), Style::new().fg(ACCENT)),
            Span::raw(*what),
        ]))
        .collect();
    lines.push(Line::raw(""));
    for line in footer {
        lines.push(Line::styled(*line, Style::new().fg(DIM)));
    }
    lines.push(Line::styled("any key closes this", Style::new().fg(DIM)));
    frame.render_widget(Paragraph::new(lines), inner);
}

pub fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{}{}", bytes, UNITS[0])
    } else if value < 10.0 {
        format!("{value:.1}{}", UNITS[unit])
    } else {
        format!("{value:.0}{}", UNITS[unit])
    }
}

fn fmt_ago(at: Instant) -> String {
    let secs = Instant::now().duration_since(at).as_secs();
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        _ => format!("{}h", secs / 3600),
    }
}

fn first_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or("").trim();
    if line.chars().count() > 60 {
        format!("{}…", line.chars().take(59).collect::<String>())
    } else {
        line.to_string()
    }
}
