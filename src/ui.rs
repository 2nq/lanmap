use std::cmp::Ordering;
use std::io::stdout;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::{
    cursor::Show,
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};

use crate::scanner::{HostInfo, ScanState, RESCAN_INTERVAL};

const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
// How long a newly-joined device keeps its "new" badge.
const NEW_BADGE_TTL: Duration = Duration::from_secs(300);
// How long a transient status line (e.g. "exported…") stays on screen.
const STATUS_TTL: Duration = Duration::from_secs(4);

#[derive(Clone, Copy, PartialEq)]
enum SortMode {
    Ip,
    Latency,
    Hostname,
    LastSeen,
}

impl SortMode {
    fn label(self) -> &'static str {
        match self {
            SortMode::Ip => "IP",
            SortMode::Latency => "latency",
            SortMode::Hostname => "hostname",
            SortMode::LastSeen => "last seen",
        }
    }

    fn next(self) -> SortMode {
        match self {
            SortMode::Ip => SortMode::Latency,
            SortMode::Latency => SortMode::Hostname,
            SortMode::Hostname => SortMode::LastSeen,
            SortMode::LastSeen => SortMode::Ip,
        }
    }
}

/// The host rows to actually display, after filtering and sorting. IP is the
/// tiebreaker for every mode so the order is stable frame-to-frame.
fn visible_hosts(state: &ScanState, sort: SortMode, online_only: bool) -> Vec<&HostInfo> {
    let mut v: Vec<&HostInfo> = state
        .hosts
        .iter()
        .filter(|h| !online_only || h.online)
        .collect();

    let by_ip = |h: &&HostInfo| u32::from(h.ip);
    match sort {
        SortMode::Ip => v.sort_by_key(by_ip),
        SortMode::Latency => v.sort_by(|a, b| {
            // Unreachable hosts (no latency) sort last.
            let ka = a.latency_ms.unwrap_or(f64::INFINITY);
            let kb = b.latency_ms.unwrap_or(f64::INFINITY);
            ka.partial_cmp(&kb)
                .unwrap_or(Ordering::Equal)
                .then_with(|| by_ip(a).cmp(&by_ip(b)))
        }),
        // Hosts without a hostname sort last.
        SortMode::Hostname => v.sort_by_cached_key(|h| {
            (
                h.hostname.is_none(),
                h.hostname.clone().unwrap_or_default().to_lowercase(),
                u32::from(h.ip),
            )
        }),
        // Most recently seen first.
        SortMode::LastSeen => v.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| by_ip(a).cmp(&by_ip(b)))
        }),
    }
    v
}

pub struct App {
    pub state: Arc<Mutex<ScanState>>,
    pub table_state: TableState,
    pub spinner_frame: usize,
    pub last_tick: Instant,
    sort_mode: SortMode,
    online_only: bool,
    status: Option<(String, Instant)>,
}

impl App {
    pub fn new(state: Arc<Mutex<ScanState>>) -> Self {
        Self {
            state,
            table_state: TableState::default(),
            spinner_frame: 0,
            last_tick: Instant::now(),
            sort_mode: SortMode::Ip,
            online_only: false,
            status: None,
        }
    }

    /// Keep the selection within the visible list after filtering/sorting.
    fn clamp_selection(&mut self, len: usize) {
        match self.table_state.selected() {
            Some(_) if len == 0 => self.table_state.select(None),
            Some(i) if i >= len => self.table_state.select(Some(len - 1)),
            _ => {}
        }
    }

    fn export(&mut self) {
        let msg = {
            let state = self.state.lock().unwrap();
            write_export(&state)
        };
        self.status = Some((msg, Instant::now()));
    }

    fn next_row(&mut self, len: usize) {
        if len == 0 {
            return;
        }
        let i = self
            .table_state
            .selected()
            .map_or(0, |i| (i + 1).min(len - 1));
        self.table_state.select(Some(i));
    }

    fn prev_row(&mut self, len: usize) {
        if len == 0 {
            return;
        }
        let i = self
            .table_state
            .selected()
            .map_or(0, |i| i.saturating_sub(1));
        self.table_state.select(Some(i));
    }
}

pub fn run(state: Arc<Mutex<ScanState>>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;

    // Restore the terminal even if the UI loop errors or panics — a broken
    // raw-mode terminal would otherwise swallow the error message itself.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        original_hook(info);
    }));

    let result = run_loop(state);
    restore_terminal();
    result
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen, Show);
}

fn run_loop(state: Arc<Mutex<ScanState>>) -> anyhow::Result<()> {
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;

    let mut app = App::new(state);

    loop {
        if app.last_tick.elapsed() >= Duration::from_millis(80) {
            app.spinner_frame = (app.spinner_frame + 1) % SPINNER.len();
            app.last_tick = Instant::now();
        }

        let visible_count = {
            let state = app.state.lock().unwrap();
            visible_hosts(&state, app.sort_mode, app.online_only).len()
        };
        app.clamp_selection(visible_count);

        terminal.draw(|f| render(f, &mut app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('r') => {
                        app.state.lock().unwrap().rescan_requested = true;
                    }
                    KeyCode::Char('e') => app.export(),
                    KeyCode::Char('s') => app.sort_mode = app.sort_mode.next(),
                    KeyCode::Char('f') => app.online_only = !app.online_only,
                    KeyCode::Down | KeyCode::Char('j') => app.next_row(visible_count),
                    KeyCode::Up | KeyCode::Char('k') => app.prev_row(visible_count),
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

/// Write the current scan to `lanmap-<unixtime>.json` in the working directory.
/// Returns a human-readable result for the status line.
fn write_export(state: &ScanState) -> String {
    let json = match crate::scanner::export_json(state) {
        Ok(j) => j,
        Err(e) => return format!("export failed: {}", e),
    };
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = format!("lanmap-{}.json", ts);
    match std::fs::write(&name, json) {
        Ok(()) => format!("exported {} hosts → {}", state.hosts.len(), name),
        Err(e) => format!("export failed: {}", e),
    }
}

fn render(f: &mut Frame, app: &mut App) {
    let sort_mode = app.sort_mode;
    let online_only = app.online_only;
    let spinner = app.spinner_frame;
    let status = app.status.clone();
    let state = app.state.lock().unwrap();

    // Check for fatal error
    if let Some(err) = &state.error {
        let msg = Paragraph::new(format!(" error: {}", err))
            .style(Style::default().fg(Color::Red))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" lanmap "),
            );
        f.render_widget(msg, f.area());
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.area());

    let visible = visible_hosts(&state, sort_mode, online_only);

    render_header(f, chunks[0], &state, spinner, sort_mode, online_only);
    render_table(f, chunks[1], &visible, state.hosts.len(), &mut app.table_state);
    render_footer(f, chunks[2], &state, status.as_ref());
}

fn render_header(
    f: &mut Frame,
    area: Rect,
    state: &ScanState,
    spinner_idx: usize,
    sort_mode: SortMode,
    online_only: bool,
) {
    let subnet_str = state
        .subnet
        .map(|s| s.to_string())
        .unwrap_or_else(|| "detecting…".into());

    let local_str = state
        .local_ip
        .map(|ip| ip.to_string())
        .unwrap_or_default();

    let online_count = state.hosts.iter().filter(|h| h.online).count();

    let status = if state.scanning {
        format!(
            "{} scanning  {}/{}",
            SPINNER[spinner_idx],
            state.scan_progress,
            state.scan_total
        )
    } else {
        format!("● {} online", online_count)
    };

    let mut spans = vec![
        Span::styled(
            " lanmap ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
        Span::styled(subnet_str, Style::default().fg(Color::White)),
        Span::styled("  (", Style::default().fg(Color::DarkGray)),
        Span::styled(local_str, Style::default().fg(Color::Yellow)),
        Span::styled(")  │  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            status,
            Style::default().fg(if state.scanning {
                Color::Yellow
            } else {
                Color::Green
            }),
        ),
        Span::styled(
            format!("  │  sort: {}", sort_mode.label()),
            Style::default().fg(Color::DarkGray),
        ),
    ];
    if online_only {
        spans.push(Span::styled(
            "  [online only]",
            Style::default().fg(Color::Cyan),
        ));
    }
    let line = Line::from(spans);

    let header = Paragraph::new(line)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .alignment(Alignment::Left);

    f.render_widget(header, area);
}

fn render_table(
    f: &mut Frame,
    area: Rect,
    hosts: &[&HostInfo],
    total: usize,
    table_state: &mut TableState,
) {
    let hdr = |label: &'static str| {
        Cell::from(label).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    };

    let header = Row::new(vec![
        hdr("IP Address"),
        hdr("MAC"),
        hdr("Vendor"),
        hdr("Hostname"),
        hdr("Latency"),
        hdr("Status"),
    ])
    .height(1)
    .bottom_margin(1);

    let rows: Vec<Row> = hosts
        .iter()
        .map(|host| {
            let (status_sym, status_style) = if host.online {
                if host.is_new && host.first_seen.elapsed() < NEW_BADGE_TTL {
                    ("★ new".to_string(), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                } else {
                    ("● online".to_string(), Style::default().fg(Color::Green))
                }
            } else {
                (
                    format!("○ {} ago", fmt_age(host.last_seen.elapsed())),
                    Style::default().fg(Color::DarkGray),
                )
            };

            let ip_style = if host.online {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            let latency = host
                .latency_ms
                .map(|ms| format!("{:.1} ms", ms))
                .unwrap_or_else(|| "—".into());

            let mac = host.mac.clone().unwrap_or_else(|| "—".into());

            let (vendor, vendor_style) = match host.vendor.as_deref() {
                    Some("Randomized") => ("Randomized".to_string(), Style::default().fg(Color::DarkGray)),
                    Some(v) => (v.to_string(), Style::default().fg(Color::Magenta)),
                    None => ("—".to_string(), Style::default().fg(Color::DarkGray)),
                };

            let hostname = host.hostname.clone().unwrap_or_else(|| "—".into());

            Row::new(vec![
                Cell::from(host.ip.to_string()).style(ip_style),
                Cell::from(mac).style(Style::default().fg(Color::Rgb(120, 120, 160))),
                Cell::from(vendor).style(vendor_style),
                Cell::from(hostname).style(Style::default().fg(Color::Gray)),
                Cell::from(latency).style(Style::default().fg(Color::Yellow)),
                Cell::from(status_sym).style(status_style),
            ])
        })
        .collect();

    let title = if hosts.len() == total {
        format!(" {} hosts ", total)
    } else {
        format!(" {} / {} hosts ", hosts.len(), total)
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(16),  // IP
            Constraint::Length(19),  // MAC  (xx:xx:xx:xx:xx:xx = 17 chars)
            Constraint::Length(14),  // Vendor
            Constraint::Min(16),     // Hostname
            Constraint::Length(10),  // Latency
            Constraint::Length(10),  // Status
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(title),
    )
    .highlight_style(
        Style::default()
            .bg(Color::Rgb(40, 40, 60))
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    f.render_stateful_widget(table, area, table_state);
}

fn fmt_age(age: Duration) -> String {
    let secs = age.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

fn render_footer(f: &mut Frame, area: Rect, state: &ScanState, status: Option<&(String, Instant)>) {
    // A fresh transient message (export result, etc.) takes over the right
    // side; otherwise show the scan countdown.
    let (right, right_style) = match status {
        Some((msg, t)) if t.elapsed() < STATUS_TTL => {
            (msg.clone(), Style::default().fg(Color::Green))
        }
        _ => {
            let next = if state.scanning {
                "scanning…".to_string()
            } else if state.rescan_requested {
                "rescan queued".to_string()
            } else if let Some(t) = state.last_scan {
                let remaining = RESCAN_INTERVAL
                    .as_secs()
                    .saturating_sub(t.elapsed().as_secs());
                format!("next scan in {}s", remaining)
            } else {
                "starting…".to_string()
            };
            (next, Style::default().fg(Color::DarkGray))
        }
    };

    let line = Line::from(vec![
        Span::styled(" [q]", Style::default().fg(Color::Yellow)),
        Span::raw(" quit  "),
        Span::styled("[r]", Style::default().fg(Color::Yellow)),
        Span::raw(" rescan  "),
        Span::styled("[e]", Style::default().fg(Color::Yellow)),
        Span::raw(" export  "),
        Span::styled("[s]", Style::default().fg(Color::Yellow)),
        Span::raw(" sort  "),
        Span::styled("[f]", Style::default().fg(Color::Yellow)),
        Span::raw(" filter  "),
        Span::styled("[↑↓/jk]", Style::default().fg(Color::Yellow)),
        Span::raw(" nav  "),
        Span::styled("│  ", Style::default().fg(Color::DarkGray)),
        Span::styled(right, right_style),
    ]);

    let footer = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(footer, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn host(ip: [u8; 4], online: bool, latency: Option<f64>, hostname: Option<&str>) -> HostInfo {
        let now = Instant::now();
        HostInfo {
            ip: Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            hostname: hostname.map(str::to_string),
            mac: None,
            vendor: None,
            latency_ms: latency,
            online,
            is_new: false,
            first_seen: now,
            last_seen: now,
        }
    }

    fn ips(hosts: &[&HostInfo]) -> Vec<Ipv4Addr> {
        hosts.iter().map(|h| h.ip).collect()
    }

    fn state_with(hosts: Vec<HostInfo>) -> ScanState {
        ScanState {
            hosts,
            ..Default::default()
        }
    }

    #[test]
    fn online_filter_hides_offline_hosts() {
        let s = state_with(vec![
            host([192, 168, 1, 2], true, Some(5.0), None),
            host([192, 168, 1, 3], false, None, None),
        ]);
        let all = visible_hosts(&s, SortMode::Ip, false);
        let online = visible_hosts(&s, SortMode::Ip, true);
        assert_eq!(all.len(), 2);
        assert_eq!(ips(&online), vec![Ipv4Addr::new(192, 168, 1, 2)]);
    }

    #[test]
    fn latency_sort_puts_unreachable_last() {
        let s = state_with(vec![
            host([192, 168, 1, 2], true, Some(30.0), None),
            host([192, 168, 1, 3], false, None, None),
            host([192, 168, 1, 4], true, Some(2.0), None),
        ]);
        let sorted = visible_hosts(&s, SortMode::Latency, false);
        assert_eq!(
            ips(&sorted),
            vec![
                Ipv4Addr::new(192, 168, 1, 4), // 2ms
                Ipv4Addr::new(192, 168, 1, 2), // 30ms
                Ipv4Addr::new(192, 168, 1, 3), // no latency
            ]
        );
    }

    #[test]
    fn hostname_sort_puts_nameless_last_case_insensitively() {
        let s = state_with(vec![
            host([192, 168, 1, 2], true, None, None),
            host([192, 168, 1, 3], true, None, Some("Zebra")),
            host([192, 168, 1, 4], true, None, Some("alpha")),
        ]);
        let sorted = visible_hosts(&s, SortMode::Hostname, false);
        assert_eq!(
            ips(&sorted),
            vec![
                Ipv4Addr::new(192, 168, 1, 4), // alpha
                Ipv4Addr::new(192, 168, 1, 3), // Zebra
                Ipv4Addr::new(192, 168, 1, 2), // no hostname
            ]
        );
    }
}
