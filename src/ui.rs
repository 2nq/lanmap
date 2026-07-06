use std::io::stdout;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

use crate::scanner::{ScanState, RESCAN_INTERVAL};

const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
// How long a newly-joined device keeps its "new" badge.
const NEW_BADGE_TTL: Duration = Duration::from_secs(300);

pub struct App {
    pub state: Arc<Mutex<ScanState>>,
    pub table_state: TableState,
    pub spinner_frame: usize,
    pub last_tick: Instant,
}

impl App {
    pub fn new(state: Arc<Mutex<ScanState>>) -> Self {
        Self {
            state,
            table_state: TableState::default(),
            spinner_frame: 0,
            last_tick: Instant::now(),
        }
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

        let host_count = app.state.lock().unwrap().hosts.len();

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
                    KeyCode::Down | KeyCode::Char('j') => app.next_row(host_count),
                    KeyCode::Up | KeyCode::Char('k') => app.prev_row(host_count),
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn render(f: &mut Frame, app: &mut App) {
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

    render_header(f, chunks[0], &state, app.spinner_frame);
    render_table(f, chunks[1], &state, &mut app.table_state);
    render_footer(f, chunks[2], &state);
}

fn render_header(f: &mut Frame, area: Rect, state: &ScanState, spinner_idx: usize) {
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

    let line = Line::from(vec![
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
    ]);

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

fn render_table(f: &mut Frame, area: Rect, state: &ScanState, table_state: &mut TableState) {
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

    let rows: Vec<Row> = state
        .hosts
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

    let title = format!(" {} hosts ", state.hosts.len());

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

fn render_footer(f: &mut Frame, area: Rect, state: &ScanState) {
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

    let line = Line::from(vec![
        Span::styled(" [q]", Style::default().fg(Color::Yellow)),
        Span::raw(" quit  "),
        Span::styled("[r]", Style::default().fg(Color::Yellow)),
        Span::raw(" rescan  "),
        Span::styled("[↑↓ / jk]", Style::default().fg(Color::Yellow)),
        Span::raw(" navigate  "),
        Span::styled(format!("│  {}", next), Style::default().fg(Color::DarkGray)),
    ]);

    let footer = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(footer, area);
}
