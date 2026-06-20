//! Terminal UX: a live ratatui dashboard (the "warp-speed" view) with a plain
//! line reporter and a JSON summary as fallbacks for pipes/CI.

use crate::stats::{fmt_bits, fmt_bytes, fmt_pps, Rate, Snapshot};
use crate::sys::Caps;
use std::collections::VecDeque;
use std::io::Write;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UiKind {
    Tui,
    Plain,
    Json,
}

pub trait Reporter {
    /// Called each tick. Returns true if the user asked to quit early.
    fn tick(&mut self, snap: &Snapshot, rate: &Rate, per_worker: &[(u64, u64)]) -> bool;
    fn finish(&mut self, final_snap: &Snapshot);
}

pub fn make_reporter(
    kind: UiKind,
    header: String,
    caps: Caps,
    duration: Duration,
) -> Box<dyn Reporter> {
    match kind {
        UiKind::Tui => match TuiReporter::new(header.clone(), caps.clone(), duration) {
            Ok(r) => Box::new(r),
            Err(_) => Box::new(PlainReporter::new(header, caps, duration, false)),
        },
        UiKind::Plain => Box::new(PlainReporter::new(header, caps, duration, false)),
        UiKind::Json => Box::new(PlainReporter::new(header, caps, duration, true)),
    }
}

pub fn caps_badges(c: &Caps) -> String {
    let mut v: Vec<String> = Vec::new();
    v.push(format!("{} x{}", c.os, c.cores));
    if c.reuseport {
        v.push("REUSEPORT".into());
    }
    if c.udp_gso {
        v.push("GSO".into());
    }
    if c.udp_gro {
        v.push("GRO".into());
    }
    if c.sendmmsg {
        v.push("mmsg".into());
    }
    if c.io_uring {
        v.push("io_uring".into());
    }
    if c.af_xdp {
        v.push("AF_XDP".into());
    }
    if c.hugepages > 0 {
        v.push(format!("huge:{}", c.hugepages));
    }
    v.join(" ")
}

pub fn banner_server(caps: &Caps, listen: SocketAddr) {
    println!("blast server listening on {listen}");
    println!("  accel: {}", caps_badges(caps));
}

/// (bytes_sent_by_us, bytes_received_by_peer, loss_pct) using the peer's
/// 07-heartbeat counter. Upload: we sent tx, peer got remote. Download: peer
/// sent remote, we got rx.
pub fn peer_loss(snap: &Snapshot) -> (u64, u64, f64) {
    let (sent, received) = if snap.tx_bytes >= snap.rx_bytes {
        (snap.tx_bytes, snap.remote_bytes)
    } else {
        (snap.remote_bytes, snap.rx_bytes)
    };
    let loss = if sent > 0 && received <= sent {
        (sent - received) as f64 / sent as f64 * 100.0
    } else {
        0.0
    };
    (sent, received, loss)
}

// ---------------- Plain / JSON ----------------

pub struct PlainReporter {
    header: String,
    caps: Caps,
    duration: Duration,
    json: bool,
    start: Instant,
    last_line: Instant,
}

impl PlainReporter {
    fn new(header: String, caps: Caps, duration: Duration, json: bool) -> Self {
        if !json {
            println!("{header}");
            println!("  accel: {}", caps_badges(&caps));
        }
        PlainReporter {
            header,
            caps,
            duration,
            json,
            start: Instant::now(),
            last_line: Instant::now() - Duration::from_secs(2),
        }
    }
}

impl Reporter for PlainReporter {
    fn tick(&mut self, snap: &Snapshot, rate: &Rate, _pw: &[(u64, u64)]) -> bool {
        if self.json {
            return false;
        }
        if self.last_line.elapsed() < Duration::from_millis(950) {
            return false;
        }
        self.last_line = Instant::now();
        let t = snap.elapsed;
        // Peer-received rate from the btest 07 heartbeats (what the OTHER side got).
        let peer = if snap.remote_rate_bps > 0.0 {
            format!("  peer-rx {:>11}", fmt_bits(snap.remote_rate_bps))
        } else {
            String::new()
        };
        println!(
            "[{t:5.1}s] tx {:>11}  rx {:>11}{peer} | {:>10} | tot {:>9}",
            fmt_bits(rate.tx_bps),
            fmt_bits(rate.rx_bps),
            fmt_pps(rate.tx_pps + rate.rx_pps),
            fmt_bytes((snap.tx_bytes + snap.rx_bytes) as f64),
        );
        let _ = std::io::stdout().flush();
        false
    }

    fn finish(&mut self, snap: &Snapshot) {
        let avg = snap.avg();
        let (sent, received, loss) = peer_loss(snap);
        if self.json {
            // Minimal, dependency-free JSON.
            println!(
                "{{\"header\":\"{}\",\"os\":\"{}\",\"cores\":{},\"seconds\":{:.3},\
                 \"tx_bytes\":{},\"rx_bytes\":{},\"tx_pkts\":{},\"rx_pkts\":{},\
                 \"avg_tx_bps\":{:.0},\"avg_rx_bps\":{:.0},\
                 \"peer_rx_bytes\":{},\"peer_avg_bps\":{:.0},\"loss_pct\":{:.2},\
                 \"accel\":\"{}\"}}",
                self.header.replace('"', "'"),
                self.caps.os,
                self.caps.cores,
                snap.elapsed,
                snap.tx_bytes,
                snap.rx_bytes,
                snap.tx_pkts,
                snap.rx_pkts,
                avg.tx_bps,
                avg.rx_bps,
                snap.remote_bytes,
                snap.remote_bytes as f64 * 8.0 / snap.elapsed.max(1e-9),
                loss,
                caps_badges(&self.caps),
            );
        } else {
            println!("{}", "-".repeat(64));
            println!(
                "  done in {:.1}s over {} worker-set",
                snap.elapsed,
                self.caps.cores
            );
            println!(
                "  avg TX {:>11}   total {:>9}   {:>10}",
                fmt_bits(avg.tx_bps),
                fmt_bytes(snap.tx_bytes as f64),
                fmt_pps(avg.tx_pps)
            );
            println!(
                "  avg RX {:>11}   total {:>9}   {:>10}",
                fmt_bits(avg.rx_bps),
                fmt_bytes(snap.rx_bytes as f64),
                fmt_pps(avg.rx_pps)
            );
            if snap.remote_bytes > 0 {
                println!(
                    "  peer received {} of {} sent  ->  {:.2}% loss",
                    fmt_bytes(received as f64),
                    fmt_bytes(sent as f64),
                    loss
                );
            }
        }
        let _ = self.duration;
    }
}

// ---------------- TUI ----------------

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::layout::{Alignment, Constraint, Direction as LDir, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Gauge, Paragraph, Sparkline};
use ratatui::{Frame, Terminal};

type Term = Terminal<CrosstermBackend<std::io::Stdout>>;

pub struct TuiReporter {
    term: Term,
    header: String,
    caps: Caps,
    duration: Duration,
    start: Instant,
    tx_hist: VecDeque<u64>,
    rx_hist: VecDeque<u64>,
    peak_tx: f64,
    peak_rx: f64,
    last_rate: Rate,
    last_pw: Vec<(u64, u64)>,
    last_pw_prev: Vec<(u64, u64)>,
}

const HIST: usize = 240;

impl TuiReporter {
    fn new(header: String, caps: Caps, duration: Duration) -> std::io::Result<Self> {
        enable_raw_mode()?;
        let mut out = std::io::stdout();
        execute!(out, EnterAlternateScreen)?;
        let term = Terminal::new(CrosstermBackend::new(out))?;
        Ok(TuiReporter {
            term,
            header,
            caps,
            duration,
            start: Instant::now(),
            tx_hist: VecDeque::with_capacity(HIST),
            rx_hist: VecDeque::with_capacity(HIST),
            peak_tx: 0.0,
            peak_rx: 0.0,
            last_rate: Rate::default(),
            last_pw: Vec::new(),
            last_pw_prev: Vec::new(),
        })
    }

    fn restore(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.term.backend_mut(), LeaveAlternateScreen);
        let _ = self.term.show_cursor();
    }
}

fn push_hist(h: &mut VecDeque<u64>, v: u64) {
    if h.len() == HIST {
        h.pop_front();
    }
    h.push_back(v);
}

impl Reporter for TuiReporter {
    fn tick(&mut self, snap: &Snapshot, rate: &Rate, per_worker: &[(u64, u64)]) -> bool {
        // scale sparkline in Mbps units to keep u64 buckets readable
        push_hist(&mut self.tx_hist, (rate.tx_bps / 1.0e6) as u64);
        push_hist(&mut self.rx_hist, (rate.rx_bps / 1.0e6) as u64);
        self.peak_tx = self.peak_tx.max(rate.tx_bps);
        self.peak_rx = self.peak_rx.max(rate.rx_bps);
        self.last_rate = *rate;
        self.last_pw_prev = std::mem::take(&mut self.last_pw);
        self.last_pw = per_worker.to_vec();

        let snap = *snap;
        let elapsed = self.start.elapsed().as_secs_f64();
        let total = self.duration.as_secs_f64().max(0.001);
        let progress = (elapsed / total).clamp(0.0, 1.0);

        let header = self.header.clone();
        let badges = caps_badges(&self.caps);
        let tx_hist: Vec<u64> = self.tx_hist.iter().copied().collect();
        let rx_hist: Vec<u64> = self.rx_hist.iter().copied().collect();
        let rate = *rate;
        let peak_tx = self.peak_tx;
        let peak_rx = self.peak_rx;
        let pw = self.last_pw.clone();
        let pwp = self.last_pw_prev.clone();

        let _ = self.term.draw(|f| {
            draw(
                f, &header, &badges, &snap, &rate, peak_tx, peak_rx, &tx_hist, &rx_hist, progress,
                &pw, &pwp,
            )
        });

        // input
        if event::poll(Duration::from_millis(0)).unwrap_or(false) {
            if let Ok(Event::Key(k)) = event::read() {
                let quit = matches!(k.code, KeyCode::Char('q') | KeyCode::Esc)
                    || (k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL));
                if quit {
                    return true;
                }
            }
        }
        false
    }

    fn finish(&mut self, snap: &Snapshot) {
        self.restore();
        let avg = snap.avg();
        println!("{}", self.header);
        println!("  accel: {}", caps_badges(&self.caps));
        println!("{}", "-".repeat(64));
        println!(
            "  avg TX {:>11}  peak {:>11}  total {:>9}",
            fmt_bits(avg.tx_bps),
            fmt_bits(self.peak_tx),
            fmt_bytes(snap.tx_bytes as f64),
        );
        println!(
            "  avg RX {:>11}  peak {:>11}  total {:>9}",
            fmt_bits(avg.rx_bps),
            fmt_bits(self.peak_rx),
            fmt_bytes(snap.rx_bytes as f64),
        );
        println!("  packets: tx {}  rx {}", snap.tx_pkts, snap.rx_pkts);
        if snap.remote_bytes > 0 {
            let (sent, received, loss) = peer_loss(snap);
            println!(
                "  peer received {} of {} sent  ->  {:.2}% loss",
                fmt_bytes(received as f64),
                fmt_bytes(sent as f64),
                loss
            );
        }
    }
}

impl Drop for TuiReporter {
    fn drop(&mut self) {
        self.restore();
    }
}

#[allow(clippy::too_many_arguments)]
fn draw(
    f: &mut Frame,
    header: &str,
    badges: &str,
    snap: &Snapshot,
    rate: &Rate,
    peak_tx: f64,
    peak_rx: f64,
    tx_hist: &[u64],
    rx_hist: &[u64],
    progress: f64,
    pw: &[(u64, u64)],
    pwp: &[(u64, u64)],
) {
    let area = f.area();
    let rows = Layout::default()
        .direction(LDir::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(7), // big readouts
            Constraint::Min(6),    // sparklines
            Constraint::Length(7), // per-worker
            Constraint::Length(3), // progress
        ])
        .split(area);

    // header
    let head = Paragraph::new(Line::from(vec![
        Span::styled(" blast ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(header.to_string(), Style::default().add_modifier(Modifier::BOLD)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(Span::styled(
                format!(" accel: {badges} "),
                Style::default().fg(Color::DarkGray),
            )),
    );
    f.render_widget(head, rows[0]);

    // readouts: TX | RX
    let cols = Layout::default()
        .direction(LDir::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    f.render_widget(big_readout("TX  (upload)", rate.tx_bps, peak_tx, rate.tx_pps, Color::LightGreen), cols[0]);
    f.render_widget(big_readout("RX  (download)", rate.rx_bps, peak_rx, rate.rx_pps, Color::LightMagenta), cols[1]);

    // sparklines
    let sp = Layout::default()
        .direction(LDir::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[2]);
    f.render_widget(spark("TX history (Mbps)", tx_hist, Color::LightGreen), sp[0]);
    f.render_widget(spark("RX history (Mbps)", rx_hist, Color::LightMagenta), sp[1]);

    // per-worker bars
    f.render_widget(worker_panel(pw, pwp), rows[3]);

    // progress
    let pct = (progress * 100.0) as u16;
    let prog = Gauge::default()
        .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).title(" elapsed "))
        .gauge_style(Style::default().fg(Color::Cyan))
        .percent(pct)
        .label(format!(
            "{:.0}%   {}s   total {}",
            progress * 100.0,
            snap.elapsed as u64,
            fmt_bytes((snap.tx_bytes + snap.rx_bytes) as f64)
        ));
    f.render_widget(prog, rows[4]);
}

fn big_readout(title: &str, bps: f64, peak: f64, pps: f64, color: Color) -> Paragraph<'static> {
    let big = fmt_bits(bps);
    let lines = vec![
        Line::from(Span::styled(
            big,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("peak {}", fmt_bits(peak)),
            Style::default().fg(Color::Gray),
        )),
        Line::from(Span::styled(
            fmt_pps(pps),
            Style::default().fg(Color::DarkGray),
        )),
    ];
    Paragraph::new(lines)
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(Span::styled(format!(" {title} "), Style::default().fg(color))),
        )
}

fn spark(title: &str, data: &[u64], color: Color) -> Sparkline<'static> {
    Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(Span::styled(format!(" {title} "), Style::default().fg(Color::DarkGray))),
        )
        .data(data.to_vec())
        .style(Style::default().fg(color))
}

fn worker_panel(pw: &[(u64, u64)], pwp: &[(u64, u64)]) -> Paragraph<'static> {
    let mut lines: Vec<Line> = Vec::new();
    let maxw = 30usize;
    // compute per-worker deltas, find max for scaling
    let deltas: Vec<u64> = pw
        .iter()
        .enumerate()
        .map(|(i, (t, r))| {
            let (pt, pr) = pwp.get(i).copied().unwrap_or((0, 0));
            (t.saturating_sub(pt)) + (r.saturating_sub(pr))
        })
        .collect();
    let peak = deltas.iter().copied().max().unwrap_or(1).max(1);
    for (i, d) in deltas.iter().enumerate().take(6) {
        let fill = ((*d as f64 / peak as f64) * maxw as f64) as usize;
        let bar = format!("{}{}", "=".repeat(fill), " ".repeat(maxw - fill));
        lines.push(Line::from(vec![
            Span::styled(format!(" w{i:<2} "), Style::default().fg(Color::Cyan)),
            Span::styled(bar, Style::default().fg(Color::Green)),
            Span::raw(format!("  {}", fmt_bytes((pw[i].0 + pw[i].1) as f64))),
        ]));
    }
    if pw.len() > 6 {
        lines.push(Line::from(Span::styled(
            format!(" ... and {} more workers", pw.len() - 6),
            Style::default().fg(Color::DarkGray),
        )));
    }
    Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(" per-worker throughput "),
    )
}
