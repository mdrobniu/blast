//! blast - high-throughput, hardware-accelerated bandwidth tester.
//!
//! Modes:
//!   * compat - MikroTik btest wire protocol (interop with RouterOS / btest.exe)
//!   * turbo  - native protocol between two blast instances (jumbo + GSO + io_uring path)
//!
//! See PROTOCOL.md for the reverse-engineered MikroTik wire format.

// Protocol vocabularies (handshake words, stats codec, accessors) are defined
// in full on purpose; not every variant is wired into a code path yet.
#![allow(dead_code)]

mod ecsrp5;
mod engine;
mod iperf;
mod iperf2;
mod spdtst;
mod librespeed;
mod net;
mod proto;
mod speedtest;
mod stats;
mod sys;
mod ui;
mod uring;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use engine::{Mode, Resolved};
use proto::{Direction, Protocol};
use std::io::IsTerminal;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "blast",
    version,
    about = "blast - high-throughput, hardware-accelerated bandwidth tester (MikroTik btest compatible + turbo)",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Listen for incoming tests (server side).
    Server(ServerArgs),
    /// Connect to a server and run a test (client side).
    Client(ClientArgs),
    /// Run an iperf3-compatible client (interops with `iperf3 -s`).
    Iperf(IperfArgs),
    /// Run a classic iperf2 client/server (what Ubiquiti airOS Speed Test uses).
    Iperf2(Iperf2Args),
    /// Run the Ubiquiti airOS Speed Test protocol (spdtst.ko), client/server.
    Spdtst(SpdtstArgs),
    /// Run an Ookla-legacy speedtest (client, or `--server` to listen).
    Speedtest(SpeedtestArgs),
    /// Run a LibreSpeed HTTP test (client URL, or `--server` to listen).
    Librespeed(LibreArgs),
    /// Print detected acceleration capabilities and exit.
    Caps,
}

#[derive(Args)]
struct LibreArgs {
    /// Server base URL (client mode), e.g. http://host:8080 or https://example/backend
    url: Option<String>,
    /// Run as a LibreSpeed HTTP server instead of a client.
    #[arg(short = 's', long)]
    server: bool,
    /// Listen address in --server mode.
    #[arg(short = 'l', long, default_value = "0.0.0.0:8080")]
    listen: String,
    /// Seconds per phase (download, upload).
    #[arg(short = 'd', long, default_value_t = 10)]
    duration: u32,
    /// Parallel streams.
    #[arg(short = 'P', long, default_value_t = 3)]
    streams: usize,
    /// Emit a JSON summary only.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct SpeedtestArgs {
    /// Server host (client mode); omit and pass --server to listen.
    host: Option<String>,
    /// Server port.
    #[arg(short = 'p', long, default_value_t = 8080)]
    port: u16,
    /// Run as a speedtest server instead of a client.
    #[arg(short = 's', long)]
    server: bool,
    /// Listen address in --server mode.
    #[arg(short = 'l', long, default_value = "0.0.0.0:8080")]
    listen: String,
    /// Seconds per phase (download, upload).
    #[arg(short = 'd', long, default_value_t = 10)]
    duration: u32,
    /// Parallel streams.
    #[arg(short = 'P', long, default_value_t = 4)]
    streams: usize,
    /// Emit a JSON summary only.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct IperfArgs {
    /// iperf3 server host (name or IP).
    host: String,
    /// Server control port.
    #[arg(short = 'p', long, default_value_t = 5201)]
    port: u16,
    /// Use UDP instead of TCP.
    #[arg(short = 'u', long)]
    udp: bool,
    /// Reverse mode: server sends, client receives (download).
    #[arg(short = 'R', long)]
    reverse: bool,
    /// Test duration in seconds.
    #[arg(short = 'd', long, default_value_t = 10)]
    duration: u32,
    /// Parallel streams.
    #[arg(short = 'P', long, default_value_t = 1)]
    parallel: usize,
    /// Block size in bytes (0 = auto: 128 KiB TCP, 1460 UDP).
    #[arg(long, default_value_t = 0)]
    len: usize,
    /// Target bitrate in bits/sec (suffixes K/M/G; 0 = unlimited).
    #[arg(short = 'b', long, default_value = "0")]
    bandwidth: String,
    /// Force plain line output.
    #[arg(long)]
    plain: bool,
    /// Emit a JSON summary only.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct Iperf2Args {
    /// Server host (client mode). Ignored with --server.
    #[arg(default_value = "0.0.0.0")]
    host: String,
    /// Run as a server (listen) instead of a client.
    #[arg(short = 's', long)]
    server: bool,
    /// Port (airOS/iperf2 default 5001).
    #[arg(short = 'p', long, default_value_t = 5001)]
    port: u16,
    /// Use UDP instead of TCP.
    #[arg(short = 'u', long)]
    udp: bool,
    /// Test duration in seconds (client).
    #[arg(short = 'd', long, default_value_t = 10)]
    duration: u32,
    /// Parallel streams (client).
    #[arg(short = 'P', long, default_value_t = 1)]
    parallel: usize,
    /// Block size in bytes (0 = auto: 128 KiB TCP, 1470 UDP).
    #[arg(long, default_value_t = 0)]
    len: usize,
    /// Target bitrate bits/sec (suffixes K/M/G; 0 = unlimited).
    #[arg(short = 'b', long, default_value = "0")]
    bandwidth: String,
    /// Force plain line output.
    #[arg(long)]
    plain: bool,
    /// Emit a JSON summary only.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct SpdtstArgs {
    /// Peer host (client mode). Ignored with --server.
    #[arg(default_value = "0.0.0.0")]
    host: String,
    /// Run as the slave (listen) instead of the master.
    #[arg(short = 's', long)]
    server: bool,
    /// UDP port (blast<->blast transport).
    #[arg(short = 'p', long, default_value_t = 16569)]
    port: u16,
    /// Test duration in seconds (master).
    #[arg(short = 'd', long, default_value_t = 10)]
    duration: u32,
    /// Direction: rx, tx, or dx (both).
    #[arg(short = 'D', long, default_value = "tx")]
    direction: String,
    /// Datagram payload size in bytes.
    #[arg(long, default_value_t = 1472)]
    datasize: u16,
    /// Rate hint in Mbit/s (0 = unlimited).
    #[arg(short = 'b', long, default_value_t = 0)]
    datarate: u16,
    /// Force plain line output.
    #[arg(long)]
    plain: bool,
    /// Emit a JSON summary only.
    #[arg(long)]
    json: bool,
}

#[derive(Copy, Clone, ValueEnum)]
enum ModeArg {
    Compat,
    Turbo,
}
impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Mode {
        match m {
            ModeArg::Compat => Mode::Compat,
            ModeArg::Turbo => Mode::Turbo,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum DirArg {
    /// Client transmits (upload).
    Tx,
    /// Client receives (download).
    Rx,
    /// Both at once.
    Both,
}
impl From<DirArg> for Direction {
    fn from(d: DirArg) -> Direction {
        match d {
            DirArg::Tx => Direction::Tx,
            DirArg::Rx => Direction::Rx,
            DirArg::Both => Direction::Both,
        }
    }
}

#[derive(Args)]
struct CommonArgs {
    /// Protocol family.
    #[arg(long, value_enum, default_value = "turbo")]
    mode: ModeArg,
    /// Use UDP for the data plane.
    #[arg(short = 'u', long)]
    udp: bool,
    /// Use TCP for the data plane (default).
    #[arg(short = 't', long)]
    tcp: bool,
    /// Parallel connections / workers (0 = auto).
    #[arg(short = 'P', long, default_value_t = 0)]
    connections: usize,
    /// UDP datagram size in bytes.
    #[arg(long, default_value_t = 1432)]
    size: usize,
    /// TCP write block size in bytes.
    #[arg(long, default_value_t = 262144)]
    tcp_block: usize,
    /// GSO segment size (Linux). 0 = match --size, use --no-gso to disable.
    #[arg(long)]
    gso: Option<u16>,
    /// Disable UDP GSO even if available.
    #[arg(long)]
    no_gso: bool,
    /// Zero-fill payload instead of random.
    #[arg(long)]
    zero: bool,
    /// Use the io_uring batched-send backend (Linux, turbo UDP).
    #[arg(long)]
    io_uring: bool,
    /// Force plain line output.
    #[arg(long)]
    plain: bool,
    /// Emit a JSON summary only.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ServerArgs {
    /// Listen address.
    #[arg(short = 'l', long, default_value = "0.0.0.0:2000")]
    listen: String,
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args)]
struct ClientArgs {
    /// Server host (name or IP).
    host: String,
    /// Server control port.
    #[arg(short = 'p', long, default_value_t = 2000)]
    port: u16,
    /// Test direction.
    #[arg(short = 'D', long, value_enum, default_value = "tx")]
    direction: DirArg,
    /// Test duration in seconds.
    #[arg(short = 'd', long, default_value_t = 10)]
    duration: u64,
    /// Local TX rate cap in bits/sec (suffixes K/M/G, 0 = unlimited).
    #[arg(short = 'b', long, default_value = "0")]
    rate: String,
    /// Username for MikroTik auth (compat mode).
    #[arg(long, default_value = "")]
    user: String,
    /// Password for MikroTik auth (compat mode).
    #[arg(long, default_value = "")]
    password: String,
    #[command(flatten)]
    common: CommonArgs,
}

fn pick_protocol(c: &CommonArgs) -> Protocol {
    if c.udp && !c.tcp {
        Protocol::Udp
    } else if c.tcp {
        Protocol::Tcp
    } else {
        // default: TCP (safe, reaches line rate via TSO/LRO)
        Protocol::Tcp
    }
}

fn pick_ui(c: &CommonArgs) -> ui::UiKind {
    if c.json {
        ui::UiKind::Json
    } else if c.plain || !std::io::stdout().is_terminal() {
        ui::UiKind::Plain
    } else {
        ui::UiKind::Tui
    }
}

fn parse_bitrate(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() || s == "0" {
        return Ok(0);
    }
    let (num, mult) = match s.chars().last().unwrap().to_ascii_uppercase() {
        'K' => (&s[..s.len() - 1], 1_000u64),
        'M' => (&s[..s.len() - 1], 1_000_000),
        'G' => (&s[..s.len() - 1], 1_000_000_000),
        c if c.is_ascii_digit() => (s, 1),
        _ => bail!("bad rate '{s}'"),
    };
    let bits: f64 = num.trim().parse().with_context(|| format!("bad rate '{s}'"))?;
    Ok((bits * mult as f64 / 8.0) as u64) // bits/s -> bytes/s
}

fn auto_workers(req: usize, mode: Mode, caps: &sys::Caps) -> usize {
    if req > 0 {
        return req;
    }
    match mode {
        Mode::Compat => 1,
        Mode::Turbo => caps.cores.clamp(1, 8),
    }
}

fn resolve(common: &CommonArgs, mode: Mode, direction: Direction, duration: u64, rate: u64, user: String, password: String, caps: sys::Caps) -> Resolved {
    let proto = pick_protocol(common);
    let workers = auto_workers(common.connections, mode, &caps);
    let gso_segment = if proto == Protocol::Udp && !common.no_gso && caps.udp_gso {
        common.gso.unwrap_or(common.size as u16)
    } else {
        0
    };
    Resolved {
        mode,
        proto,
        direction,
        random: !common.zero,
        workers,
        udp_datagram: common.size,
        gso_segment,
        mmsg_batch: 64,
        tcp_block: common.tcp_block,
        local_cap: rate,
        remote_cap: rate,
        duration: Duration::from_secs(duration.max(1)),
        caps,
        ui: pick_ui(common),
        user,
        password,
        io_uring: common.io_uring,
        is_server: false,
    }
}

fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address for {host}:{port}"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let caps = sys::detect();

    match cli.cmd {
        Cmd::Caps => {
            println!("blast acceleration capabilities");
            println!("  os/cores  : {} / {}", caps.os, caps.cores);
            println!("  reuseport : {}", caps.reuseport);
            println!("  udp gso   : {}", caps.udp_gso);
            println!("  udp gro   : {}", caps.udp_gro);
            println!("  sendmmsg  : {}", caps.sendmmsg);
            println!("  io_uring  : {}", caps.io_uring);
            println!("  af_xdp    : {}", caps.af_xdp);
            println!("  hugepages : {}", caps.hugepages);
            Ok(())
        }
        Cmd::Server(a) => {
            let listen: SocketAddr = a
                .listen
                .parse()
                .with_context(|| format!("parse --listen {}", a.listen))?;
            let mut r = resolve(&a.common, a.common.mode.into(), Direction::Rx, 10, 0, String::new(), String::new(), caps);
            // A server is headless: plain per-session lines, never a per-session TUI.
            if !a.common.json {
                r.ui = ui::UiKind::Plain;
            }
            engine::run_server(&r, listen)
        }
        Cmd::Client(a) => {
            let server = resolve_addr(&a.host, a.port)?;
            let rate = parse_bitrate(&a.rate)?;
            let r = resolve(
                &a.common,
                a.common.mode.into(),
                a.direction.into(),
                a.duration,
                rate,
                a.user.clone(),
                a.password.clone(),
                caps,
            );
            engine::run_client(&r, server)
        }
        Cmd::Iperf(a) => {
            let server = resolve_addr(&a.host, a.port)?;
            let bw_bits = parse_bitrate(&a.bandwidth)? * 8; // parse_bitrate -> bytes/s
            let len = if a.len != 0 {
                a.len
            } else if a.udp {
                1460
            } else {
                131072
            };
            let ui_kind = if a.json {
                ui::UiKind::Json
            } else if a.plain || !std::io::stdout().is_terminal() {
                ui::UiKind::Plain
            } else {
                ui::UiKind::Tui
            };
            let opts = iperf::IperfOpts {
                server,
                udp: a.udp,
                reverse: a.reverse,
                duration: a.duration,
                parallel: a.parallel.max(1),
                len,
                bandwidth: bw_bits,
                ui: ui_kind,
                caps,
            };
            iperf::run_client(&opts)
        }
        Cmd::Iperf2(a) => {
            let addr = if a.server {
                format!("{}:{}", if a.host == "0.0.0.0" { "0.0.0.0" } else { &a.host }, a.port)
                    .parse()
                    .context("parse listen address")?
            } else {
                resolve_addr(&a.host, a.port)?
            };
            let bw_bits = parse_bitrate(&a.bandwidth)? * 8;
            let ui_kind = if a.json {
                ui::UiKind::Json
            } else if a.plain || !std::io::stdout().is_terminal() {
                ui::UiKind::Plain
            } else {
                ui::UiKind::Tui
            };
            let opts = iperf2::Iperf2Opts {
                addr,
                server: a.server,
                udp: a.udp,
                duration: a.duration,
                parallel: a.parallel.max(1),
                len: a.len,
                bandwidth: bw_bits,
                ui: ui_kind,
                caps,
            };
            iperf2::run(&opts)
        }
        Cmd::Spdtst(a) => {
            let addr = if a.server {
                format!("0.0.0.0:{}", a.port).parse().context("parse listen address")?
            } else {
                resolve_addr(&a.host, a.port)?
            };
            let direction = match a.direction.as_str() {
                "rx" => spdtst::Dir::Rx,
                "dx" | "both" => spdtst::Dir::Dx,
                _ => spdtst::Dir::Tx,
            };
            let ui_kind = if a.json {
                ui::UiKind::Json
            } else if a.plain || !std::io::stdout().is_terminal() {
                ui::UiKind::Plain
            } else {
                ui::UiKind::Tui
            };
            let opts = spdtst::SpdtstOpts {
                addr,
                server: a.server,
                duration: a.duration,
                direction,
                datasize: a.datasize,
                datarate: a.datarate,
                ui: ui_kind,
                caps,
            };
            spdtst::run(&opts)
        }
        Cmd::Speedtest(a) => {
            if a.server {
                let listen: SocketAddr = a
                    .listen
                    .parse()
                    .with_context(|| format!("parse --listen {}", a.listen))?;
                speedtest::run_server(listen)
            } else {
                let host = a
                    .host
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("provide a host, or use --server to listen"))?;
                let server = resolve_addr(&host, a.port)?;
                let opts = speedtest::SpeedtestOpts {
                    server,
                    duration: a.duration,
                    streams: a.streams.max(1),
                    json: a.json,
                    caps,
                };
                speedtest::run_client(&opts)
            }
        }
        Cmd::Librespeed(a) => {
            if a.server {
                let listen: SocketAddr = a
                    .listen
                    .parse()
                    .with_context(|| format!("parse --listen {}", a.listen))?;
                librespeed::run_server(listen)
            } else {
                let url = a
                    .url
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("provide a base URL, or use --server to listen"))?;
                let opts = librespeed::LibreOpts {
                    base_url: url,
                    duration: a.duration,
                    streams: a.streams.max(1),
                    json: a.json,
                    caps,
                };
                librespeed::run_client(&opts)
            }
        }
    }
}
