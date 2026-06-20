//! Test orchestration and the share-nothing data plane.
//!
//! One worker per connection, each pinned to a core, each owning its socket and
//! buffer. Senders prefer UDP GSO, then `sendmmsg`, then plain `send`; receivers
//! prefer GRO, then `recvmmsg`, then plain `recv`. Stats are per-worker atomics.

use crate::proto::*;
use crate::stats::{Snapshot, Stats};
use crate::sys::{self, Buffer, Caps};
use crate::{net, ui};
use anyhow::{anyhow, bail, Context, Result};
use socket2::Socket;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Compat,
    Turbo,
}

#[derive(Clone)]
pub struct Resolved {
    pub mode: Mode,
    pub proto: Protocol,
    pub direction: Direction, // client perspective
    pub random: bool,
    pub workers: usize,
    pub udp_datagram: usize,
    pub gso_segment: u16,
    pub mmsg_batch: u16,
    pub tcp_block: usize,
    pub local_cap: u64,  // bytes/s, 0 = unlimited (local tx)
    pub remote_cap: u64, // bytes/s, 0 = unlimited (remote tx)
    pub duration: Duration,
    pub caps: Caps,
    pub ui: ui::UiKind,
    pub user: String,
    pub password: String,
    pub io_uring: bool,
}

impl Resolved {
    /// Total bytes the kernel super-buffer should hold for one GSO send.
    fn udp_super_len(&self) -> usize {
        if self.gso_segment > 0 {
            let seg = self.gso_segment as usize;
            let segs = (65507 / seg).clamp(1, 64);
            seg * segs
        } else {
            self.udp_datagram
        }
    }
}

// ---------- payload ----------

fn fill_payload(buf: &mut [u8], random: bool) {
    if !random {
        buf.fill(0);
        return;
    }
    // Cheap, fast pseudo-random fill (xorshift64*) - content only needs to be
    // incompressible-ish; this is not a security primitive.
    let mut x: u64 = 0x9E3779B97F4A7C15;
    for chunk in buf.chunks_mut(8) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let v = x.wrapping_mul(0x2545F4914F6CDD1D).to_le_bytes();
        for (b, s) in chunk.iter_mut().zip(v.iter()) {
            *b = *s;
        }
    }
}

// ---------- pacing ----------

struct Pacer {
    cap: u64, // bytes/sec, 0 = unlimited
    start: Instant,
    sent: u64,
}
impl Pacer {
    fn new(cap: u64) -> Self {
        Pacer {
            cap,
            start: Instant::now(),
            sent: 0,
        }
    }
    #[inline]
    fn account(&mut self, n: u64) {
        if self.cap == 0 {
            return;
        }
        self.sent += n;
        let target = self.sent as f64 / self.cap as f64;
        let elapsed = self.start.elapsed().as_secs_f64();
        if target > elapsed + 0.0005 {
            std::thread::sleep(Duration::from_secs_f64(target - elapsed));
        }
    }
}

// ---------- accelerated single ops (returns (bytes, packets)) ----------

#[cfg(target_os = "linux")]
fn udp_send_once(sock: &Socket, r: &Resolved, payload: &[u8]) -> std::io::Result<(usize, usize)> {
    let fd = sock.as_raw_fd();
    if r.gso_segment > 0 && r.caps.udp_gso {
        let n = unsafe { net::accel::send_gso(fd, payload, r.gso_segment)? };
        let pkts = n.div_ceil(r.gso_segment as usize).max(1);
        Ok((n, pkts))
    } else if r.mmsg_batch > 1 && r.caps.sendmmsg {
        let dg = &payload[..r.udp_datagram.min(payload.len())];
        let cnt = unsafe { net::accel::sendmmsg_same(fd, dg, r.mmsg_batch as usize)? };
        Ok((cnt * dg.len(), cnt))
    } else {
        let dg = &payload[..r.udp_datagram.min(payload.len())];
        let n = sock.send(dg)?;
        Ok((n, 1))
    }
}

#[cfg(not(target_os = "linux"))]
fn udp_send_once(sock: &Socket, r: &Resolved, payload: &[u8]) -> std::io::Result<(usize, usize)> {
    let dg = &payload[..r.udp_datagram.min(payload.len())];
    let n = sock.send(dg)?;
    Ok((n, 1))
}

#[cfg(target_os = "linux")]
fn udp_recv_once(sock: &Socket, r: &Resolved, buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
    let fd = sock.as_raw_fd();
    if r.caps.udp_gro {
        let (n, seg) = unsafe { net::accel::recv_gro(fd, buf)? };
        let pkts = if seg > 0 { n.div_ceil(seg).max(1) } else { 1 };
        Ok((n, pkts))
    } else if r.mmsg_batch > 1 && r.caps.sendmmsg {
        let slot = r.udp_datagram.max(2048);
        let slots = (buf.len() / slot).clamp(1, r.mmsg_batch as usize);
        unsafe { net::accel::recvmmsg_into(fd, buf, slot, slots) }
    } else {
        let n = net::recv_into(sock, buf)?;
        Ok((n, 1))
    }
}

#[cfg(not(target_os = "linux"))]
fn udp_recv_once(sock: &Socket, _r: &Resolved, buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
    let n = net::recv_into(sock, buf)?;
    Ok((n, 1))
}

fn is_transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    // ConnectionRefused on a connected UDP socket = an ICMP port-unreachable from
    // an earlier datagram; keep going rather than aborting the whole test.
    matches!(
        e.kind(),
        WouldBlock | TimedOut | Interrupted | ConnectionRefused
    )
}

// ---------- worker loops ----------

fn udp_send_loop(
    sock: &Socket,
    r: &Resolved,
    stats: &Stats,
    idx: usize,
    stop: &AtomicBool,
    cap: u64,
) {
    // Compat: each MikroTik UDP datagram begins with a 4-byte big-endian sequence
    // (counter+2), then payload (from the decompiled RouterOS btest.ko). Per-packet
    // sequencing precludes GSO, so send one datagram at a time.
    // io_uring batched send (turbo UDP, Linux) - one enter dispatches many sends.
    #[cfg(target_os = "linux")]
    if r.io_uring && r.mode == Mode::Turbo {
        let mut buf = vec![0u8; r.udp_datagram.max(64)];
        fill_payload(&mut buf, r.random);
        crate::uring::udp_send(sock.as_raw_fd(), &buf, stats, idx, stop, cap);
        return;
    }

    if r.mode == Mode::Compat {
        let mut buf = vec![0u8; r.udp_datagram.max(32)];
        fill_payload(&mut buf, r.random);
        let mut seq: u32 = 2;
        let mut pacer = Pacer::new(cap);
        while !stop.load(Ordering::Relaxed) {
            buf[0..4].copy_from_slice(&seq.to_be_bytes());
            match sock.send(&buf) {
                Ok(n) => {
                    stats.add_tx(idx, n as u64, 1);
                    pacer.account(n as u64);
                    seq = seq.wrapping_add(1);
                }
                Err(ref e) if is_transient(e) => continue,
                Err(_) => break,
            }
        }
        return;
    }

    let mut buf = Buffer::alloc(r.udp_super_len());
    fill_payload(&mut buf, r.random);
    let mut pacer = Pacer::new(cap);
    while !stop.load(Ordering::Relaxed) {
        match udp_send_once(sock, r, &buf) {
            Ok((n, p)) => {
                stats.add_tx(idx, n as u64, p as u64);
                pacer.account(n as u64);
            }
            Err(ref e) if is_transient(e) => continue,
            Err(_) => break,
        }
    }
}

fn udp_recv_loop(sock: &Socket, r: &Resolved, stats: &Stats, idx: usize, stop: &AtomicBool) {
    let mut buf = Buffer::alloc(r.udp_super_len().max(256 * 1024));
    let mut last_data = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        match udp_recv_once(sock, r, &mut buf) {
            Ok((0, _)) => {}
            Ok((n, p)) => {
                stats.add_rx(idx, n as u64, p as u64);
                last_data = Instant::now();
            }
            Err(ref e) if is_transient(e) => {}
            Err(_) => break,
        }
        // UDP has no close; treat a long silence as "peer gone".
        if last_data.elapsed() > Duration::from_secs(3) {
            break;
        }
    }
}

fn tcp_send_loop(
    mut sock: &Socket,
    r: &Resolved,
    stats: &Stats,
    idx: usize,
    stop: &AtomicBool,
    cap: u64,
) {
    let mut buf = Buffer::alloc(r.tcp_block);
    fill_payload(&mut buf, r.random);
    let mut pacer = Pacer::new(cap);
    while !stop.load(Ordering::Relaxed) {
        match sock.write(&buf) {
            Ok(0) => break,
            Ok(n) => {
                stats.add_tx(idx, n as u64, 1);
                pacer.account(n as u64);
            }
            Err(ref e) if is_transient(e) => continue,
            Err(_) => break,
        }
    }
}

fn tcp_recv_loop(mut sock: &Socket, r: &Resolved, stats: &Stats, idx: usize, stop: &AtomicBool) {
    let mut buf = vec![0u8; r.tcp_block];
    while !stop.load(Ordering::Relaxed) {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => stats.add_rx(idx, n as u64, 1),
            Err(ref e) if is_transient(e) => continue,
            Err(_) => break,
        }
    }
}

// ---------- job model ----------

enum Op {
    Send,
    Recv,
}
struct Job {
    worker: usize,
    sock_idx: usize,
    op: Op,
    cap: u64,
}

/// Run a set of jobs over the given sockets until `duration` elapses, driving
/// the live reporter. Returns the final snapshot.
/// Read the MikroTik `07` heartbeats off the control connection and record the
/// peer's *actually received* byte counts (what the other side got, vs what we
/// sent). Each message is 12 bytes: `07 XX 00 00 [secs u32 LE] [bytes u32 LE]`.
fn read_remote_07(ctrl: &std::net::TcpStream, stats: &Stats, stop: &AtomicBool) {
    let _ = ctrl.set_read_timeout(Some(Duration::from_millis(200)));
    let mut s: &std::net::TcpStream = ctrl;
    let mut acc: Vec<u8> = Vec::with_capacity(256);
    let mut buf = [0u8; 1024];
    while !stop.load(Ordering::Relaxed) {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                acc.extend_from_slice(&buf[..n]);
                let mut i = 0;
                while i + 12 <= acc.len() {
                    if acc[i] == STATS_OPCODE {
                        let b = u32::from_le_bytes([acc[i + 8], acc[i + 9], acc[i + 10], acc[i + 11]]);
                        stats.add_remote(b as u64);
                        i += 12;
                    } else {
                        i += 1; // resync
                    }
                }
                acc.drain(..i);
                if acc.len() > 4096 {
                    acc.clear();
                }
            }
            Err(ref e) if is_transient(e) => {}
            Err(_) => break,
        }
    }
}

fn run_jobs(
    socks: &[Socket],
    jobs: Vec<Job>,
    r: &Resolved,
    header: String,
    ctrl: Option<std::net::TcpStream>,
) -> Result<Snapshot> {
    let stats = Stats::new(r.workers.max(1));
    let stop = AtomicBool::new(false);
    // When every data worker has exited (peer gone / idle), end the session
    // promptly instead of waiting out the full timer (matters for the server,
    // whose compat duration defaults high).
    let active = std::sync::atomic::AtomicUsize::new(jobs.len().max(1));

    let timeout = Some(Duration::from_millis(250));
    for s in socks {
        let _ = s.set_read_timeout(timeout);
        let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    }

    let result = std::thread::scope(|scope| -> Result<Snapshot> {
        // data workers
        for (slot, job) in jobs.iter().enumerate() {
            let sock = &socks[job.sock_idx];
            let stats = &stats;
            let stop = &stop;
            let active = &active;
            let r = r;
            let cap = job.cap;
            let widx = job.worker;
            let op_send = matches!(job.op, Op::Send);
            std::thread::Builder::new()
                .name(format!("blast-w{slot}"))
                .spawn_scoped(scope, move || {
                    sys::pin_to_core(slot);
                    match (r.proto, op_send) {
                        (Protocol::Udp, true) => udp_send_loop(sock, r, stats, widx, stop, cap),
                        (Protocol::Udp, false) => udp_recv_loop(sock, r, stats, widx, stop),
                        (Protocol::Tcp, true) => tcp_send_loop(sock, r, stats, widx, stop, cap),
                        (Protocol::Tcp, false) => tcp_recv_loop(sock, r, stats, widx, stop),
                    }
                    active.fetch_sub(1, Ordering::Relaxed);
                })
                .expect("spawn worker");
        }

        // timer
        let stop_t = &stop;
        let dur = r.duration;
        scope.spawn(move || {
            let deadline = Instant::now() + dur;
            while Instant::now() < deadline && !stop_t.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
            }
            stop_t.store(true, Ordering::Relaxed);
        });

        // peer-received stats from the btest 07 heartbeats (compat control conn)
        if let Some(ref ctrl) = ctrl {
            if r.mode == Mode::Compat {
                let stats = &stats;
                let stop = &stop;
                scope.spawn(move || read_remote_07(ctrl, stats, stop));
            }
        }

        // reporter (this thread)
        let mut rep = ui::make_reporter(r.ui, header, r.caps.clone(), r.duration);
        let mut prev = stats.snapshot();
        let tick = Duration::from_millis(120);
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(tick);
            let now = stats.snapshot();
            let rate = now.rate_since(&prev);
            if rep.tick(&now, &rate, &stats.per_worker()) {
                stop.store(true, Ordering::Relaxed); // user pressed quit
            }
            if active.load(Ordering::Relaxed) == 0 {
                stop.store(true, Ordering::Relaxed); // all workers finished (peer gone)
            }
            prev = now;
        }
        let final_snap = stats.snapshot();
        rep.finish(&final_snap);
        Ok(final_snap)
    })?;

    Ok(result)
}

// ===================================================================
// CLIENT
// ===================================================================

pub fn run_client(r: &Resolved, server: SocketAddr) -> Result<()> {
    let header = format!(
        "blast {} client -> {}  [{:?} {:?}]",
        mode_str(r.mode),
        server,
        r.proto,
        r.direction
    );

    // Real MikroTik btest carries TCP data over the *control* connection itself,
    // so compat+TCP uses a dedicated path instead of separate data ports.
    if r.mode == Mode::Compat && r.proto == Protocol::Tcp {
        return run_client_compat_tcp(r, server, header);
    }

    // Control handshake on TCP.
    let mut ctrl = std::net::TcpStream::connect(server)
        .with_context(|| format!("connect control {server}"))?;
    ctrl.set_nodelay(true).ok();

    let data_base = match r.mode {
        Mode::Turbo => client_handshake_turbo(&mut ctrl, r)?,
        Mode::Compat => client_handshake_compat(&mut ctrl, r)?,
    };

    // Build data sockets + jobs.
    let server_ip = server.ip();
    let data_addr = SocketAddr::new(server_ip, server.port().wrapping_add(1));
    let (socks, jobs) = match r.proto {
        Protocol::Udp => client_udp_setup(r, server_ip, data_base)?,
        Protocol::Tcp => client_tcp_setup(r, data_addr)?,
    };

    // Hand the control connection to run_jobs: in compat it streams the 07
    // heartbeats with the peer's actually-received byte counts.
    let snap = run_jobs(&socks, jobs, r, header, Some(ctrl))?;
    let _ = snap;
    Ok(())
}

/// MikroTik-compatible TCP test: each connection does the control handshake and
/// then carries the bulk data itself (real btest multiplexes data on the
/// control socket, not on a separate data port).
fn run_client_compat_tcp(r: &Resolved, server: SocketAddr, header: String) -> Result<()> {
    let mut socks: Vec<Socket> = Vec::new();
    let mut jobs: Vec<Job> = Vec::new();
    let send_cap = per_worker(r.local_cap, r.workers, r.direction.local_sends());
    for i in 0..r.workers {
        let mut stream = std::net::TcpStream::connect(server)
            .with_context(|| format!("connect {server}"))?;
        stream.set_nodelay(true).ok();
        let _ = client_handshake_compat(&mut stream, r)?;
        let s = Socket::from(stream);
        net::tune_tcp_stream(&s);
        let primary = socks.len();
        if matches!(r.direction, Direction::Both) {
            let c = s.try_clone()?;
            socks.push(s);
            let sec = socks.len();
            socks.push(c);
            jobs.push(Job { worker: i, sock_idx: primary, op: Op::Send, cap: send_cap });
            jobs.push(Job { worker: i, sock_idx: sec, op: Op::Recv, cap: 0 });
        } else {
            socks.push(s);
            push_jobs(&mut jobs, i, primary, r.direction, send_cap);
        }
    }
    run_jobs(&socks, jobs, r, header, None)?;
    Ok(())
}

fn client_handshake_turbo(ctrl: &mut std::net::TcpStream, r: &Resolved) -> Result<u16> {
    ctrl.write_all(&[0x00])?; // role tag: control
    let p = TurboParams {
        proto: r.proto,
        direction: r.direction,
        random: r.random,
        workers: r.workers as u16,
        send_size: r.udp_super_len() as u32,
        gso_segment: r.gso_segment,
        local_speed: r.local_cap,
        remote_speed: r.remote_cap,
        duration_secs: r.duration.as_secs() as u32,
    };
    ctrl.write_all(&p.to_bytes())?;
    let mut reply = [0u8; 4];
    ctrl.read_exact(&mut reply)?;
    let base = u16::from_le_bytes([reply[0], reply[1]]);
    let status = u16::from_le_bytes([reply[2], reply[3]]);
    if status != 1 {
        bail!("server rejected turbo session (status {status})");
    }
    Ok(base)
}

fn client_handshake_compat(ctrl: &mut std::net::TcpStream, r: &Resolved) -> Result<u16> {
    // Server speaks first: 4-byte hello.
    let mut hello = [0u8; 4];
    ctrl.read_exact(&mut hello).context("read server hello")?;
    // Send 16-byte command (server performs the mirror).
    let cmd = Command {
        proto: r.proto,
        direction: r.direction,
        random: r.random,
        conn_count: r.workers as u8,
        remote_size: r.udp_datagram as u16,
        local_size: r.udp_datagram as u16,
        // MikroTik's wire speed fields are bits/sec; our caps are bytes/sec.
        remote_speed: r.remote_cap.saturating_mul(8).min(u32::MAX as u64) as u32,
        local_speed: r.local_cap.saturating_mul(8).min(u32::MAX as u64) as u32,
    };
    ctrl.write_all(&cmd.to_bytes())?;

    // Server response: ok / md5-challenge / srp.
    let mut resp = [0u8; 4];
    ctrl.read_exact(&mut resp)?;
    match resp[0] {
        0x01 => {} // ok, no auth
        0x02 => {
            let mut challenge = [0u8; 16];
            ctrl.read_exact(&mut challenge)?;
            let reply = md5_auth_reply(&r.user, &r.password, &challenge);
            ctrl.write_all(&reply)?;
            let mut res = [0u8; 4];
            ctrl.read_exact(&mut res)?;
            if res[0] != 0x01 {
                bail!("authentication failed");
            }
        }
        0x03 => bail!("server requires EC-SRP5 auth (RouterOS >= 6.43) - not yet implemented"),
        other => bail!("unexpected server response 0x{other:02x}"),
    }
    // For UDP, the server then sends a 2-byte big-endian base UDP port (it binds
    // `base` and sends to the client at `base+256`; the base is ephemeral - the
    // next free port from the server's "allocate UDP ports from", e.g. 2045).
    if r.proto == Protocol::Udp {
        let mut pb = [0u8; 2];
        ctrl.read_exact(&mut pb).context("read udp base port")?;
        return Ok(u16::from_be_bytes(pb));
    }
    Ok(2257)
}

/// Compat uses MikroTik's deterministic connected-UDP scheme (from the
/// decompiled orchestrators): client binds `base+256+i` and connects to the
/// server's single `base` port - no rendezvous packet. Turbo keeps ephemeral
/// local ports + a hello so the server can learn them.
pub const COMPAT_UDP_BASE: u16 = 2000;

fn client_udp_setup(r: &Resolved, server_ip: std::net::IpAddr, base: u16) -> Result<(Vec<Socket>, Vec<Job>)> {
    let mut socks = Vec::new();
    let mut jobs = Vec::new();
    let send_cap = per_worker(r.local_cap, r.workers, r.direction.local_sends());
    for i in 0..r.workers {
        let (local_port_v, remote_port_v, send_hello) = match r.mode {
            Mode::Turbo => (0u16, base + i as u16, true),
            // `base` is the server-advertised UDP base (read during the handshake).
            Mode::Compat => (base + 256 + i as u16, base, false),
        };
        let local: SocketAddr = match server_ip {
            std::net::IpAddr::V4(_) => format!("0.0.0.0:{local_port_v}").parse()?,
            std::net::IpAddr::V6(_) => format!("[::]:{local_port_v}").parse()?,
        };
        let remote = SocketAddr::new(server_ip, remote_port_v);
        let s = net::udp_data_socket(local, remote, r.caps.reuseport, net::DEFAULT_RCVBUF, net::DEFAULT_SNDBUF)
            .with_context(|| format!("udp worker {i}"))?;
        #[cfg(target_os = "linux")]
        if r.caps.udp_gro {
            unsafe { net::accel::enable_gro(s.as_raw_fd()); }
        }
        if send_hello {
            let _ = s.send(&[0xB1]); // turbo: let the server learn our ephemeral port
        }
        let sock_idx = socks.len();
        socks.push(s);
        push_jobs(&mut jobs, i, sock_idx, r.direction, send_cap);
    }
    Ok((socks, jobs))
}

fn client_tcp_setup(r: &Resolved, data_addr: SocketAddr) -> Result<(Vec<Socket>, Vec<Job>)> {
    let mut socks = Vec::new();
    let mut jobs = Vec::new();
    let send_cap = per_worker(r.local_cap, r.workers, r.direction.local_sends());
    for i in 0..r.workers {
        let s = connect_tcp_data(data_addr, r.mode)?;
        let need_clone = matches!(r.direction, Direction::Both);
        let primary = socks.len();
        if need_clone {
            let c = s.try_clone()?;
            socks.push(s);
            let secondary = socks.len();
            socks.push(c);
            jobs.push(Job { worker: i, sock_idx: primary, op: Op::Send, cap: send_cap });
            jobs.push(Job { worker: i, sock_idx: secondary, op: Op::Recv, cap: 0 });
        } else {
            socks.push(s);
            push_jobs(&mut jobs, i, primary, r.direction, send_cap);
        }
    }
    Ok((socks, jobs))
}

fn connect_tcp_data(server: SocketAddr, mode: Mode) -> Result<Socket> {
    let stream = std::net::TcpStream::connect(server)?;
    let s = Socket::from(stream);
    if mode == Mode::Turbo {
        s.send(&[0x01])?; // role tag: data
    }
    net::tune_tcp_stream(&s);
    Ok(s)
}

// ===================================================================
// SERVER
// ===================================================================

pub fn run_server(r: &Resolved, listen: SocketAddr) -> Result<()> {
    let listener = net::tcp_listener(listen, r.caps.reuseport)?;
    let std_listener: std::net::TcpListener = listener.into();
    ui::banner_server(&r.caps, listen);

    loop {
        let (ctrl, peer) = match std_listener.accept() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        // Handle each session on its own thread so a running test never blocks
        // new clients (the compat wire command carries no duration).
        let rc = r.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle_session(&rc, ctrl, peer, listen) {
                eprintln!("session from {peer} ended: {e:#}");
            }
        });
    }
}

fn handle_session(
    base_r: &Resolved,
    mut ctrl: std::net::TcpStream,
    peer: SocketAddr,
    listen: SocketAddr,
) -> Result<()> {
    ctrl.set_nodelay(true).ok();
    let mut r = base_r.clone();

    // ---- Phase 1: read the client's request (do not release it yet) ----
    let header = match base_r.mode {
        Mode::Turbo => {
            let mut tag = [0u8; 1];
            ctrl.read_exact(&mut tag)?;
            if tag[0] != 0x00 {
                return Ok(()); // stray data connection without a session
            }
            let mut hdr = [0u8; 40];
            ctrl.read_exact(&mut hdr)?;
            let p = TurboParams::from_bytes(&hdr)?;
            r.proto = p.proto;
            r.direction = p.direction.mirror(); // server mirrors the client
            r.random = p.random;
            r.workers = (p.workers as usize).max(1);
            r.gso_segment = p.gso_segment;
            r.local_cap = p.remote_speed; // server's tx cap == client's "remote"
            r.remote_cap = p.local_speed;
            r.duration = Duration::from_secs(p.duration_secs.max(1) as u64);
            format!("blast turbo server <- {} [{:?} {:?}]", peer, r.proto, r.direction)
        }
        Mode::Compat => {
            ctrl.write_all(&HELLO_OK)?; // server speaks first
            let mut cmd = [0u8; 16];
            ctrl.read_exact(&mut cmd)?;
            let c = Command::from_bytes(&cmd)?;
            r.proto = c.proto;
            r.direction = c.direction.mirror();
            r.random = c.random;
            r.workers = (c.conn_count as usize).max(1);
            r.local_cap = c.remote_speed as u64;
            r.remote_cap = c.local_speed as u64;
            format!("blast compat server <- {} [{:?} {:?}]", peer, r.proto, r.direction)
        }
    };

    let data_base = match base_r.mode {
        Mode::Turbo => listen.port().wrapping_add(1),
        Mode::Compat => 2001,
    };

    // GSO-accelerate the server's UDP send path (compat carries no GSO hint).
    if r.proto == Protocol::Udp && r.caps.udp_gso && r.gso_segment == 0 {
        r.gso_segment = r.udp_datagram as u16;
    }

    // Compat TCP carries data on the control connection itself (real btest);
    // handle it directly instead of binding a separate data port.
    if base_r.mode == Mode::Compat && r.proto == Protocol::Tcp {
        ctrl.write_all(&HELLO_OK)?; // release
        let s = Socket::from(ctrl);
        net::tune_tcp_stream(&s);
        let send_cap = per_worker(r.local_cap, r.workers, r.direction.local_sends());
        let (socks, jobs) = if matches!(r.direction, Direction::Both) {
            let c = s.try_clone()?;
            (
                vec![s, c],
                vec![
                    Job { worker: 0, sock_idx: 0, op: Op::Send, cap: send_cap },
                    Job { worker: 0, sock_idx: 1, op: Op::Recv, cap: 0 },
                ],
            )
        } else {
            let mut jobs = Vec::new();
            push_jobs(&mut jobs, 0, 0, r.direction, send_cap);
            (vec![s], jobs)
        };
        return run_jobs(&socks, jobs, &r, header, None).map(|_| ());
    }

    // ---- Phase 2: pre-bind data resources BEFORE the releasing ack ----
    // (Otherwise the client races ahead and connects to an unbound port.)
    enum Prebind {
        Udp(Vec<Socket>),
        UdpCompat(Vec<Socket>),
        Tcp(std::net::TcpListener),
    }
    let prebind = match (base_r.mode, r.proto) {
        (Mode::Compat, Protocol::Udp) => Prebind::UdpCompat(server_udp_compat_bind(&r, listen)?),
        (_, Protocol::Udp) => Prebind::Udp(server_udp_bind(&r, listen, data_base)?),
        (_, Protocol::Tcp) => Prebind::Tcp(server_tcp_bind(&r, listen)?),
    };

    // ---- Phase 3: releasing ack (now the client may safely connect) ----
    match base_r.mode {
        Mode::Turbo => {
            let mut reply = [0u8; 4];
            reply[0..2].copy_from_slice(&data_base.to_le_bytes());
            reply[2..4].copy_from_slice(&1u16.to_le_bytes());
            ctrl.write_all(&reply)?;
        }
        Mode::Compat => {
            ctrl.write_all(&HELLO_OK)?; // no auth in v1 server
            // UDP: advertise the base port the client must use (it binds base+256).
            if r.proto == Protocol::Udp {
                ctrl.write_all(&COMPAT_UDP_BASE.to_be_bytes())?;
            }
        }
    }

    // ---- Phase 4: complete (rendezvous / accept), then run ----
    let (socks, jobs) = match prebind {
        Prebind::Udp(socks) => server_udp_rendezvous(&r, socks)?,
        Prebind::UdpCompat(socks) => server_udp_compat_connect(&r, socks, peer.ip())?,
        Prebind::Tcp(dl) => server_tcp_accept(&r, dl)?,
    };
    let _ctrl_keepalive = ctrl;
    run_jobs(&socks, jobs, &r, header, None)?;
    Ok(())
}

/// Compat UDP server: bind every worker to the single `base` port (SO_REUSEPORT)
/// and connect each deterministically to the client's `base+256+i` - no
/// rendezvous, matching the decompiled MikroTik scheme.
fn server_udp_compat_bind(r: &Resolved, listen: SocketAddr) -> Result<Vec<Socket>> {
    let mut socks = Vec::new();
    for _ in 0..r.workers {
        let local = SocketAddr::new(listen.ip(), COMPAT_UDP_BASE);
        let s = net::udp_listen_socket(local, true, net::DEFAULT_RCVBUF)
            .with_context(|| format!("compat udp bind {local}"))?;
        let _ = s.set_send_buffer_size(net::DEFAULT_SNDBUF);
        socks.push(s);
    }
    Ok(socks)
}

fn server_udp_compat_connect(
    r: &Resolved,
    socks: Vec<Socket>,
    peer_ip: std::net::IpAddr,
) -> Result<(Vec<Socket>, Vec<Job>)> {
    let mut jobs = Vec::new();
    let send_cap = per_worker(r.local_cap, r.workers, r.direction.local_sends());
    for (i, s) in socks.iter().enumerate() {
        let client = SocketAddr::new(peer_ip, COMPAT_UDP_BASE + 256 + i as u16);
        s.connect(&client.into())
            .with_context(|| format!("compat udp connect {client}"))?;
        #[cfg(target_os = "linux")]
        if r.caps.udp_gro {
            unsafe { net::accel::enable_gro(s.as_raw_fd()); }
        }
        push_jobs(&mut jobs, i, i, r.direction, send_cap);
    }
    Ok((socks, jobs))
}

fn server_udp_bind(r: &Resolved, listen: SocketAddr, base: u16) -> Result<Vec<Socket>> {
    let mut socks = Vec::new();
    for i in 0..r.workers {
        let local = SocketAddr::new(listen.ip(), base + i as u16);
        let s = net::udp_listen_socket(local, r.caps.reuseport, net::DEFAULT_RCVBUF)
            .with_context(|| format!("udp server bind {local}"))?;
        let _ = s.set_send_buffer_size(net::DEFAULT_SNDBUF);
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        socks.push(s);
    }
    Ok(socks)
}

fn server_udp_rendezvous(r: &Resolved, socks: Vec<Socket>) -> Result<(Vec<Socket>, Vec<Job>)> {
    let mut jobs = Vec::new();
    let send_cap = per_worker(r.local_cap, r.workers, r.direction.local_sends());
    for (i, s) in socks.iter().enumerate() {
        // Wait for the client hello to learn its address, then connect.
        let mut tmp = [0u8; 64];
        let from = match net::recv_from_into(s, &mut tmp) {
            Ok((_, a)) => a,
            Err(ref e) if is_transient(e) => {
                return Err(anyhow!("client UDP worker {i} never arrived (timeout)"));
            }
            Err(e) => return Err(e.into()),
        };
        s.connect(&from)?;
        #[cfg(target_os = "linux")]
        if r.caps.udp_gro {
            unsafe { net::accel::enable_gro(s.as_raw_fd()); }
        }
        push_jobs(&mut jobs, i, i, r.direction, send_cap);
    }
    Ok((socks, jobs))
}

fn server_tcp_bind(r: &Resolved, listen: SocketAddr) -> Result<std::net::TcpListener> {
    let data_addr = SocketAddr::new(listen.ip(), listen.port().wrapping_add(1));
    let dl = net::tcp_listener(data_addr, r.caps.reuseport)
        .with_context(|| format!("tcp data listen {data_addr}"))?;
    let dl: std::net::TcpListener = dl.into();
    dl.set_nonblocking(false).ok();
    Ok(dl)
}

fn server_tcp_accept(r: &Resolved, dl: std::net::TcpListener) -> Result<(Vec<Socket>, Vec<Job>)> {
    let mut socks = Vec::new();
    let mut jobs = Vec::new();
    let send_cap = per_worker(r.local_cap, r.workers, r.direction.local_sends());
    for i in 0..r.workers {
        let (stream, _) = dl.accept()?;
        let s = Socket::from(stream);
        if r.mode == Mode::Turbo {
            let mut tag = [0u8; 1];
            let _ = net::recv_into(&s, &mut tag);
        }
        net::tune_tcp_stream(&s);
        let need_clone = matches!(r.direction, Direction::Both);
        let primary = socks.len();
        if need_clone {
            let c = s.try_clone()?;
            socks.push(s);
            let secondary = socks.len();
            socks.push(c);
            jobs.push(Job { worker: i, sock_idx: primary, op: Op::Send, cap: send_cap });
            jobs.push(Job { worker: i, sock_idx: secondary, op: Op::Recv, cap: 0 });
        } else {
            socks.push(s);
            push_jobs(&mut jobs, i, primary, r.direction, send_cap);
        }
    }
    Ok((socks, jobs))
}

// ---------- helpers ----------

fn mode_str(m: Mode) -> &'static str {
    match m {
        Mode::Compat => "compat",
        Mode::Turbo => "turbo",
    }
}

fn local_port(base: u16, i: usize) -> u16 {
    if base == 0 {
        0
    } else {
        base + i as u16
    }
}

fn per_worker(total_cap: u64, workers: usize, this_side_sends: bool) -> u64 {
    if !this_side_sends || total_cap == 0 || workers == 0 {
        0
    } else {
        (total_cap / workers as u64).max(1)
    }
}

/// Push the send/recv jobs for a worker. `local_dir` is THIS side's own
/// direction (already mirrored for the server in `handle_session`).
fn push_jobs(jobs: &mut Vec<Job>, worker: usize, sock_idx: usize, local_dir: Direction, send_cap: u64) {
    if local_dir.local_sends() {
        jobs.push(Job { worker, sock_idx, op: Op::Send, cap: send_cap });
    }
    if local_dir.local_recvs() {
        jobs.push(Job { worker, sock_idx, op: Op::Recv, cap: 0 });
    }
}
