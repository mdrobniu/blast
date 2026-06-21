//! iperf3-compatible client. Interoperates with `iperf3 -s`.
//!
//! Protocol (verified against esnet/iperf source): TCP control on :5201, a
//! 37-byte cookie, a single-byte state machine, length-prefixed JSON parameter
//! and results exchange, and N data streams (TCP raw bytes / UDP with a
//! per-datagram header). See the in-repo notes for citations.

use crate::stats::{Snapshot, Stats};
use crate::sys::{self, Caps};
use crate::ui;
use anyhow::{bail, Context, Result};
use socket2::Socket;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};

// ---- control state signals (signed char on the wire) ----
const TEST_START: i8 = 1;
const TEST_RUNNING: i8 = 2;
const TEST_END: i8 = 4;
const PARAM_EXCHANGE: i8 = 9;
const CREATE_STREAMS: i8 = 10;
const EXCHANGE_RESULTS: i8 = 13;
const DISPLAY_RESULTS: i8 = 14;
const IPERF_DONE: i8 = 16;
const ACCESS_DENIED: i8 = -1;
const SERVER_ERROR: i8 = -2;

const COOKIE_SIZE: usize = 37;
const RNDCHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

// UDP rendezvous magic (on-wire bytes, endianness-fixed in iperf).
const UDP_CONNECT_MSG: [u8; 4] = [0x36, 0x37, 0x38, 0x39]; // "6789"
const UDP_CONNECT_REPLY: [u8; 4] = [0x39, 0x38, 0x37, 0x36]; // "9876"

pub struct IperfOpts {
    pub server: SocketAddr,
    pub udp: bool,
    pub reverse: bool, // -R: server sends, client receives
    pub duration: u32,
    pub parallel: usize,
    pub len: usize,        // block size
    pub bandwidth: u64,    // target bits/sec (UDP); 0 = unlimited
    pub ui: ui::UiKind,
    pub caps: Caps,
}

fn fill_rand(buf: &mut [u8]) {
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(buf).is_ok() {
            return;
        }
    }
    // Fallback PRNG seeded by wall clock.
    let mut x = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x1234_5678)
        | 1;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
}

fn make_cookie() -> [u8; COOKIE_SIZE] {
    let mut c = [0u8; COOKIE_SIZE];
    fill_rand(&mut c[..COOKIE_SIZE - 1]);
    for b in c.iter_mut().take(COOKIE_SIZE - 1) {
        *b = RNDCHARS[(*b as usize) % RNDCHARS.len()];
    }
    c[COOKIE_SIZE - 1] = 0;
    c
}

fn read_state(ctrl: &mut TcpStream) -> Result<i8> {
    let mut b = [0u8; 1];
    ctrl.read_exact(&mut b).context("read control state")?;
    Ok(b[0] as i8)
}

fn write_state(ctrl: &mut TcpStream, st: i8) -> Result<()> {
    ctrl.write_all(&[st as u8])?;
    Ok(())
}

fn write_json(ctrl: &mut TcpStream, v: &serde_json::Value) -> Result<()> {
    let body = serde_json::to_vec(v)?;
    ctrl.write_all(&(body.len() as u32).to_be_bytes())?;
    ctrl.write_all(&body)?;
    Ok(())
}

fn read_json(ctrl: &mut TcpStream) -> Result<serde_json::Value> {
    let mut lb = [0u8; 4];
    ctrl.read_exact(&mut lb).context("read json length")?;
    let n = u32::from_be_bytes(lb) as usize;
    let mut body = vec![0u8; n];
    ctrl.read_exact(&mut body)
        .with_context(|| format!("read json body ({n} bytes)"))?;
    serde_json::from_slice(&body).context("parse json")
}

pub fn run_client(opts: &IperfOpts) -> Result<()> {
    let header = format!(
        "blast iperf3 client -> {}  [{} {}]",
        opts.server,
        if opts.udp { "UDP" } else { "TCP" },
        if opts.reverse { "reverse/download" } else { "forward/upload" }
    );

    let mut ctrl = TcpStream::connect(opts.server)
        .with_context(|| format!("connect iperf3 control {}", opts.server))?;
    ctrl.set_nodelay(true).ok();
    let cookie = make_cookie();
    ctrl.write_all(&cookie)?;

    let mut streams: Vec<Stream> = Vec::new();
    let mut final_snap = Snapshot::default();
    let mut udp_losses: Vec<StreamLoss> = Vec::new();

    loop {
        let st = read_state(&mut ctrl)?;
        match st {
            PARAM_EXCHANGE => write_json(&mut ctrl, &build_params(opts))?,
            CREATE_STREAMS => streams = create_streams(opts, &cookie)?,
            TEST_START => { /* timers init implicitly when streams run */ }
            TEST_RUNNING => {
                // Client receives in reverse mode, otherwise sends.
                let (snap, losses) = run_streams(&streams, opts, opts.reverse, header.clone())?;
                final_snap = snap;
                udp_losses = losses;
                write_state(&mut ctrl, TEST_END)?; // client ends the test
                // Signal EOF on the data streams so the server can finalize and
                // send its results (it waits for every stream, esp. with -P>1).
                if !opts.udp && !opts.reverse {
                    for s in &streams {
                        let _ = s.sock.shutdown(std::net::Shutdown::Write);
                    }
                }
            }
            EXCHANGE_RESULTS => {
                write_json(&mut ctrl, &build_results(&final_snap, &streams, &udp_losses))?;
                let server_results = read_json(&mut ctrl)?;
                // For forward UDP the server is the receiver and holds the real loss;
                // for reverse UDP we measured it ourselves. Show whichever applies.
                if opts.udp {
                    let shown = if opts.reverse {
                        let lost: u64 = udp_losses.iter().map(|l| l.lost).sum();
                        let total: u64 = udp_losses.iter().map(|l| l.total).sum();
                        let jit = udp_losses.iter().map(|l| l.jitter).fold(0.0, f64::max);
                        (total > 0).then_some((lost, total, jit))
                    } else {
                        udp_loss_from_results(&server_results).filter(|(_, t, _)| *t > 0)
                    };
                    if let Some((lost, total, jitter)) = shown {
                        println!(
                            "  datagrams: {} lost / {} ({:.2}% loss), jitter {:.3} ms",
                            lost,
                            total,
                            lost as f64 / total as f64 * 100.0,
                            jitter * 1000.0
                        );
                    }
                }
            }
            DISPLAY_RESULTS => {
                write_state(&mut ctrl, IPERF_DONE)?;
                break;
            }
            IPERF_DONE => break,
            ACCESS_DENIED => bail!("iperf3 server denied access (another test in progress?)"),
            SERVER_ERROR => {
                let mut e = [0u8; 8];
                let _ = ctrl.read_exact(&mut e);
                let ierr = i32::from_be_bytes([e[0], e[1], e[2], e[3]]);
                let serr = i32::from_be_bytes([e[4], e[5], e[6], e[7]]);
                bail!("iperf3 server error: i_errno={ierr} errno={serr}");
            }
            other => {
                // TEST_END or unknown - keep reading.
                let _ = other;
            }
        }
    }
    Ok(())
}

fn build_params(o: &IperfOpts) -> serde_json::Value {
    use serde_json::json;
    let mut p = json!({
        "client_version": "3.9",
        "time": o.duration,
        "parallel": o.parallel,
        "len": o.len,
    });
    let m = p.as_object_mut().unwrap();
    if o.udp {
        m.insert("udp".into(), json!(true));
        // Default 32-bit packet counters (12-byte datagram header).
        m.insert("bandwidth".into(), json!(o.bandwidth));
    } else {
        m.insert("tcp".into(), json!(true));
        if o.bandwidth > 0 {
            m.insert("bandwidth".into(), json!(o.bandwidth));
        }
    }
    if o.reverse {
        m.insert("reverse".into(), json!(true));
    }
    p
}

fn build_results(snap: &Snapshot, streams: &[Stream], losses: &[StreamLoss]) -> serde_json::Value {
    use serde_json::json;
    let n = streams.len().max(1) as u64;
    let per = (snap.tx_bytes + snap.rx_bytes) / n;
    // iperf3 stream-id quirk (iperf_add_stream): stream 0 -> id 1, stream k>=1 -> id k+2.
    let arr: Vec<serde_json::Value> = (0..streams.len())
        .map(|i| {
            let id = if i == 0 { 1 } else { i + 2 };
            // When we were the UDP receiver, report the loss/jitter we measured.
            let (errors, packets, jitter) = match losses.get(i) {
                Some(l) if l.total > 0 => (l.lost, l.total, l.jitter),
                _ => (0, (snap.tx_pkts + snap.rx_pkts) / n, 0.0),
            };
            json!({
                "id": id,
                "bytes": per,
                "retransmits": 0,
                "jitter": jitter,
                "errors": errors,
                "packets": packets,
                "start_time": 0.0,
                "end_time": snap.elapsed,
            })
        })
        .collect();
    json!({
        "cpu_util_total": 0.0,
        "cpu_util_user": 0.0,
        "cpu_util_system": 0.0,
        "sender_has_retransmits": 0,
        "streams": arr,
    })
}

struct Stream {
    sock: Socket,
    udp: bool,
}

/// Receiver-side UDP loss/jitter accumulator (one per stream), filled by `udp_recv`.
#[derive(Default)]
struct UdpRx {
    highest: AtomicU32,    // highest sequence number seen
    count: AtomicU64,      // datagrams received
    jitter_bits: AtomicU64, // RFC1889 jitter in seconds, stored as f64 bits
}
struct StreamLoss {
    lost: u64,
    total: u64,
    jitter: f64,
}
impl UdpRx {
    fn result(&self) -> StreamLoss {
        let total = self.highest.load(Ordering::Relaxed) as u64;
        let count = self.count.load(Ordering::Relaxed);
        StreamLoss {
            lost: total.saturating_sub(count),
            total,
            jitter: f64::from_bits(self.jitter_bits.load(Ordering::Relaxed)),
        }
    }
}

/// Sum the UDP loss/jitter out of an iperf3 results JSON (the peer's `streams`).
fn udp_loss_from_results(v: &serde_json::Value) -> Option<(u64, u64, f64)> {
    let streams = v.get("streams")?.as_array()?;
    let (mut lost, mut total, mut jitter) = (0u64, 0u64, 0.0f64);
    for s in streams {
        lost += s.get("errors").and_then(|x| x.as_u64()).unwrap_or(0);
        total += s.get("packets").and_then(|x| x.as_u64()).unwrap_or(0);
        let j = s.get("jitter").and_then(|x| x.as_f64()).unwrap_or(0.0);
        if j > jitter {
            jitter = j;
        }
    }
    Some((lost, total, jitter))
}

fn create_streams(o: &IperfOpts, cookie: &[u8; COOKIE_SIZE]) -> Result<Vec<Stream>> {
    let mut v = Vec::with_capacity(o.parallel);
    for i in 0..o.parallel {
        if o.udp {
            let u = UdpSocket::bind(if o.server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
            u.connect(o.server)?;
            u.set_read_timeout(Some(Duration::from_millis(800)))?;
            // Rendezvous: send "6789" EXACTLY ONCE (the server's accept consumes
            // one datagram; any resend leaks into the data stream and is counted
            // as packet #1 with pcount 0x36373839). Best-effort drain "9876".
            u.send(&UDP_CONNECT_MSG)?;
            let mut buf = [0u8; 16];
            let _ = u.recv(&mut buf);
            let s = unsafe { Socket::from_raw_fd(u.into_raw_fd()) };
            let _ = s.set_send_buffer_size(crate::net::DEFAULT_SNDBUF);
            let _ = s.set_recv_buffer_size(crate::net::DEFAULT_RCVBUF);
            v.push(Stream { sock: s, udp: true });
        } else {
            let mut t = TcpStream::connect(o.server)
                .with_context(|| format!("iperf3 stream {i} connect"))?;
            t.set_nodelay(true).ok();
            t.write_all(cookie)?; // associate the stream with the test
            let s = Socket::from(t);
            crate::net::tune_tcp_stream(&s);
            v.push(Stream { sock: s, udp: false });
        }
    }
    Ok(v)
}

// ---- data plane ----

fn run_streams(
    streams: &[Stream],
    o: &IperfOpts,
    client_recv: bool,
    header: String,
) -> Result<(Snapshot, Vec<StreamLoss>)> {
    let stats = Stats::new(streams.len().max(1));
    let udp_rx: Vec<UdpRx> = (0..streams.len().max(1)).map(|_| UdpRx::default()).collect();
    let stop = AtomicBool::new(false);
    for s in streams {
        let _ = s.sock.set_read_timeout(Some(Duration::from_millis(250)));
        let _ = s.sock.set_write_timeout(Some(Duration::from_secs(2)));
    }
    let dur = Duration::from_secs(o.duration.max(1) as u64);
    let per_stream_bw = if o.bandwidth > 0 {
        o.bandwidth / 8 / streams.len().max(1) as u64
    } else {
        0
    };

    std::thread::scope(|sc| {
        for (i, st) in streams.iter().enumerate() {
            let stats = &stats;
            let stop = &stop;
            let len = o.len;
            let udp = st.udp;
            let sock = &st.sock;
            let rx = &udp_rx[i];
            sc.spawn(move || {
                sys::pin_to_core(i);
                match (udp, client_recv) {
                    (false, false) => tcp_send(sock, stats, i, stop, len),
                    (false, true) => tcp_recv(sock, stats, i, stop, len),
                    (true, false) => udp_send(sock, stats, i, stop, len, per_stream_bw),
                    (true, true) => udp_recv(sock, stats, i, stop, len, rx),
                }
            });
        }
        let stop_t = &stop;
        sc.spawn(move || {
            let end = Instant::now() + dur;
            while Instant::now() < end && !stop_t.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
            }
            stop_t.store(true, Ordering::Relaxed);
        });
        let mut rep = ui::make_reporter(o.ui, header, o.caps.clone(), dur);
        let mut prev = stats.snapshot();
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(120));
            let now = stats.snapshot();
            let rate = now.rate_since(&prev);
            if rep.tick(&now, &rate, &stats.per_worker()) {
                stop.store(true, Ordering::Relaxed);
            }
            prev = now;
        }
        let f = stats.snapshot();
        rep.finish(&f);
    });
    let losses = udp_rx.iter().map(|r| r.result()).collect();
    Ok((stats.snapshot(), losses))
}

fn is_transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(e.kind(), WouldBlock | TimedOut | Interrupted)
}

fn tcp_send(sock: &Socket, stats: &Stats, idx: usize, stop: &AtomicBool, len: usize) {
    let buf = vec![0u8; len.max(1)];
    let mut s = sock;
    while !stop.load(Ordering::Relaxed) {
        match s.write(&buf) {
            Ok(0) => break,
            Ok(n) => stats.add_tx(idx, n as u64, 1),
            Err(ref e) if is_transient(e) => continue,
            Err(_) => break,
        }
    }
}

fn tcp_recv(sock: &Socket, stats: &Stats, idx: usize, stop: &AtomicBool, len: usize) {
    let mut buf = vec![0u8; len.max(65536)];
    let mut s = sock;
    while !stop.load(Ordering::Relaxed) {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => stats.add_rx(idx, n as u64, 1),
            Err(ref e) if is_transient(e) => continue,
            Err(_) => break,
        }
    }
}

fn udp_header(buf: &mut [u8], seq: u32) {
    // 32-bit counter layout (12 bytes): sec, usec, pcount - all network order.
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    buf[0..4].copy_from_slice(&(now.as_secs() as u32).to_be_bytes());
    buf[4..8].copy_from_slice(&(now.subsec_micros()).to_be_bytes());
    buf[8..12].copy_from_slice(&seq.to_be_bytes());
}

fn udp_send(sock: &Socket, stats: &Stats, idx: usize, stop: &AtomicBool, len: usize, bw: u64) {
    let len = len.max(12);
    let mut buf = vec![0u8; len];
    let mut seq: u32 = 0;
    let start = Instant::now();
    let mut sent: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        seq += 1;
        udp_header(&mut buf, seq);
        match sock.send(&buf) {
            Ok(n) => {
                stats.add_tx(idx, n as u64, 1);
                sent += n as u64;
                if bw > 0 {
                    let target = sent as f64 / bw as f64;
                    let elapsed = start.elapsed().as_secs_f64();
                    if target > elapsed + 0.0005 {
                        std::thread::sleep(Duration::from_secs_f64(target - elapsed));
                    }
                }
            }
            Err(ref e) if is_transient(e) => continue,
            Err(_) => break,
        }
    }
}

fn udp_recv(sock: &Socket, stats: &Stats, idx: usize, stop: &AtomicBool, len: usize, rx: &UdpRx) {
    let mut buf = vec![std::mem::MaybeUninit::<u8>::uninit(); len.max(65536)];
    let mut jitter = 0.0f64;
    let mut prev_transit = 0.0f64;
    let mut have_prev = false;
    while !stop.load(Ordering::Relaxed) {
        match sock.recv(&mut buf) {
            Ok(0) => continue,
            Ok(n) => {
                stats.add_rx(idx, n as u64, 1);
                if n >= 12 {
                    // header: sec, usec, pcount (all BE); first 12 bytes are initialized.
                    let h = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, 12) };
                    let sec = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
                    let usec = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
                    let pcount = u32::from_be_bytes([h[8], h[9], h[10], h[11]]);
                    rx.count.fetch_add(1, Ordering::Relaxed);
                    rx.highest.fetch_max(pcount, Ordering::Relaxed);
                    // RFC1889 jitter from the one-way transit delta.
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
                    let sent = sec as f64 + usec as f64 * 1e-6;
                    let transit = now - sent;
                    if have_prev {
                        let d = (transit - prev_transit).abs();
                        jitter += (d - jitter) / 16.0;
                    }
                    prev_transit = transit;
                    have_prev = true;
                }
            }
            Err(ref e) if is_transient(e) => continue,
            Err(_) => break,
        }
    }
    rx.jitter_bits.store(jitter.to_bits(), Ordering::Relaxed);
}

// Touch fd traits so cfg(unix)-only imports aren't flagged unused on other OSes.
#[cfg(unix)]
#[allow(dead_code)]
fn _fd_touch(s: &Socket) -> i32 {
    s.as_raw_fd()
}
