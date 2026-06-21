//! Classic **iperf2** (iperf 2.0.x) protocol - what Ubiquiti **airOS** uses for its
//! built-in "Speed Test" tool. Reverse-engineered from airOS 6.x firmware, whose
//! `/bin/iperf` is `iperf version 2.0.4 (7 Apr 2008)`. Verified wire-compatible
//! with the stock `iperf`(2) binary.
//!
//! Protocol (default TCP port 5001):
//! - **TCP**: a normal (unidirectional) test is just a raw data stream; the receiver
//!   times the bytes. No per-block header (that only appears for -d/-r dual tests).
//! - **UDP**: every datagram begins with a 12-byte `UDP_datagram` header
//!   (`int32 id`, `uint32 sec`, `uint32 usec`, network order). `id` counts up; the
//!   client signals end-of-test by sending a datagram whose `id` is negative. The
//!   server then returns a `server_hdr` report (total bytes, lost datagrams, jitter).

use anyhow::{Context, Result};
use socket2::{Domain, Socket, Type};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::stats::Stats;
use crate::sys::Caps;
use crate::{net, ui};

pub const IPERF2_PORT: u16 = 5001;
const UDP_HDR: usize = 12; // int32 id + uint32 sec + uint32 usec

pub struct Iperf2Opts {
    pub addr: SocketAddr, // client: the server; server: the listen address
    pub server: bool,
    pub udp: bool,
    pub duration: u32,
    pub parallel: usize,
    pub len: usize,
    pub bandwidth: u64, // bits/sec, 0 = unlimited
    pub ui: ui::UiKind,
    pub caps: Caps,
}

pub fn run(o: &Iperf2Opts) -> Result<()> {
    if o.server {
        run_server(o)
    } else {
        run_client(o)
    }
}

fn now_f64() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}
fn is_transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(e.kind(), WouldBlock | TimedOut | Interrupted)
}

// ---------------- client ----------------

fn run_client(o: &Iperf2Opts) -> Result<()> {
    let header = format!(
        "blast iperf2 client -> {}  [{} upload]",
        o.addr,
        if o.udp { "UDP" } else { "TCP" }
    );
    let n = o.parallel.max(1);
    let stats = Stats::new(n);
    let stop = AtomicBool::new(false);
    let dur = Duration::from_secs(o.duration.max(1) as u64);
    let per_cap = if o.bandwidth > 0 { o.bandwidth / 8 / n as u64 } else { 0 };
    let len = if o.len != 0 { o.len } else if o.udp { 1470 } else { 131072 };

    // Pre-connect so a refused server fails before we start the reporter.
    enum Conn {
        Tcp(TcpStream),
        Udp(UdpSocket),
    }
    let mut conns = Vec::with_capacity(n);
    for _ in 0..n {
        if o.udp {
            let u = UdpSocket::bind(if o.addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
            u.connect(o.addr).with_context(|| format!("udp connect {}", o.addr))?;
            conns.push(Conn::Udp(u));
        } else {
            let s = TcpStream::connect(o.addr).with_context(|| format!("connect {}", o.addr))?;
            s.set_nodelay(true).ok();
            conns.push(Conn::Tcp(s));
        }
    }

    let report = std::thread::scope(|sc| {
        for (i, c) in conns.into_iter().enumerate() {
            let stats = &stats;
            let stop = &stop;
            sc.spawn(move || match c {
                Conn::Tcp(s) => tcp_send(s, stats, i, stop, len, per_cap),
                Conn::Udp(u) => udp_send(u, stats, i, stop, len, per_cap, o.duration),
            });
        }
        // duration timer
        let stop_t = &stop;
        sc.spawn(move || {
            let end = Instant::now() + dur;
            while Instant::now() < end && !stop_t.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
            }
            stop_t.store(true, Ordering::Relaxed);
        });
        let mut rep = ui::make_reporter(o.ui, header.clone(), o.caps.clone(), dur);
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
        f
    });
    let _ = report;
    Ok(())
}

fn tcp_send(mut s: TcpStream, stats: &Stats, idx: usize, stop: &AtomicBool, len: usize, cap: u64) {
    let buf = vec![0u8; len.max(1)];
    let start = Instant::now();
    let mut sent: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        match s.write(&buf) {
            Ok(0) => break,
            Ok(w) => {
                stats.add_tx(idx, w as u64, 1);
                sent += w as u64;
                pace(cap, sent, start);
            }
            Err(ref e) if is_transient(e) => continue,
            Err(_) => break,
        }
    }
    let _ = s.shutdown(std::net::Shutdown::Write);
}

fn udp_send(u: UdpSocket, stats: &Stats, idx: usize, stop: &AtomicBool, len: usize, cap: u64, _dur: u32) {
    let len = len.max(UDP_HDR);
    let mut buf = vec![0u8; len];
    let start = Instant::now();
    let mut sent: u64 = 0;
    let mut id: i32 = 0;
    while !stop.load(Ordering::Relaxed) {
        id = id.wrapping_add(1);
        write_udp_hdr(&mut buf, id);
        match u.send(&buf) {
            Ok(w) => {
                stats.add_tx(idx, w as u64, 1);
                sent += w as u64;
                pace(cap, sent, start);
            }
            Err(ref e) if is_transient(e) => continue,
            Err(_) => break,
        }
    }
    // End-of-test: a few datagrams with a negative id, then read the server report.
    write_udp_hdr(&mut buf, -id);
    for _ in 0..10 {
        if u.send(&buf).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    u.set_read_timeout(Some(Duration::from_millis(800))).ok();
    let mut rb = [0u8; 256];
    if let Ok(r) = u.recv(&mut rb) {
        if let Some((lost, total, jitter)) = parse_server_report(&rb[..r]) {
            if total > 0 {
                println!(
                    "  server: {} lost / {} datagrams ({:.2}% loss), jitter {:.3} ms",
                    lost,
                    total,
                    lost as f64 / total as f64 * 100.0,
                    jitter * 1000.0
                );
            }
        }
    }
}

fn pace(cap: u64, sent: u64, start: Instant) {
    if cap > 0 {
        let target = sent as f64 / cap as f64;
        let elapsed = start.elapsed().as_secs_f64();
        if target > elapsed + 0.0005 {
            std::thread::sleep(Duration::from_secs_f64(target - elapsed));
        }
    }
}

fn write_udp_hdr(buf: &mut [u8], id: i32) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    buf[0..4].copy_from_slice(&id.to_be_bytes());
    buf[4..8].copy_from_slice(&(now.as_secs() as u32).to_be_bytes());
    buf[8..12].copy_from_slice(&now.subsec_micros().to_be_bytes());
}

/// Parse an iperf2 server_hdr report. The packet is a datagram-echo preamble (12 or
/// 16 bytes by version) then `server_hdr`: `flags, total_len1, total_len2, stop_sec,
/// stop_usec, error_cnt, outorder_cnt, datagrams, jitter1, jitter2` (network int32).
/// We locate it by the flags word's HEADER_VERSION1 bit (skipping the echo, whose id
/// FIN word also has the high bit). Returns (lost, total_datagrams, jitter_seconds).
fn parse_server_report(d: &[u8]) -> Option<(u64, u64, f64)> {
    let i32at = |o: usize| i32::from_be_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]);
    let mut o = UDP_HDR; // skip the 12-byte UDP_datagram echo
    let h = loop {
        if o + 40 > d.len() {
            return None;
        }
        if (i32at(o) as u32) & 0x8000_0000 != 0 {
            break o;
        }
        o += 4;
    };
    let error_cnt = i32at(h + 20) as i64; // lost
    let datagrams = i32at(h + 28) as i64; // total
    let jitter = i32at(h + 32) as i64 as f64 + i32at(h + 36) as i64 as f64 / 1e6;
    Some((error_cnt.max(0) as u64, datagrams.max(0) as u64, jitter))
}

// ---------------- server ----------------

fn run_server(o: &Iperf2Opts) -> Result<()> {
    println!(
        "blast iperf2 server  [{}]  listening on {}",
        if o.udp { "UDP" } else { "TCP" },
        o.addr
    );
    if o.udp {
        run_server_udp(o.addr)
    } else {
        run_server_tcp(o.addr, o.caps.reuseport)
    }
}

fn run_server_tcp(addr: SocketAddr, reuseport: bool) -> Result<()> {
    let listener: TcpListener = net::tcp_listener(addr, reuseport)?.into();
    for conn in listener.incoming() {
        let mut s = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
        let peer = s.peer_addr().ok();
        std::thread::spawn(move || {
            s.set_nodelay(true).ok();
            let mut buf = vec![0u8; 1 << 17];
            let mut total: u64 = 0;
            let mut start: Option<Instant> = None;
            loop {
                match s.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        start.get_or_insert_with(Instant::now);
                        total += n as u64;
                    }
                    Err(ref e) if is_transient(e) => continue,
                    Err(_) => break,
                }
            }
            let secs = start.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0).max(1e-9);
            let mbps = total as f64 * 8.0 / secs / 1e6;
            println!(
                "  [TCP] {} -> {:.2} MB in {:.2}s = {:.1} Mbit/s",
                peer.map(|p| p.to_string()).unwrap_or_default(),
                total as f64 / 1e6,
                secs,
                mbps
            );
        });
    }
    Ok(())
}

fn run_server_udp(addr: SocketAddr) -> Result<()> {
    let sock = Socket::new(Domain::for_address(addr), Type::DGRAM, None)?;
    sock.set_reuse_address(true).ok();
    sock.bind(&addr.into())?;
    let u: UdpSocket = sock.into();
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1 << 16];
    // Single in-flight test keyed by peer (radios test one stream at a time).
    let mut peer: Option<SocketAddr> = None;
    let mut total_bytes: u64 = 0;
    let mut count: u64 = 0;
    let mut highest: i32 = 0;
    let mut start: Option<Instant> = None;
    let mut jitter = 0.0f64;
    let mut prev_transit = 0.0f64;
    let mut have_prev = false;
    loop {
        let (n, from) = match u.recv_from(unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, buf.len())
        }) {
            Ok(v) => v,
            Err(ref e) if is_transient(e) => continue,
            Err(_) => continue,
        };
        let b = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        if n < UDP_HDR {
            continue;
        }
        let id = i32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let sec = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        let usec = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
        if peer != Some(from) && id >= 0 {
            // new test
            peer = Some(from);
            total_bytes = 0;
            count = 0;
            highest = 0;
            start = Some(Instant::now());
            jitter = 0.0;
            have_prev = false;
        }
        total_bytes += n as u64;
        count += 1;
        // jitter (RFC1889)
        let transit = now_f64() - (sec as f64 + usec as f64 * 1e-6);
        if have_prev {
            let dv = (transit - prev_transit).abs();
            jitter += (dv - jitter) / 16.0;
        }
        prev_transit = transit;
        have_prev = true;

        if id < 0 {
            // end of test: report and reply with a server_hdr
            let secs = start.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0).max(1e-9);
            let datagrams = highest.max(0) as u64;
            let lost = datagrams.saturating_sub(count - 1); // minus the FIN datagram
            let mbps = total_bytes as f64 * 8.0 / secs / 1e6;
            println!(
                "  [UDP] {} -> {:.2} MB, {:.1} Mbit/s, {} lost/{} ({:.2}%), jitter {:.3} ms",
                from,
                total_bytes as f64 / 1e6,
                mbps,
                lost,
                datagrams,
                if datagrams > 0 { lost as f64 / datagrams as f64 * 100.0 } else { 0.0 },
                jitter * 1000.0
            );
            let reply = build_server_report(total_bytes, secs, lost, datagrams, jitter);
            let _ = u.send_to(&reply, from);
            peer = None;
        } else if id > highest {
            highest = id;
        }
    }
}

fn build_server_report(bytes: u64, secs: f64, lost: u64, datagrams: u64, jitter: f64) -> Vec<u8> {
    // 16-byte datagram-echo preamble then the server_hdr, matching stock iperf2.
    let b = 16;
    let mut v = vec![0u8; b + 40];
    let put = |v: &mut [u8], o: usize, x: i32| v[o..o + 4].copy_from_slice(&x.to_be_bytes());
    put(&mut v, b, 0x80000000u32 as i32); // flags: HEADER_VERSION1
    put(&mut v, b + 4, (bytes >> 32) as i32); // total_len1
    put(&mut v, b + 8, (bytes & 0xffff_ffff) as i32); // total_len2
    put(&mut v, b + 12, secs as i32); // stop_sec
    put(&mut v, b + 16, ((secs.fract()) * 1e6) as i32); // stop_usec
    put(&mut v, b + 20, lost as i32); // error_cnt
    put(&mut v, b + 24, 0); // outorder_cnt
    put(&mut v, b + 28, datagrams as i32); // datagrams
    put(&mut v, b + 32, jitter as i32); // jitter1
    put(&mut v, b + 36, (jitter.fract() * 1e6) as i32); // jitter2
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn udp_hdr_roundtrip() {
        let mut b = [0u8; 12];
        write_udp_hdr(&mut b, -42);
        assert_eq!(i32::from_be_bytes([b[0], b[1], b[2], b[3]]), -42);
    }
    #[test]
    fn server_report_parses() {
        let r = build_server_report(1_000_000, 2.0, 7, 700, 0.003);
        let (lost, total, _j) = parse_server_report(&r).unwrap();
        assert_eq!(lost, 7);
        assert_eq!(total, 700);
    }
}
