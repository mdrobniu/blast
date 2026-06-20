//! Ookla-legacy "speedtest" protocol over a raw TCP socket (default :8080).
//!
//! Line commands: `HI` -> `HELLO <ver> <date> <salt>`, `PING <ms>` -> `PONG <ms>`,
//! `DOWNLOAD <n>` -> server streams n bytes, `UPLOAD <n> 0\n<n bytes>` ->
//! `OK <n> <ms>`, `QUIT`. blast implements both ends (self-testable) and a
//! speedtest-style client report (latency / download / upload). Interop with
//! third-party servers that speak this socket protocol is best-effort.

use crate::stats::{fmt_bits, Stats};
use crate::sys::{self, Caps};
use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct SpeedtestOpts {
    pub server: SocketAddr,
    pub duration: u32, // per phase (download, upload)
    pub streams: usize,
    pub json: bool,
    pub caps: Caps,
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Read a single `\n`-terminated line (commands are short and infrequent).
fn read_line(s: &mut TcpStream) -> Result<String> {
    let mut out = Vec::with_capacity(32);
    let mut b = [0u8; 1];
    loop {
        let n = s.read(&mut b)?;
        if n == 0 {
            break;
        }
        if b[0] == b'\n' {
            break;
        }
        out.push(b[0]);
    }
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

fn read_exact_counting(s: &mut TcpStream, mut n: usize, buf: &mut [u8]) -> std::io::Result<()> {
    while n > 0 {
        let want = n.min(buf.len());
        let got = s.read(&mut buf[..want])?;
        if got == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
        }
        n -= got;
    }
    Ok(())
}

// ===================================================================
// SERVER
// ===================================================================

pub fn run_server(listen: SocketAddr) -> Result<()> {
    let l = TcpListener::bind(listen).with_context(|| format!("speedtest bind {listen}"))?;
    println!("blast speedtest server listening on {listen}");
    for conn in l.incoming() {
        match conn {
            Ok(s) => {
                std::thread::spawn(move || {
                    let _ = handle_conn(s);
                });
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
    Ok(())
}

fn handle_conn(mut s: TcpStream) -> Result<()> {
    s.set_nodelay(true).ok();
    let payload = vec![0x33u8; 1 << 20]; // 1 MiB of filler reused for DOWNLOAD
    let mut sink = vec![0u8; 1 << 20];
    loop {
        let line = read_line(&mut s)?;
        if line.is_empty() {
            break;
        }
        let mut it = line.split_whitespace();
        match it.next() {
            Some("HI") => {
                s.write_all(b"HELLO 2.6 2024-01-01.1 blast\n")?;
            }
            Some("PING") => {
                let t = it.next().unwrap_or("0");
                s.write_all(format!("PONG {t}\n").as_bytes())?;
            }
            Some("DOWNLOAD") => {
                // Response is exactly n bytes: "DOWNLOAD " + filler + trailing "\n".
                let n: usize = it.next().unwrap_or("0").parse().unwrap_or(0);
                if n >= 10 {
                    s.write_all(b"DOWNLOAD ")?;
                    let mut left = n - 10;
                    while left > 0 {
                        let w = left.min(payload.len());
                        s.write_all(&payload[..w])?;
                        left -= w;
                    }
                    s.write_all(b"\n")?;
                } else if n > 0 {
                    s.write_all(&payload[..n.min(payload.len())])?;
                }
            }
            Some("UPLOAD") => {
                // <size> is INCLUSIVE of the "UPLOAD <size> 0\n" header line.
                let n: usize = it.next().unwrap_or("0").parse().unwrap_or(0);
                let header_len = format!("UPLOAD {n} 0\n").len();
                let payload_bytes = n.saturating_sub(header_len);
                let t0 = now_ms();
                read_exact_counting(&mut s, payload_bytes, &mut sink)?;
                let el = now_ms().saturating_sub(t0).max(1);
                s.write_all(format!("OK {n} {el}\n").as_bytes())?;
            }
            Some("QUIT") | None => break,
            _ => break,
        }
    }
    Ok(())
}

// ===================================================================
// CLIENT
// ===================================================================

pub fn run_client(o: &SpeedtestOpts) -> Result<()> {
    // --- handshake + latency on one connection ---
    let mut c = TcpStream::connect(o.server)
        .with_context(|| format!("connect speedtest {}", o.server))?;
    c.set_nodelay(true).ok();
    c.write_all(b"HI\n")?;
    let hello = read_line(&mut c)?;
    if !hello.starts_with("HELLO") {
        bail!("unexpected greeting: {hello:?}");
    }

    let mut rtts = Vec::new();
    for _ in 0..6 {
        let t = now_ms();
        c.write_all(format!("PING {t}\n").as_bytes())?;
        let line = read_line(&mut c)?;
        let rtt = now_ms().saturating_sub(t) as f64;
        if line.starts_with("PONG") {
            rtts.push(rtt);
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let _ = c.write_all(b"QUIT\n");
    let ping = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
    let jitter = if rtts.len() > 1 {
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        (rtts.iter().map(|r| (r - avg).abs()).sum::<f64>() / rtts.len() as f64).abs()
    } else {
        0.0
    };

    if !o.json {
        println!("blast speedtest -> {}", o.server);
        println!("  Latency:  {ping:.2} ms   (jitter {jitter:.2} ms)");
    }

    // --- download / upload phases over N parallel connections ---
    let down_bps = phase(o, false).context("download phase")?;
    let up_bps = phase(o, true).context("upload phase")?;

    if o.json {
        println!(
            "{{\"server\":\"{}\",\"ping_ms\":{:.2},\"jitter_ms\":{:.2},\"download_bps\":{:.0},\"upload_bps\":{:.0}}}",
            o.server, ping, jitter, down_bps, up_bps
        );
    } else {
        println!("  Download: {}", fmt_bits(down_bps));
        println!("  Upload:   {}", fmt_bits(up_bps));
    }
    Ok(())
}

/// Run one throughput phase (download or upload) for `duration` over N streams.
/// Returns average bits/sec.
fn phase(o: &SpeedtestOpts, upload: bool) -> Result<f64> {
    let stats = Stats::new(o.streams.max(1));
    let stop = AtomicBool::new(false);
    let chunk: usize = 4 << 20; // 4 MiB per command
    let dur = Duration::from_secs(o.duration.max(1) as u64);
    let label = if upload { "Upload" } else { "Download" };

    let result = std::thread::scope(|sc| -> f64 {
        for i in 0..o.streams.max(1) {
            let stats = &stats;
            let stop = &stop;
            let server = o.server;
            sc.spawn(move || {
                sys::pin_to_core(i);
                if let Ok(mut s) = TcpStream::connect(server) {
                    s.set_nodelay(true).ok();
                    let _ = s.write_all(b"HI\n");
                    let _ = read_line(&mut s);
                    let buf = vec![0x5au8; chunk];
                    let mut rbuf = vec![0u8; 1 << 20];
                    while !stop.load(Ordering::Relaxed) {
                        if upload {
                            // <size> includes the header line; send size - header payload bytes.
                            let header = format!("UPLOAD {chunk} 0\n");
                            if s.write_all(header.as_bytes()).is_err() {
                                break;
                            }
                            let mut left = chunk - header.len();
                            while left > 0 && !stop.load(Ordering::Relaxed) {
                                let want = left.min(buf.len());
                                match s.write(&buf[..want]) {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        stats.add_tx(i, n as u64, 1);
                                        left -= n;
                                    }
                                }
                            }
                            let _ = read_line(&mut s); // OK <n> <ms>
                        } else {
                            if s.write_all(format!("DOWNLOAD {chunk}\n").as_bytes()).is_err() {
                                break;
                            }
                            let mut left = chunk;
                            while left > 0 && !stop.load(Ordering::Relaxed) {
                                let want = left.min(rbuf.len());
                                match s.read(&mut rbuf[..want]) {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        stats.add_rx(i, n as u64, 1);
                                        left -= n;
                                    }
                                }
                            }
                        }
                    }
                    let _ = s.write_all(b"QUIT\n");
                }
            });
        }
        // timer + lightweight live line
        let start = Instant::now();
        let mut prev = stats.snapshot();
        while start.elapsed() < dur {
            std::thread::sleep(Duration::from_millis(500));
            let now = stats.snapshot();
            let r = now.rate_since(&prev);
            let bps = if upload { r.tx_bps } else { r.rx_bps };
            if !o.json {
                print!("\r  {label}: {:<14}", fmt_bits(bps));
                let _ = std::io::stdout().flush();
            }
            prev = now;
        }
        stop.store(true, Ordering::Relaxed);
        let snap = stats.snapshot();
        let bytes = if upload { snap.tx_bytes } else { snap.rx_bytes };
        if !o.json {
            print!("\r");
            let _ = std::io::stdout().flush();
        }
        bytes as f64 * 8.0 / snap.elapsed.max(1e-9)
    });
    Ok(result)
}
