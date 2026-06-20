//! LibreSpeed (LGPL) HTTP speedtest - the license-clean path to real speedtest
//! infrastructure. Client uses `ureq` (HTTP + rustls TLS); blast also ships a
//! minimal HTTP server (`garbage.php` / `empty.php` / `getIP.php`) so it is
//! self-testable and can act as a LibreSpeed backend.

use crate::stats::{fmt_bits, Stats};
use crate::sys::Caps;
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub struct LibreOpts {
    pub base_url: String, // e.g. http://host:port  (paths appended)
    pub duration: u32,    // seconds per phase
    pub streams: usize,
    pub json: bool,
    pub caps: Caps,
}

fn join(base: &str, path: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), path.trim_start_matches('/'))
}

// ===================================================================
// CLIENT (ureq)
// ===================================================================

pub fn run_client(o: &LibreOpts) -> Result<()> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(8))
        .build();

    if !o.json {
        println!("blast librespeed -> {}", o.base_url);
    }

    // ---- getIP (optional, informational) ----
    if let Ok(resp) = agent.get(&join(&o.base_url, "getIP.php")).call() {
        if let Ok(body) = resp.into_string() {
            if !o.json {
                let s = body.trim();
                println!("  Server says: {}", &s[..s.len().min(120)]);
            }
        }
    }

    // ---- ping / jitter: GET empty.php, measure RTT locally ----
    let ping_url = join(&o.base_url, "empty.php");
    let mut rtts = Vec::new();
    for _ in 0..8 {
        let t = Instant::now();
        if agent.get(&ping_url).call().is_ok() {
            rtts.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let ping = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
    let jitter = if rtts.len() > 1 {
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        rtts.iter().map(|r| (r - avg).abs()).sum::<f64>() / rtts.len() as f64
    } else {
        0.0
    };
    if ping.is_finite() && !o.json {
        println!("  Latency:  {ping:.2} ms   (jitter {jitter:.2} ms)");
    }

    // ---- download: GET garbage.php?ckSize=N, N streams, read for duration ----
    let down = phase(o, &agent, false)?;
    // ---- upload: POST empty.php, N streams, send for duration ----
    let up = phase(o, &agent, true)?;

    if o.json {
        println!(
            "{{\"server\":\"{}\",\"ping_ms\":{:.2},\"jitter_ms\":{:.2},\"download_bps\":{:.0},\"upload_bps\":{:.0}}}",
            o.base_url,
            if ping.is_finite() { ping } else { 0.0 },
            jitter,
            down,
            up
        );
    } else {
        println!("  Download: {}", fmt_bits(down));
        println!("  Upload:   {}", fmt_bits(up));
    }
    Ok(())
}

fn phase(o: &LibreOpts, agent: &ureq::Agent, upload: bool) -> Result<f64> {
    let stats = Stats::new(o.streams.max(1));
    let stop = AtomicBool::new(false);
    let dur = Duration::from_secs(o.duration.max(1) as u64);
    let base = o.base_url.clone();
    let label = if upload { "Upload" } else { "Download" };

    let result = std::thread::scope(|sc| -> f64 {
        for i in 0..o.streams.max(1) {
            let stats = &stats;
            let stop = &stop;
            let agent = agent.clone();
            let base = base.clone();
            sc.spawn(move || {
                if upload {
                    // Large fixed-length bodies amortize per-request overhead and
                    // keep the connection alive (Content-Length set by send_bytes).
                    let blob = vec![0x5au8; 16 << 20]; // 16 MiB per POST
                    let url = join(&base, "empty.php");
                    while !stop.load(Ordering::Relaxed) {
                        match agent
                            .post(&url)
                            .set("Content-Type", "application/octet-stream")
                            .send_bytes(&blob)
                        {
                            Ok(_) => stats.add_tx(i, blob.len() as u64, 1),
                            Err(_) => break,
                        }
                    }
                } else {
                    let url = join(&base, "garbage.php?ckSize=100");
                    let mut buf = vec![0u8; 256 * 1024];
                    while !stop.load(Ordering::Relaxed) {
                        if let Ok(resp) = agent.get(&url).call() {
                            let mut rd = resp.into_reader();
                            while !stop.load(Ordering::Relaxed) {
                                match rd.read(&mut buf) {
                                    Ok(0) => break,
                                    Ok(n) => stats.add_rx(i, n as u64, 1),
                                    Err(_) => break,
                                }
                            }
                        } else {
                            break;
                        }
                    }
                }
            });
        }
        // timer + live line
        let start = Instant::now();
        let mut prev = stats.snapshot();
        while start.elapsed() < dur {
            std::thread::sleep(Duration::from_millis(500));
            let now = stats.snapshot();
            let r = now.rate_since(&prev);
            let bps = if upload { r.tx_bps } else { r.rx_bps };
            if !o.json {
                print!("\r  {label}: {:<16}", fmt_bits(bps));
                let _ = std::io::stdout().flush();
            }
            prev = now;
        }
        stop.store(true, Ordering::Relaxed);
        let snap = stats.snapshot();
        if !o.json {
            print!("\r");
            let _ = std::io::stdout().flush();
        }
        let bytes = if upload { snap.tx_bytes } else { snap.rx_bytes };
        bytes as f64 * 8.0 / snap.elapsed.max(1e-9)
    });
    Ok(result)
}

/// A Read that tallies bytes into Stats as the HTTP body is consumed (upload).
struct CountReader<'a> {
    inner: &'a [u8],
    pos: usize,
    stats: &'a Stats,
    idx: usize,
}
impl Read for CountReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.inner.len() {
            return Ok(0);
        }
        let n = (self.inner.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.inner[self.pos..self.pos + n]);
        self.pos += n;
        self.stats.add_tx(self.idx, n as u64, 1);
        Ok(n)
    }
}

// ===================================================================
// SERVER (minimal HTTP/1.1)
// ===================================================================

pub fn run_server(listen: SocketAddr) -> Result<()> {
    let l = TcpListener::bind(listen).with_context(|| format!("librespeed bind {listen}"))?;
    println!("blast librespeed server on http://{listen}  (/garbage.php /empty.php /getIP.php)");
    for c in l.incoming() {
        if let Ok(s) = c {
            std::thread::spawn(move || {
                let _ = serve(s);
            });
        }
    }
    Ok(())
}

fn serve(mut s: TcpStream) -> Result<()> {
    s.set_nodelay(true).ok();
    loop {
        // Read request line + headers.
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        let mut content_len = 0usize;
        loop {
            let n = s.read(&mut b)?;
            if n == 0 {
                return Ok(());
            }
            head.push(b[0]);
            if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
                break;
            }
            if head.len() > 16384 {
                break;
            }
        }
        let text = String::from_utf8_lossy(&head);
        let mut lines = text.split("\r\n");
        let req = lines.next().unwrap_or("");
        let mut parts = req.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("/");
        for line in lines {
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_len = v.trim().parse().unwrap_or(0);
            }
        }

        if path.starts_with("/garbage.php") {
            let ck = path
                .split("ckSize=")
                .nth(1)
                .and_then(|s| s.split('&').next())
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(100)
                .clamp(1, 1024);
            let total = ck * 1024 * 1024;
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {total}\r\nConnection: keep-alive\r\nCache-Control: no-store\r\n\r\n"
            );
            s.write_all(hdr.as_bytes())?;
            let chunk = vec![0x41u8; 256 * 1024];
            let mut left = total;
            while left > 0 {
                let w = left.min(chunk.len());
                if s.write_all(&chunk[..w]).is_err() {
                    return Ok(());
                }
                left -= w;
            }
        } else if path.starts_with("/empty.php") || path.starts_with("/empty") {
            // Drain any POST body, then 200 empty.
            let mut left = content_len;
            let mut sink = vec![0u8; 256 * 1024];
            while left > 0 {
                let want = left.min(sink.len());
                let n = s.read(&mut sink[..want])?;
                if n == 0 {
                    break;
                }
                left -= n;
            }
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n")?;
        } else if path.starts_with("/getIP.php") {
            let body = "{\"processedString\":\"blast server\",\"rawIspInfo\":\"\"}";
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                body.len()
            );
            s.write_all(hdr.as_bytes())?;
            s.write_all(body.as_bytes())?;
        } else {
            s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")?;
        }
        let _ = method; // (all methods handled uniformly per path)
    }
}
