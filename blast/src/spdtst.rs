//! Ubiquiti airOS **Speed Test** protocol (`spdtst.ko`), reverse-engineered from
//! airOS 6.x firmware (Ghidra) and a live XW.v6.3.11 radio. See research notes in
//! `SPDTST.md`. This is the airOS equivalent of MikroTik btest (and is NOT iperf -
//! `/bin/iperf` on the radio is only the manual CLI).
//!
//! Wire format (UDP, big-endian), CONFIRMED from `st_build_packet` / `st_nf_rx`:
//!   header(12) = magic 0xDA51A514 | version 0x01 | msg_type | length(u16) | session(u32)
//!   PARAMS(type 1) payload(12) = direction(u32) duration(u32) datasize(u16) datarate(u16)
//!   RESULTS payload(80) = counters
//!
//! Caveat: the real module is a *bridge-path* link tester - its receive hook only fires
//! on traffic forwarded through a radio, so it can't be driven host-to-host. This is a
//! faithful blast<->blast implementation of the wire format; the non-PARAMS message
//! codes / data-phase are provisional (marked below) pending a capture of a real link.

use anyhow::{bail, Context, Result};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::sys::Caps;
use crate::ui;

pub const MAGIC: u32 = 0xDA51_A514;
pub const SPDTST_PORT: u16 = 16569; // blast<->blast transport (real spdtst matches by magic, not port)
const VERSION: u8 = 0x01;

// message types - PARAMS=1 is confirmed; the rest are provisional (consistent for
// blast<->blast) until a real bridged-link capture pins them.
const M_PARAMS: u8 = 1;
const M_PARAMS_ACK: u8 = 2;
const M_RX_READY: u8 = 3;
const M_DATA: u8 = 5;
const M_DATA_END: u8 = 7;
const M_RESULTS: u8 = 8;
const M_FINISH: u8 = 9;

#[derive(Copy, Clone, PartialEq)]
pub enum Dir {
    Rx,
    Tx,
    Dx,
}
impl Dir {
    fn code(self) -> u32 {
        match self {
            Dir::Rx => 0,
            Dir::Tx => 2,
            Dir::Dx => 3,
        }
    }
}

pub struct SpdtstOpts {
    pub addr: SocketAddr, // master: peer; slave: listen
    pub server: bool,     // slave (listen) vs master
    pub duration: u32,
    pub direction: Dir,
    pub datasize: u16, // datagram payload size
    pub datarate: u16, // rate hint (Mbit/s; 0 = unlimited)
    pub ui: ui::UiKind,
    pub caps: Caps,
}

fn put_hdr(buf: &mut [u8], msgtype: u8, session: u32, payload_len: usize) {
    buf[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    buf[4] = VERSION;
    buf[5] = msgtype;
    buf[6..8].copy_from_slice(&((12 + payload_len) as u16).to_be_bytes());
    buf[8..12].copy_from_slice(&session.to_be_bytes());
}
fn parse_hdr(b: &[u8]) -> Option<(u8, u32)> {
    if b.len() < 12 || u32::from_be_bytes([b[0], b[1], b[2], b[3]]) != MAGIC {
        return None;
    }
    Some((b[5], u32::from_be_bytes([b[8], b[9], b[10], b[11]])))
}

pub fn run(o: &SpdtstOpts) -> Result<()> {
    if o.server {
        run_slave(o)
    } else {
        run_master(o)
    }
}

// ---------------- master ----------------

fn run_master(o: &SpdtstOpts) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(o.addr).with_context(|| format!("connect {}", o.addr))?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;
    let session: u32 = std::process::id().wrapping_mul(0x9E37_79B1).wrapping_add(o.duration).max(1);

    // PARAMS
    let mut p = [0u8; 24];
    put_hdr(&mut p, M_PARAMS, session, 12);
    p[12..16].copy_from_slice(&o.direction.code().to_be_bytes());
    p[16..20].copy_from_slice(&o.duration.to_be_bytes());
    p[20..22].copy_from_slice(&o.datasize.to_be_bytes());
    p[22..24].copy_from_slice(&o.datarate.to_be_bytes());
    // retry PARAMS until the slave acks (RX_READY)
    let mut ready = false;
    for _ in 0..20 {
        sock.send(&p)?;
        let mut rb = [0u8; 64];
        if let Ok(n) = sock.recv(&mut rb) {
            if let Some((mt, _)) = parse_hdr(&rb[..n]) {
                if mt == M_RX_READY || mt == M_PARAMS_ACK {
                    ready = true;
                    if mt == M_RX_READY {
                        break;
                    }
                }
            }
        }
    }
    if !ready {
        bail!("no PARAMS_ACK/RX_READY from {} (is it running `blast spdtst --server`?)", o.addr);
    }

    // DATA phase
    let header = format!("blast spdtst master -> {}  [{} {}s]", o.addr, dir_str(o.direction), o.duration);
    let dur = Duration::from_secs(o.duration.max(1) as u64);
    let size = (o.datasize as usize).max(12).min(1472);
    let mut buf = vec![0u8; size];
    let cap_bytes = if o.datarate > 0 { o.datarate as u64 * 1_000_000 / 8 } else { 0 };
    let start = Instant::now();
    let mut sent_bytes: u64 = 0;
    let mut sent_pkts: u64 = 0;
    let mut rep = ui::make_reporter(o.ui, header, o.caps.clone(), dur);
    let stats = crate::stats::Stats::new(1);
    let mut prev = stats.snapshot();
    let mut last_tick = Instant::now();
    while start.elapsed() < dur {
        put_hdr(&mut buf, M_DATA, session, size - 12);
        match sock.send(&buf) {
            Ok(n) => {
                sent_bytes += n as u64;
                sent_pkts += 1;
                stats.add_tx(0, n as u64, 1);
            }
            Err(_) => {}
        }
        if cap_bytes > 0 {
            let target = sent_bytes as f64 / cap_bytes as f64;
            let el = start.elapsed().as_secs_f64();
            if target > el + 0.0005 {
                std::thread::sleep(Duration::from_secs_f64(target - el));
            }
        }
        if last_tick.elapsed() >= Duration::from_millis(120) {
            let now = stats.snapshot();
            let rate = now.rate_since(&prev);
            rep.tick(&now, &rate, &stats.per_worker());
            prev = now;
            last_tick = Instant::now();
        }
    }
    // DATA_END, then collect RESULTS
    let mut end = [0u8; 12];
    put_hdr(&mut end, M_DATA_END, session, 0);
    let mut peer_bytes: u64 = 0;
    let mut peer_pkts: u64 = 0;
    for _ in 0..10 {
        sock.send(&end)?;
        let mut rb = [0u8; 128];
        if let Ok(n) = sock.recv(&mut rb) {
            if let Some((mt, _)) = parse_hdr(&rb[..n]) {
                if mt == M_RESULTS && n >= 12 + 16 {
                    peer_bytes = u64::from_be_bytes(rb[12..20].try_into().unwrap());
                    peer_pkts = u64::from_be_bytes(rb[20..28].try_into().unwrap());
                    break;
                }
            }
        }
    }
    let mut fin = [0u8; 12];
    put_hdr(&mut fin, M_FINISH, session, 0);
    let _ = sock.send(&fin);

    let snap = stats.snapshot();
    rep.finish(&snap);
    let secs = start.elapsed().as_secs_f64().max(1e-9);
    println!(
        "  spdtst: sent {:.1} MB ({} pkts), peer received {:.1} MB ({} pkts) -> {:.2}% loss",
        sent_bytes as f64 / 1e6,
        sent_pkts,
        peer_bytes as f64 / 1e6,
        peer_pkts,
        if sent_pkts > 0 { (sent_pkts.saturating_sub(peer_pkts)) as f64 / sent_pkts as f64 * 100.0 } else { 0.0 }
    );
    let _ = secs;
    Ok(())
}

// ---------------- slave (server) ----------------

fn run_slave(o: &SpdtstOpts) -> Result<()> {
    let sock = UdpSocket::bind(o.addr).with_context(|| format!("bind {}", o.addr))?;
    println!("blast spdtst slave  listening on {}", o.addr);
    let mut buf = [0u8; 2048];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let (mt, session) = match parse_hdr(&buf[..n]) {
            Some(v) => v,
            None => continue,
        };
        if mt != M_PARAMS {
            continue;
        }
        // PARAMS -> ack + RX_READY, then receive DATA until DATA_END
        let mut ack = [0u8; 12];
        put_hdr(&mut ack, M_PARAMS_ACK, session, 0);
        let _ = sock.send_to(&ack, peer);
        let mut rdy = [0u8; 12];
        put_hdr(&mut rdy, M_RX_READY, session, 0);
        let _ = sock.send_to(&rdy, peer);

        let mut rx_bytes: u64 = 0;
        let mut rx_pkts: u64 = 0;
        let start = Instant::now();
        sock.set_read_timeout(Some(Duration::from_secs(10))).ok();
        loop {
            let (n, from) = match sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => break,
            };
            if from != peer {
                continue;
            }
            match parse_hdr(&buf[..n]) {
                Some((M_DATA, _)) => {
                    rx_bytes += n as u64;
                    rx_pkts += 1;
                }
                Some((M_DATA_END, _)) => break,
                _ => {}
            }
        }
        // RESULTS
        let mut res = [0u8; 12 + 80];
        put_hdr(&mut res, M_RESULTS, session, 80);
        res[12..20].copy_from_slice(&rx_bytes.to_be_bytes());
        res[20..28].copy_from_slice(&rx_pkts.to_be_bytes());
        for _ in 0..3 {
            let _ = sock.send_to(&res, peer);
        }
        sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
        let secs = start.elapsed().as_secs_f64().max(1e-9);
        println!(
            "  [spdtst] {} -> {:.2} MB, {} pkts, {:.1} Mbit/s",
            peer,
            rx_bytes as f64 / 1e6,
            rx_pkts,
            rx_bytes as f64 * 8.0 / secs / 1e6
        );
        sock.set_read_timeout(None).ok();
    }
}

fn dir_str(d: Dir) -> &'static str {
    match d {
        Dir::Rx => "rx",
        Dir::Tx => "tx",
        Dir::Dx => "dx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn header_roundtrip() {
        let mut b = [0u8; 12];
        put_hdr(&mut b, M_PARAMS, 0x11223344, 12);
        let (mt, s) = parse_hdr(&b).unwrap();
        assert_eq!(mt, M_PARAMS);
        assert_eq!(s, 0x11223344);
        assert_eq!(u32::from_be_bytes([b[0], b[1], b[2], b[3]]), MAGIC);
        assert_eq!(u16::from_be_bytes([b[6], b[7]]), 24);
    }
}
