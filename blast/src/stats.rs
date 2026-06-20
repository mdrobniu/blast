//! Lock-free, share-nothing statistics.
//!
//! Each worker owns one cache-line-padded counter cell and only ever touches
//! its own. The reporter thread sums across cells. No locks on the data path,
//! no false sharing between cores.

use crossbeam_utils::CachePadded;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Default)]
pub struct Cell {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_pkts: AtomicU64,
    pub rx_pkts: AtomicU64,
}

pub struct Stats {
    cells: Vec<CachePadded<Cell>>,
    /// Peer-reported received bytes (cumulative) from the btest `07` heartbeats -
    /// i.e. what the OTHER side actually got, which differs from what we sent.
    remote_bytes: CachePadded<AtomicU64>,
    /// Latest peer-reported interval rate, bits/sec.
    remote_rate_bps: CachePadded<AtomicU64>,
    pub start: Instant,
}

impl Stats {
    pub fn new(workers: usize) -> Arc<Stats> {
        let mut cells = Vec::with_capacity(workers);
        for _ in 0..workers {
            cells.push(CachePadded::new(Cell::default()));
        }
        Arc::new(Stats {
            cells,
            remote_bytes: CachePadded::new(AtomicU64::new(0)),
            remote_rate_bps: CachePadded::new(AtomicU64::new(0)),
            start: Instant::now(),
        })
    }

    /// Record one peer heartbeat: `interval_bytes` received by the peer in ~1s.
    pub fn add_remote(&self, interval_bytes: u64) {
        self.remote_bytes.fetch_add(interval_bytes, Ordering::Relaxed);
        self.remote_rate_bps
            .store(interval_bytes.saturating_mul(8), Ordering::Relaxed);
    }

    pub fn has_remote(&self) -> bool {
        self.remote_bytes.load(Ordering::Relaxed) > 0
    }

    #[inline(always)]
    pub fn add_tx(&self, worker: usize, bytes: u64, pkts: u64) {
        let c = &self.cells[worker];
        c.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
        c.tx_pkts.fetch_add(pkts, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn add_rx(&self, worker: usize, bytes: u64, pkts: u64) {
        let c = &self.cells[worker];
        c.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        c.rx_pkts.fetch_add(pkts, Ordering::Relaxed);
    }

    pub fn workers(&self) -> usize {
        self.cells.len()
    }

    /// Per-worker (tx_bytes, rx_bytes) for the live per-connection view.
    pub fn per_worker(&self) -> Vec<(u64, u64)> {
        self.cells
            .iter()
            .map(|c| {
                (
                    c.tx_bytes.load(Ordering::Relaxed),
                    c.rx_bytes.load(Ordering::Relaxed),
                )
            })
            .collect()
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut s = Snapshot {
            elapsed: self.start.elapsed().as_secs_f64(),
            ..Default::default()
        };
        for c in &self.cells {
            s.tx_bytes += c.tx_bytes.load(Ordering::Relaxed);
            s.rx_bytes += c.rx_bytes.load(Ordering::Relaxed);
            s.tx_pkts += c.tx_pkts.load(Ordering::Relaxed);
            s.rx_pkts += c.rx_pkts.load(Ordering::Relaxed);
        }
        s.remote_bytes = self.remote_bytes.load(Ordering::Relaxed);
        s.remote_rate_bps = self.remote_rate_bps.load(Ordering::Relaxed) as f64;
        s
    }
}

#[derive(Default, Clone, Copy)]
pub struct Snapshot {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_pkts: u64,
    pub rx_pkts: u64,
    pub elapsed: f64,
    /// Peer-reported received bytes (cumulative) and latest interval rate (bits/s).
    pub remote_bytes: u64,
    pub remote_rate_bps: f64,
}

/// Instantaneous rate between two snapshots, plus the deltas.
#[derive(Default, Clone, Copy)]
pub struct Rate {
    pub tx_bps: f64, // bits/sec
    pub rx_bps: f64,
    pub tx_pps: f64, // packets/sec
    pub rx_pps: f64,
    pub dt: f64,
}

impl Snapshot {
    pub fn rate_since(&self, prev: &Snapshot) -> Rate {
        let dt = (self.elapsed - prev.elapsed).max(1e-9);
        Rate {
            tx_bps: (self.tx_bytes - prev.tx_bytes) as f64 * 8.0 / dt,
            rx_bps: (self.rx_bytes - prev.rx_bytes) as f64 * 8.0 / dt,
            tx_pps: (self.tx_pkts - prev.tx_pkts) as f64 / dt,
            rx_pps: (self.rx_pkts - prev.rx_pkts) as f64 / dt,
            dt,
        }
    }

    pub fn avg(&self) -> Rate {
        let dt = self.elapsed.max(1e-9);
        Rate {
            tx_bps: self.tx_bytes as f64 * 8.0 / dt,
            rx_bps: self.rx_bytes as f64 * 8.0 / dt,
            tx_pps: self.tx_pkts as f64 / dt,
            rx_pps: self.rx_pkts as f64 / dt,
            dt,
        }
    }
}

// ---------- humanization ----------

/// Format a bits/sec value as bps/Kbps/Mbps/Gbps (base-1000, like network gear).
pub fn fmt_bits(bps: f64) -> String {
    const U: [&str; 5] = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
    let mut v = bps;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    format!("{v:.2} {}", U[i])
}

/// Format a byte count as B/KiB/MiB/GiB (base-1024).
pub fn fmt_bytes(b: f64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.2} {}", U[i])
}

pub fn fmt_pps(pps: f64) -> String {
    const U: [&str; 3] = ["", "K", "M"];
    let mut v = pps;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    format!("{v:.1} {}pps", U[i])
}
