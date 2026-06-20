//! io_uring data-plane backend (Linux). Keeps a deep ring of in-flight UDP
//! sends so one `io_uring_enter` dispatches many datagrams - far fewer syscalls
//! than send()-per-datagram. Used for turbo UDP TX when `--io-uring` is set.

#![cfg(target_os = "linux")]

use crate::stats::Stats;
use io_uring::{opcode, types, IoUring};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const QUEUE_DEPTH: usize = 256;
const INFLIGHT: usize = 192;

/// Returns true if io_uring is usable (probe a small ring).
pub fn available() -> bool {
    IoUring::new(8).is_ok()
}

/// Batched UDP send over a connected socket via io_uring until `stop`.
pub fn udp_send(
    fd: RawFd,
    datagram: &[u8],
    stats: &Stats,
    idx: usize,
    stop: &AtomicBool,
    cap: u64,
) {
    let mut ring = match IoUring::new(QUEUE_DEPTH as u32) {
        Ok(r) => r,
        Err(_) => return,
    };
    let entry = opcode::Send::new(types::Fd(fd), datagram.as_ptr(), datagram.len() as u32)
        .build()
        .user_data(1);

    // Prime the ring with in-flight sends.
    {
        let mut sq = ring.submission();
        for _ in 0..INFLIGHT {
            if unsafe { sq.push(&entry) }.is_err() {
                break;
            }
        }
    }
    if ring.submit().is_err() {
        return;
    }

    let start = Instant::now();
    let mut sent: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        // Reap in batches to amortize io_uring_enter overhead.
        if ring.submit_and_wait(64).is_err() {
            break;
        }
        let mut done = 0usize;
        {
            let mut cq = ring.completion();
            cq.sync();
            for cqe in &mut cq {
                let r = cqe.result();
                if r > 0 {
                    stats.add_tx(idx, r as u64, 1);
                    sent += r as u64;
                }
                done += 1;
            }
        }
        // Re-arm the same number of sends we just reaped.
        {
            let mut sq = ring.submission();
            for _ in 0..done {
                if unsafe { sq.push(&entry) }.is_err() {
                    break;
                }
            }
        }
        let _ = ring.submit();

        if cap > 0 {
            let target = sent as f64 / cap as f64;
            let elapsed = start.elapsed().as_secs_f64();
            if target > elapsed + 0.001 {
                std::thread::sleep(Duration::from_secs_f64(target - elapsed));
            }
        }
    }
}
