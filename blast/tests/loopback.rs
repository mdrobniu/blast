//! End-to-end loopback tests: spawn `blast` as a server, run it as a client,
//! and assert data actually flowed. Each test uses a distinct port so they can
//! run in parallel. Run with `cargo test --release` (debug is slow for UDP).
//! On few-core machines these spawn many processes at once; if one flakes under
//! the load, `cargo test --release -- --test-threads=2` runs them with headroom.

use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn blast() -> &'static str {
    env!("CARGO_BIN_EXE_blast")
}

/// Spawn server, run client (expects `--json`), return the parsed summary.
fn run(server: &[&str], client: &[&str]) -> serde_json::Value {
    let mut srv = Command::new(blast())
        .args(server)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");
    thread::sleep(Duration::from_millis(900));
    let out = Command::new(blast())
        .args(client)
        .output()
        .expect("run client");
    let _ = srv.kill();
    let _ = srv.wait();
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .unwrap_or("{}");
    serde_json::from_str(line).unwrap_or_else(|_| serde_json::json!({}))
}

fn num(v: &serde_json::Value, key: &str) -> f64 {
    v.get(key).and_then(|x| x.as_f64()).unwrap_or(0.0)
}

#[test]
fn turbo_tcp_tx() {
    let j = run(
        &["server", "--mode", "turbo", "-l", "127.0.0.1:23101"],
        &["client", "127.0.0.1", "-p", "23101", "--mode", "turbo", "-t", "-D", "tx", "-d", "2", "--json"],
    );
    assert!(num(&j, "tx_bytes") > 0.0, "turbo tcp tx flowed: {j}");
}

#[test]
fn turbo_udp_both() {
    let j = run(
        &["server", "--mode", "turbo", "-l", "127.0.0.1:23102"],
        &["client", "127.0.0.1", "-p", "23102", "--mode", "turbo", "-u", "-D", "both", "-P", "2", "-d", "2", "--json"],
    );
    assert!(num(&j, "tx_bytes") > 0.0 && num(&j, "rx_bytes") > 0.0, "turbo udp both flowed: {j}");
}

#[test]
fn compat_tcp_rx() {
    let j = run(
        &["server", "--mode", "compat", "-l", "127.0.0.1:23103"],
        &["client", "127.0.0.1", "-p", "23103", "--mode", "compat", "-t", "-D", "rx", "-d", "2", "--json"],
    );
    assert!(num(&j, "rx_bytes") > 0.0, "compat tcp rx flowed: {j}");
}

#[test]
fn compat_udp_tx() {
    let j = run(
        &["server", "--mode", "compat", "-l", "127.0.0.1:23104"],
        &["client", "127.0.0.1", "-p", "23104", "--mode", "compat", "-u", "-D", "tx", "-d", "2", "--json"],
    );
    assert!(num(&j, "tx_bytes") > 0.0, "compat udp tx flowed: {j}");
}

#[test]
fn compat_udp_rate_limited() {
    // -b 200M should pace tx near 200 Mbit/s (allow a wide band).
    let j = run(
        &["server", "--mode", "compat", "-l", "127.0.0.1:23105"],
        &["client", "127.0.0.1", "-p", "23105", "--mode", "compat", "-u", "-D", "tx", "-b", "200M", "-d", "2", "--json"],
    );
    let bps = num(&j, "avg_tx_bps");
    assert!(bps > 80e6 && bps < 320e6, "compat udp rate cap ~200M, got {bps}: {j}");
}

#[test]
fn compat_tcp_multiconn_rx() {
    // Multi-connection download: blast client (-P 4) <-> blast server, token-coordinated.
    let j = run(
        &["server", "--mode", "compat", "-l", "127.0.0.1:23108"],
        &["client", "127.0.0.1", "-p", "23108", "--mode", "compat", "-t", "-D", "rx", "-P", "4", "-d", "2", "--json"],
    );
    assert!(num(&j, "rx_bytes") > 0.0, "compat tcp -P4 download flowed: {j}");
}

#[test]
fn compat_tcp_multiconn_tx() {
    let j = run(
        &["server", "--mode", "compat", "-l", "127.0.0.1:23109"],
        &["client", "127.0.0.1", "-p", "23109", "--mode", "compat", "-t", "-D", "tx", "-P", "4", "-d", "2", "--json"],
    );
    assert!(num(&j, "tx_bytes") > 0.0, "compat tcp -P4 upload flowed: {j}");
}

#[test]
fn turbo_udp_multiworker() {
    let j = run(
        &["server", "--mode", "turbo", "-l", "127.0.0.1:23110"],
        &["client", "127.0.0.1", "-p", "23110", "--mode", "turbo", "-u", "-D", "tx", "-P", "4", "-d", "2", "--json"],
    );
    assert!(num(&j, "tx_bytes") > 0.0, "turbo udp -P4 flowed: {j}");
}

#[test]
fn iperf2_tcp_loopback() {
    // Classic iperf2 (airOS Speed Test protocol): blast client -> blast --server.
    let mut srv = Command::new(blast())
        .args(["iperf2", "--server", "-p", "23111"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn iperf2 server");
    thread::sleep(Duration::from_millis(700));
    let out = Command::new(blast())
        .args(["iperf2", "127.0.0.1", "-p", "23111", "-d", "2", "--json"])
        .output()
        .expect("run iperf2 client");
    let _ = srv.kill();
    let _ = srv.wait();
    // The client streams data; success = it ran to completion (non-empty summary).
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains('{') || s.contains("Gbps") || s.contains("Mbps"), "iperf2 ran: {s}");
}

#[test]
fn spdtst_loopback() {
    // Ubiquiti airOS Speed Test protocol (spdtst.ko wire format), blast<->blast.
    let mut srv = Command::new(blast())
        .args(["spdtst", "--server", "-p", "23112"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn spdtst slave");
    thread::sleep(Duration::from_millis(700));
    let out = Command::new(blast())
        .args(["spdtst", "127.0.0.1", "-p", "23112", "-d", "2", "-b", "200", "--plain"])
        .output()
        .expect("run spdtst master");
    let _ = srv.kill();
    let _ = srv.wait();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("peer received"), "spdtst exchanged PARAMS/DATA/RESULTS: {s}");
}

#[test]
fn speedtest_loopback() {
    let j = run(
        &["speedtest", "--server", "-l", "127.0.0.1:23106"],
        &["speedtest", "127.0.0.1", "-p", "23106", "-P", "2", "-d", "2", "--json"],
    );
    assert!(num(&j, "download_bps") > 0.0 && num(&j, "upload_bps") > 0.0, "speedtest flowed: {j}");
}

#[test]
fn librespeed_loopback() {
    let j = run(
        &["librespeed", "--server", "-l", "127.0.0.1:23107"],
        &["librespeed", "http://127.0.0.1:23107", "-P", "2", "-d", "2", "--json"],
    );
    assert!(num(&j, "download_bps") > 0.0 && num(&j, "upload_bps") > 0.0, "librespeed flowed: {j}");
}
