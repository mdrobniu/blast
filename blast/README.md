# blast

**A high-throughput, hardware-accelerated, multi-protocol bandwidth tester.**

`blast` is a clean-room, from-scratch reimplementation born from reverse-engineering
MikroTik's `btest.exe` (see [`../PROTOCOL.md`](../PROTOCOL.md)), rebuilt as a modern
Rust tool that saturates links using every kernel/NIC offload available - and that
also speaks **iperf3**, **iperf2** (airOS's CLI tool), the **Ubiquiti airOS Speed Test**
(`spdtst`), **Ookla-legacy speedtest**, and **LibreSpeed**, so one binary covers your
whole bandwidth-testing toolbox.

```
 blast turbo client -> 10.0.0.2  [Udp Tx]            accel: linux x8 REUSEPORT GSO GRO mmsg
 ┌ TX (upload) ──────────────┐  ┌ RX (download) ─────────────┐
 │       38.91 Gbps          │  │        0.00 bps            │
 │       peak 41.2 Gbps      │  │                            │
 │       6.9 Mpps            │  │                            │
 └───────────────────────────┘  └────────────────────────────┘
 TX history (Mbps) ▁▂▃▅▆▇██▇▇████   per-worker ▕ w0 ====== w1 ====== ...
```

## Why it's fast

- **Share-nothing, one worker per core.** Each worker owns its socket, its buffer,
  and its own io path; stats are per-core cache-line-padded atomics. No locks on the
  data path.
- **Kernel/NIC offloads, auto-detected with graceful fallback:**
  - **UDP GSO/GRO** - hand the kernel one 64 KB super-buffer; it (or the NIC) slices
    it into MTU datagrams. One syscall replaces dozens.
  - **`sendmmsg`/`recvmmsg`** batching when GSO is unavailable.
  - **`SO_REUSEPORT`** multi-queue fan-out (RSS-aligned, one socket per core).
  - **Hugepage buffers** (2 MiB) + NUMA-first-touch, large `SO_RCVBUF`/`SO_SNDBUF`.
  - **CPU pinning** of workers to cores; TCP rides TSO/LRO automatically.
- Measured on a 4-core box over loopback: **~39 Gbps UDP (GSO), ~27 Gbps TCP.**

Run `blast caps` to see what your machine offers.

## Build

```bash
cargo build --release      # needs a recent stable Rust (rustup)
./target/release/blast --help
```

Single static-ish binary; no runtime deps. Linux gets the full accel path; macOS /
BSD / Windows get a portable baseline (plain sockets + threads + big buffers).

## Protocols & modes

### 1. MikroTik btest (`--mode compat`)
Wire-compatible with RouterOS / the original `btest.exe`, **verified against a live
RouterOS 7.22 device:** TCP + UDP, download/upload/both, rate limits, packet sizes,
MD5 **and** EC-SRP5 authentication, and multi-connection TCP - as a client and a server.

```bash
blast client 192.0.2.1 --mode compat -t -D rx -P 20 -d 10   # download (20 streams)
blast client 192.0.2.1 --mode compat -t -D tx -d 10         # upload to a MikroTik
blast client 192.0.2.1 --mode compat -u -D tx -b 300M -d 10 # UDP at a 300 Mbit/s cap
blast client 192.0.2.1 --mode compat -t -D rx --user me --password secret  # MD5/EC-SRP5 auth
```

### 2. blast turbo (`--mode turbo`, default)
Native protocol between two `blast` instances - removes the MikroTik size caps and
unlocks jumbo buffers + GSO + io_uring-class batching for true max throughput.

```bash
# on host A:
blast server --mode turbo -l 0.0.0.0:2000
# on host B:
blast client A.B.C.D --mode turbo -u -D both -P 8 -d 20    # 8-worker bidirectional UDP blast
```

### 3. iperf3 (`blast iperf ...`)
An iperf3-compatible client. **Verified against `iperf3 -s`:** TCP single/multi-stream,
forward and reverse, match iperf3's own counters.

```bash
blast iperf 10.0.0.5 -P 4 -d 10        # 4-stream TCP upload
blast iperf 10.0.0.5 -R -d 10          # TCP download (reverse)
blast iperf 10.0.0.5 -u -b 1G -d 10    # UDP at 1 Gbit/s
```

### 4. Ookla-legacy speedtest (`blast speedtest ...`)
The Ookla legacy raw-TCP socket protocol (`HI`/`PING`/`DOWNLOAD`/`UPLOAD`), client
and server. Self-testable; reports ping/jitter/download/upload like speedtest.net.
See [`SPEEDTEST.md`](SPEEDTEST.md) for the protocol and an honest assessment of the
(closed-source, EULA-restricted) official Ookla CLI + the LibreSpeed path.

```bash
blast speedtest --server -l 0.0.0.0:8080    # serve
blast speedtest HOST -P 4 -d 10             # client: ping + download + upload
```

## Common options

| Flag | Meaning |
|------|---------|
| `-u` / `-t` | UDP / TCP data plane (TCP default) |
| `-D tx\|rx\|both` | direction (client perspective) - btest modes |
| `-R` | reverse (iperf mode: server sends) |
| `-P N` | parallel workers / streams (0 = auto in turbo) |
| `-d S` | duration seconds |
| `-b RATE` | rate cap, bits/s with `K`/`M`/`G` suffix (0 = unlimited) |
| `--size N` | UDP datagram size; `--gso N` / `--no-gso` |
| `--plain` / `--json` | line output / one JSON summary (auto-TUI on a terminal) |

## Output

- **Interactive terminal:** a live `ratatui` dashboard (throughput gauges, sparklines,
  per-worker bars, progress). Press `q`/`Esc` to stop early.
- **Piped / CI:** automatically falls back to `--plain` lines; `--json` for one summary.
- **Real loss (compat):** for MikroTik tests blast reads the server's `07` heartbeats
  and shows both what we **sent** and what the peer **actually received**, plus loss %
  - e.g. blasting 1.2 Gbps UDP at a device that ingests ~475 Mbps reports ~61% loss.

## Status & roadmap

| Area | State |
|------|-------|
| btest compat - TCP | verified vs live RouterOS 7.22 (71/502 Mbps) |
| btest compat - UDP | verified vs live RouterOS 7.22 (135 Mbps down / ~475 Mbps up) - reads the server's advertised base port + sequenced datagrams |
| btest compat - rate limits | verified vs live device (TCP+UDP, both directions; wire speed field is bits/sec) |
| btest compat - packet sizes | verified on the wire (64-1432 B datagrams) |
| btest compat - peer-received / loss | shown live from the server's 07 heartbeats (sent vs really-received, loss%) |
| btest compat - auth | **MD5** (RouterOS <6.43) and **EC-SRP5** (>=6.43, Curve25519/mtwei) both implemented; EC-SRP5 verified vs live RouterOS 7.22 (authenticated TCP+UDP; wrong password rejected) |
| btest compat - multi-connection TCP (`-P N`) | full token-coordinated multi-stream, client + server. Verified vs live RouterOS: client `-P 4..20` (~78 Mbps down / ~410 Mbps up), server with a real `cc=20` client (~397 down / ~159 up). `both`-direction multi-conn flows data but leaves the peer upload counter at 0 (documented) |
| btest compat - server (reverse) | a real RouterOS client tests *to* blast: UDP both directions (~460/314 Mbps) and TCP single + multi-connection verified ("test unsupported" gone) |
| automated tests | `cargo test` (proto + EC-SRP5 unit tests, 10 loopback integration tests incl. multi-session) + `scripts/test-mikrotik.sh` |
| btest turbo - TCP/UDP, tx/rx/both, multi-worker | working, accelerated |
| iperf3 client - TCP single/multi, fwd/reverse | verified vs `iperf3 -s` |
| iperf3 client - UDP | verified vs `iperf3 -s`: loss + jitter match byte-for-byte (forward shows the server's count, reverse is measured locally) |
| iperf2 (`blast iperf2`) - airOS CLI tool | client + server, TCP + UDP; RE'd from airOS 6.x (iperf 2.0.4), verified vs stock `iperf`(2) and a live airOS radio (~9.9 Mbit/s match) |
| airOS Speed Test (`blast spdtst`) | the UI Tools->Speed Test = `spdtst.ko` (NOT iperf); RE'd via Ghidra (UDP, magic `0xDA51A514`); wire format implemented, blast<->blast working - see [`../SPDTST.md`](../SPDTST.md) |
| Ookla legacy speedtest (raw TCP) | client + server, self-tested (~27 Gbps loopback) |
| LibreSpeed HTTP(S) (`blast librespeed`) | client + server, self-tested (~24 Gbps down / 7 Gbps up) |
| Ookla HTTP / official-CLI | documented honestly (closed/EULA) -- see SPEEDTEST.md |
| io_uring backend (`--io-uring`) | implemented + selectable (turbo UDP TX) |
| AF_XDP kernel-bypass tier | capability auto-detected (`blast caps`); full data path needs root + a supported NIC (design in README) |

## Measuring real bandwidth (methodology)

What you set changes what you measure. Findings from a live RouterOS device (a CRS328
switch doing software btest):

- **TCP self-limits — use it for "what can I actually push."** It needs no tuning and
  reports usable throughput directly (here: 69 Mbps down / 486 Mbps up). For UDP, what
  you *send* is not what the peer *gets* — blast shows both (peer-received from the `07`
  heartbeats) plus loss%.
- **UDP unlimited just overruns the receiver.** Sending 1.24 Gbps, the device ingested
  only ~357 Mbps (71% loss). `tx` is meaningless there; **peer-received is the truth.**
- **To find real UDP capacity, ramp `-b` and watch the loss "knee":**

  | `-b` rate | sent | peer received | loss |
  |---|---|---|---|
  | 200M | 198 | 197 | 0.8% |
  | 300M | 297 | 295 | 0.9% |  &lt;- clean capacity ~300 Mbps |
  | 400M | 400 | 355 | 11%  |  &lt;- knee: loss appears |
  | 500M | 499 | 422 | 15%  |

  Clean capacity = the highest rate where loss stays ~&lt;1% (here ~300 Mbps).

- **Use long durations (>= 10 s).** The peer's `07` heartbeats start ~1 s in, so short
  tests under-count peer-received and *inflate* loss. The same `-b 100M` test reads
  **d=4 -> 26% "loss" (artifact)** vs **d=10 -> 0.6% (real)**. 10-20 s is the sweet spot.
- **Packet size:** bigger datagrams = fewer packets/sec = less pps-bound loss; tiny
  (64 B) packets spike pps and lose more. Default 1432 B (safe under a 1500 MTU) is a
  good baseline; raise toward the MTU for max throughput, lower only to stress pps.
- **Multiple connections (`-P N`) for TCP.** A single TCP stream is window/RTT-bound;
  RouterOS itself defaults to 20. More streams fill a fat or lossy path - here download
  rose 69 -> 80 Mbps from `-P 1` to `-P 20`, and parallel upload reached ~410 Mbps.
  Match the device default (`-P 20`) to compare like-for-like. UDP scales with `-P`
  workers instead (each its own port pair).
- **Expect run-to-run variation** with path load / device CPU (software btest on a
  switch CPU is bursty) - average a few 10 s runs.

Recipes:
```bash
blast client HOST --mode compat -t -D both -d 10          # usable throughput (TCP)
blast client HOST --mode compat -t -D rx -P 20 -d 10      # multi-stream TCP (RouterOS default)
blast client HOST --mode compat -u -D tx -b 300M -d 10    # UDP: ramp -b, read peer-rx + loss
scripts/test-mikrotik.sh HOST [user] [password]           # automate the whole sweep
```

## Acceleration tiers (UDP)

`blast caps` shows what the kernel offers. From fastest-to-set-up to most-extreme:

1. **GSO/GRO** (default) - one syscall emits a 64 KB super-buffer the NIC segments;
   the bulk-UDP winner on most hardware (~39 Gbps loopback here).
2. **`sendmmsg`/`recvmmsg`** - batched syscalls when GSO is unavailable.
3. **io_uring** (`--io-uring`) - a deep ring of in-flight sends; comparable to
   sendmmsg for plain datagrams, pulls ahead on real NICs with many flows / SQPOLL.
4. **AF_XDP** - kernel-bypass for line rate. blast auto-detects support
   (`af_xdp` in `blast caps`); the zero-copy UMEM/XSK data path is the advanced tier
   and needs root (`CAP_NET_ADMIN`) plus a driver with native XDP. Design: bind an
   `AF_XDP` socket to a NIC queue, share a UMEM frame pool, fill the TX ring and
   kick once per batch - no per-packet syscalls, no skb. Loopback/VM NICs don't
   benefit, so it's gated rather than enabled blindly.

See [`../PROTOCOL.md`](../PROTOCOL.md) for the reverse-engineering notes (incl. the
RouterOS firmware RE) and the live-device validation findings, and
[`SPEEDTEST.md`](SPEEDTEST.md) for the speedtest/LibreSpeed details.
