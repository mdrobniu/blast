# blast

A high-throughput, hardware-accelerated, multi-protocol bandwidth tester, written
in Rust. It began as a clean-room reverse-engineering of MikroTik's `btest.exe`
and grew into a single binary that speaks **MikroTik btest**, **iperf3**, the
**Ookla-legacy** speedtest protocol, and **LibreSpeed** - while saturating links
with UDP GSO/GRO, `sendmmsg`/`recvmmsg`, `SO_REUSEPORT`, hugepages, CPU pinning,
io_uring, and (detected) AF_XDP.

- **The tool:** [`blast/`](blast/) - source, build instructions, usage
  ([`blast/README.md`](blast/README.md)).
- **The reverse-engineering:** [`PROTOCOL.md`](PROTOCOL.md) - the MikroTik btest
  wire protocol recovered via Ghidra (the Windows client and the RouterOS firmware:
  userspace `btest` + the `btest.ko` kernel data plane), plus live-device validation.
- **Speedtest details:** [`blast/SPEEDTEST.md`](blast/SPEEDTEST.md).

## Quick start

```bash
cd blast && cargo build --release
./target/release/blast caps                 # show detected acceleration
./target/release/blast server --mode turbo  # one host
./target/release/blast client <host> --mode turbo -u -D both -P 8   # the other
./target/release/blast iperf <host> -P 4    # iperf3-compatible
```

Validated highlights: ~39 Gbps UDP (GSO) / ~27 Gbps TCP on 4 cores (loopback);
matches `iperf3 -s`'s own counters; interoperates with a live RouterOS device over
TCP (compat mode).

> Note: MikroTik's proprietary `btest.exe` is intentionally **not** included.

License: MIT OR Apache-2.0.
