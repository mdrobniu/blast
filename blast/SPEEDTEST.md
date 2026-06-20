# Speedtest support in blast

`blast speedtest` implements the **Ookla legacy raw-TCP socket protocol** (the one
`sivel/go-speedtest` speaks and classic Speedtest-Mini / OoklaServer test servers
expose on port 8080). blast ships both ends, so it is fully self-testable, and the
client can also target third-party servers that still speak this protocol.

```bash
blast speedtest --server -l 0.0.0.0:8080     # run a speedtest server
blast speedtest HOST -p 8080 -P 4 -d 10      # client: 4 streams, 10s per phase
blast speedtest HOST --json                  # machine-readable summary
```

## Legacy raw-TCP protocol (implemented)

ASCII line protocol, **`\n`-terminated (never `\r\n`)**, persistent + pipelined,
multiple parallel sockets for throughput.

```
C: HI\n
S: HELLO <version> <build-date> <salt>\n      ; e.g. "HELLO 2.1 2013-08-14.01 blast"
C: PING <ms_epoch>\n   ->  S: PONG <ms_epoch>\n   ; measure RTT with the LOCAL clock
C: DOWNLOAD <size>\n   ->  S: <exactly size bytes>  ; "DOWNLOAD " + filler + "\n", len==size
C: UPLOAD <size> 0\n<payload>  ->  S: OK <bytes> <ms>\n
C: QUIT\n
```

Two correctness details that bite naive implementations (both handled here):
- **`UPLOAD <size>` is inclusive of the command header line** - the client sends
  `size - len("UPLOAD <size> 0\n")` payload bytes, or the server hangs waiting.
- **`DOWNLOAD` payload literally begins with ASCII `"DOWNLOAD "`** and ends with
  `\n`; "done" is the byte count, there is no delimiter.

Throughput is `bytes * 8 / seconds` with **no fudge factor**.

## HTTP legacy variant (not implemented - roadmap)

`sivel/speedtest-cli` (Python) uses HTTP instead of the socket protocol:
download `GET {dir}/random{N}x{N}.jpg` (N in 350..4000), upload `POST .../upload.php`
with a `content1=`-prefixed body, latency `GET {dir}/latency.txt` (body must be
`test=test`). Server discovery via `speedtest-config.php` (client geo + thread config)
and `speedtest-servers-static.php` (XML server list), nearest chosen by haversine
(Earth radius 6371 km), 5 closest latency-tested. This needs an HTTP+TLS client and
XML parsing - deferred (blast core has no HTTP stack yet).

## The official Ookla Speedtest CLI - honest assessment

The official `speedtest` CLI (speedtest.net/apps/cli) is **closed-source and
proprietary**. Its EULA forbids reverse-engineering, redistribution, modification,
and all non-personal/commercial use; there is **no public protocol spec and no
sanctioned client API** for driving Ookla's measurement endpoints. Reconstructed
from peer-reviewed analysis (SIGMETRICS 2023), it uses **adaptive parallel HTTPS**
(1->8 TCP connections as RTT rises; adaptive ~3.5-15.7 s duration) to crowdsourced
`*.prod.hosts.ooklaserver.net` servers, but the exact verbs/TLS/UA are unpublished.
The legacy PHP endpoints are stale-but-not-dead (HTTP->403, list->429 via Cloudflare).

**A clean-room client that talks to Ookla's endpoints would violate Ookla's ToS/EULA**,
so blast does **not** target them. The legitimate, license-clean path to
"Ookla-style" numbers is:

- **LibreSpeed** (LGPL-3.0, self-hostable) - the recommended target for a clean
  HTTP speedtest client: download `GET garbage.php?ckSize=N`, upload `POST empty.php`,
  ping/jitter `GET empty.php`, info `GET getIP.php`; web client uses 6 down / 3 up
  streams, 15 s windows, optional 1.06 overhead-compensation factor. A future
  `blast speedtest --librespeed URL` is the planned way to hit real, legitimate
  infrastructure once blast grows an HTTP/TLS client.

Sources: `sivel/go-speedtest` (raw TCP, verbatim), `sivel/speedtest-cli` (HTTP),
`librespeed/speedtest`, Ookla EULA, SIGMETRICS 2023 (arxiv 2205.12376).
