# MikroTik BTest Protocol -- Reverse-Engineering Notes

Target: `btest.exe` (780,400 bytes, PE32 i386, MinGW, RouterOS 7.7/7.8 era,
SHA256 `856b92f0273a9506b908d9a076f4144c824b866f2bbc9407a9841c2b0a421960`).
Method: Ghidra 11.3 headless decompilation + cross-check against two public
reimplementations (`samm-git/btest-opensource`, `manawenuz/btest-rs`).

Legend: **[BIN]** = confirmed in the decompiled binary. **[PUB]** = from public
reverse-engineering, consistent with the binary but not byte-verified here.

---

## 1. Transport topology

- **Control channel:** TCP, server listens on `0.0.0.0:2000`, `listen(backlog=10)`. **[BIN]**
  Client `connect()`s to `<server>:2000`. The TCP control connection stays open
  for the whole test, even for a UDP data test. **[BIN/PUB]**
- **UDP data channel:** separate connected UDP sockets. **[BIN]**
  - Socket = `AF_INET, SOCK_DGRAM`; `SO_REUSEADDR=1`; `bind(localPort)`;
    `connect(remoteAddr:remotePort)` (so it is a *connected* UDP socket);
    `SO_RCVBUF = 128000` (0x1F400). **[BIN]**
  - Port scheme: server data ports `2001+`, client data ports `2257+` (a `+256`
    offset), one pair per connection. **[PUB]**

## 2. Handshake (control channel)

```
  server -> client   01 00 00 00                         ; "hello"            [PUB]
  client -> server   <16-byte COMMAND>                                        [PUB/BIN]
  server -> client   01 00 00 00                         ; auth not required  [PUB]
               or    02 00 00 00 <16 random bytes>       ; MD5 challenge      [PUB]
               or    03 00 00 00                         ; EC-SRP5 (>=6.43)   [PUB]
  (if auth) client-> <auth response>                                          [PUB/BIN]
  (if auth) server-> 00 00 00 00  (fail)  |  01 00 00 00 (ok)                 [PUB]
  ... data transfer + periodic stats ...
```

### 2.1 COMMAND message (16 bytes) [PUB], field set confirmed [BIN]

| Off | Sz | Field            | Notes                                              |
|-----|----|------------------|----------------------------------------------------|
| 0   | 1  | `proto`          | 0x01 = TCP, 0x00 = UDP                             |
| 1   | 1  | `direction`      | 0x01 = tx (send), 0x02 = rx (receive), 0x03 = both |
| 2   | 1  | `random`         | 0x00 = random payload, 0x01 = zero/null payload    |
| 3   | 1  | `connectionCount`| number of parallel TCP connections                 |
| 4   | 2  | `remoteSize`     | u16 LE -- remote tx packet/buffer size             |
| 6   | 2  | `localSize`      | u16 LE -- local tx packet/buffer size              |
| 8   | 4  | `remoteSpeed`    | u32 LE -- remote tx cap, **bits/s** (0 = unlimited) |
| 12  | 4  | `localSpeed`     | u32 LE -- local tx cap, **bits/s** (0 = unlimited)  |

> Speed fields are **bits/sec** on the wire (verified live: a `remoteSpeed` of
> 50,000,000 caps the server's download at ~50 Mbps). The `07` heartbeat's `bytes`
> field is the peer's **actually-received** bytes for that ~1s interval - the
> ground truth for UDP loss (sent on our NIC vs received by the peer).

The server's command parser (`FUN_00408e84`) reads byte0, byte1, `u32@4`,
`u32@8`, `u32@12` plus a trailing object pointer @0x10 -- consistent with the
table above. The full parameter model is also confirmed by the settings
(de)serializers `FUN_00403158` / `FUN_00403461`, which enumerate exactly:
`addr, proto, localSize, remoteSize, dir, localSpeed, remoteSpeed,
connectionCount, user, <password>, random`. **[BIN]**

## 3. Authentication

Three regimes exist; the binary contains the crypto for all of them.

- **None** -- server replies `01 00 00 00` and the test starts. **[PUB]**
- **MD5 challenge/response (RouterOS < 6.43)** **[PUB]**
  - Server: `02 00 00 00` + 16 random challenge bytes.
  - Client replies 48 bytes: username (plaintext, padded) + 16-byte digest.
  - Digest = `md5( password + md5( password + challenge ) )`.
- **EC-SRP5 (RouterOS >= 6.43)** -- Curve25519-based, server replies
  `03 00 00 00`. **Confirmed live:** with `/tool bandwidth-server set
  authenticate=yes` on RouterOS 7.22.1, the server returns `03 00 00 00` (never
  `02`/MD5) - modern RouterOS uses EC-SRP5 only. Exact field layout is partially
  public; port by reference to `btest-rs`. blast detects `03` and reports it
  clearly (EC-SRP5 not yet implemented). **[VERIFIED]**

The binary also statically links the full **MS-CHAPv2 / MPPE** suite **[BIN]**:
- `FUN_00461b50` = MS-CHAPv2 `GenerateAuthenticatorResponse`: emits
  `S=<40 hex>` from `SHA1(PasswordHashHash + NTResponse +
  "Magic server to client signing constant")` then
  `SHA1(digest + ChallengeHash + "Pad to make it do more than one iteration")`.
- `FUN_004608ed` = challenge hashing with domain labels
  `"This is for auther challenge"` / `"This is for peer challenge"`.
- MPPE key-derivation magic strings (`"This is the MPPE Master Key"`,
  send/receive-key labels) are present -- the RouterOS PPP crypto library is
  linked in. Whether btest negotiates this on the wire vs. EC-SRP5 needs a live
  capture to settle; MD5 + EC-SRP5 cover all known deployments.

## 4. Data transfer & statistics

- **Payload generation:** random bytes via `CryptGenRandom` (fallback `rand()`),
  or zero-fill when `random=1`. **[BIN]** (`FUN_00407cc8`)
- **Send path:** `send(sock, buf, len, 0)` in a tight loop; retries on
  `WSAEINTR (10004)`; treats `WSAEWOULDBLOCK (10035)` as a soft 0; anything else
  is "send failed". **[BIN]** (`FUN_00406162`)
- **Recv path:** `recv(sock, buf, 0x8000, 0)` -- **32 KB** application read
  size, same error handling. **[BIN]** (`FUN_00406439`)
- **Periodic statistics (~1/sec), 12 bytes** **[PUB]**:

  ```
   07 00 00 00  <seconds:u32 LE>  <bytesTransferred:u32 LE>
  ```
  Example `07 00 00 00 01 00 00 00 36 6e 03 00` = second 1, 0x00036e36 bytes.
  Speed is computed by the receiver from successive counters; the test uses a
  1-second status interval with dynamic speed adjustment. **[PUB]**

- **Multi-connection:** for `connectionCount > 1` the client opens additional
  data connections; the server hands back per-connection auth/seed data
  (`01 xx xx 00`). **[PUB]**

## 5. Socket-option facts worth reproducing

| Where | Option | Value | Source |
|-------|--------|-------|--------|
| UDP data | `SO_REUSEADDR` | 1 | **[BIN]** |
| UDP data | `SO_RCVBUF`    | 128000 | **[BIN]** |
| recv()   | app buffer     | 32768 (0x8000) | **[BIN]** |
| TCP ctrl | listen backlog | 10 | **[BIN]** |

## 6. What this means for a clean-room port

The performance-critical surface is tiny and fully understood: a 16-byte command,
a 4-byte hello/ack vocabulary, a 12-byte stats heartbeat, and a bulk send/recv
loop. Everything else in `btest.exe` (~95% of it) is the MikroTik "routeros" GUI
toolkit (Winbox-style widgets, bitmap/sprite/timer code) and is irrelevant to a
headless high-throughput reimplementation. We can be byte-compatible on the wire
while replacing the entire I/O engine.

## 7. Verified against a live RouterOS device (no-auth btest server)

Tested `blast` against a real MikroTik btest server. Confirmations and corrections:

- **Handshake accepted byte-for-byte on the first try.** Server hello `01 00 00 00`;
  our 16-byte command (`01 01 00 01 dc 05 dc 05 00...`) accepted; response
  `01 00 00 00` (no-auth). The RE in sections 1-3 is correct. **[VERIFIED]**
- **TCP data rides the *control* connection.** There is **no** separate TCP data
  port. After the 4-byte response:
  - `direction = rx` (download): the server immediately streams bulk data down
    the same TCP socket (measured ~16.6 MB in 2 s on a probe).
  - `direction = tx` (upload): the client streams data up the same socket; the
    server reports progress back on it via 12-byte `07` heartbeats.
  This corrects the earlier assumption of ports `2001+`; that scheme is for UDP
  only. **[VERIFIED]**
- **`07` heartbeat:** bytes 1-3 are **not** always zero (observed `07 92 00 00`,
  `07 d4 07 be`...), but `seconds @ off4` and `bytes @ off8` (both u32 LE) decode
  cleanly, so a reader keying on those offsets is correct. **[VERIFIED]**
- **Random/zero flag:** command byte 2 = `0x00` produced an all-zero payload from
  the server, i.e. `0x00 = zero-fill`, `0x01 = random` (opposite of some public
  notes). Irrelevant to throughput. **[VERIFIED]**
- **Live single-stream throughput** (remote device, real path): download
  ~37.6 Mbps, upload ~254 Mbps. **[VERIFIED]**
- **UDP port topology (from the decompiled orchestrators `FUN_0040951e` /
  `FUN_0040a700`):** deterministic *connected* UDP, no rendezvous packet. One side
  binds local `base` and connects each worker to remote `base+256+i`; the mirror
  side binds local `base+256+i` and connects to remote `base` (`base` = the
  "Allocate UDP ports from" value; wraps via `-0xff00` past 65535). blast now
  implements this for compat UDP (replacing its native hello): **blast<->blast
  compat UDP works and is GSO-accelerated (~13.6 Gbps tx / ~11.3 Gbps rx
  loopback).** **[BIN-derived]**
- **Real-hardware UDP gap:** against the live device, the server replies ICMP
  port-unreachable to the predicted `base` ports (2000/2001/2002 all tried), and
  download produces no datagrams - so the real server's UDP port is gated on a
  trigger and/or the data datagrams carry a sequence header the server validates,
  which black-box probing did not pin down. blast tolerates the ICMP (keeps
  blasting for the full test) but true server-side reception is unconfirmed; this
  needs decompiling the UDP datagram *payload* builder and the exact port source.
- **Multi-connection:** the `base+256+i` scheme scales with `connectionCount`
  (blast<->blast multi-worker UDP works); real-hardware multi-stream TCP still
  needs the server's per-stream association semantics. Single-stream TCP is fully
  interoperable.

## 8. RouterOS firmware RE (authoritative server side)

Extracted the RouterOS 7.16.2 CHR image (ext3 -> squashfs in `var/pdb/system/image`
at offset 4096) and decompiled the two server-side btest components:
`/nova/bin/btest` (userspace, i386) and `/lib/modules/.../btest.ko` (the data-plane
kernel module, x86-64, **unstripped**).

- **TCP - fully confirmed.** `btest.ko` is not used for TCP; the userspace
  `FUN_080516b6` runs a `select()` loop and `recv(control_sock, buf, 0x8000, 0)` -
  i.e. **TCP data rides the control socket with 32 KB reads**, exactly matching
  blast's compat-TCP implementation and the live result (download 71 Mbps / upload
  502 Mbps against a live RouterOS device). **[FW-VERIFIED]**

- **UDP data plane is in the kernel** (`btest.ko`), reached via `/dev/btest`:
  - userspace creates the UDP socket (bind/connect, `SO_REUSEADDR`,
    `SO_RCVBUF=0x1f400=128000`) and hands the fd to the module by
    `ioctl 0x40207801` (socket fd + 32-byte config; flag bit `0x1`=send/upload
    queues a work item, bit `0x2`=recv/download hooks the socket). Stats read back
    via `ioctl 0x80187802` as a **24-byte report**. **[FW]**
  - The module builds raw IPv4/UDP packets (`__alloc_skb`/`skb_put`/`ip_send_check`)
    and, per datagram (IPv4 path, size > 31): writes a **4-byte big-endian sequence
    number `= packet_index + 2` at the start of the UDP payload**, then random/zero
    fill from payload offset 4. (IPv6: same, payload offset differs.) **[FW]**
    blast's compat UDP send now emits exactly this sequenced format.

- **UDP port scheme - confirmed and refined.** Userspace `FUN_080516b6`:
  `base = atoi(param[2]); off = base + 0x100;` then per connection `i`, one side
  binds `base` / connects `base+256+i`, the mirror side swaps - **identical to the
  btest.exe orchestrators.** Crucially **`base` is a negotiated config parameter,
  not a fixed 2000**: it arrives through RouterOS's internal `nv::message` IPC from
  the listener that accepts the TCP control connection and spawns the btest worker.

- **UDP base port - SOLVED (via packet capture).** A `tcpdump` of a real session
  settled it: right after the `01 00 00 00` response, for a UDP test the server
  sends a **2-byte big-endian UDP base port** on the TCP control connection
  (e.g. `07 fd` = 2045). The base is **ephemeral** - the next free port up from the
  server's "allocate UDP ports from" (2000), so it varies per test (2044/2045/2048…).
  The server then binds `base`, streams from `base` to the client at **`base+256`**,
  and expects the client's upload from `base+256` back to `base`. blast now reads
  this 2-byte base during the handshake and binds `base+256` accordingly.
  **[CAPTURE-VERIFIED]**
- **Live result - full bidirectional UDP interop:** against the device, compat UDP
  **download = 135.9 Mbps received**, **upload = ~475 Mbps** (confirmed by the
  server's own `07` byte counter, e.g. `07 8e 00 00 01 00 00 00 10 92 88 03` =
  0x03889210 bytes in second 1). Together with TCP (71/502 Mbps), **blast is now a
  fully interoperable MikroTik btest client over both TCP and UDP.**

## 9. Multi-connection TCP (connection-count > 1) - CAPTURE-VERIFIED

RouterOS opens multiple TCP connections per test (default **20**). The extra
connections are coordinated by a session token (RE'd via a fake-server capture):

- **Control connection (conn 0):** the usual handshake; the command's `conn_count`
  byte is N. On success the server's "ok" is **`01 TOK_LO TOK_HI 00`** - bytes 1-2
  are a per-session **token** (0 means single-connection).
- **Data connections (1..N-1):** each reads the 4-byte hello, then sends a 16-byte
  marker **`[token:2 LE][0x0002][12 zeros]`**. The `0x0002` is a constant data-stream
  tag (identical for every data conn - it is *not* the count or the index). The
  server replies with no "ok"; data simply flows.
- **Data flows on all N connections** (conn 0 included). For an upload, the server
  reports its aggregate received bytes via the `07` heartbeats on conn 0's otherwise
  idle reverse direction.
- **Distinguishing a data conn from a control conn:** a command's byte 2 is the
  random flag (0/1); a data-conn marker's byte 2 is `0x02`. blast keys on that.

blast implements both ends. Verified vs live RouterOS: client `-P 4..20` download
~78 Mbps / upload ~410 Mbps; as a server, a real `cc=20` client downloads ~397 Mbps
and uploads ~159 Mbps. blast<->blast multi-connection scales to ~32 Gbps (loopback).
(Bidirectional `both` multi-conn flows data but leaves the peer's upload counter at
0 - conn 0 carries data in both directions, so there is no idle lane for `07`.)

## 10. Ubiquiti airOS "Speed Test" = classic iperf2 - FIRMWARE-VERIFIED

Ubiquiti airMAX (airOS) radios have a UI **Tools -> Speed Test** that measures
device-to-device throughput. Reverse-engineering the airOS 6.x firmware
(`UBNT XM.ar7240.v6.1.8`, squashfs rootfs at offset 1231551) settles how it works:

- `/bin/iperf` is **`iperf version 2.0.4 (7 Apr 2008) pthreads`** - classic **iperf2**.
- The UI test (`sptest.js` + `ubntbox`) runs that iperf over the management network;
  it is an ordinary iperf2 throughput test (default **TCP port 5001**).

iperf2 wire protocol (implemented as `blast iperf2`, verified against stock `iperf`):

- **TCP**: a normal unidirectional test is just a **raw data stream** - the receiver
  times the bytes; there is no per-block header (the 24-byte `client_hdr` only appears
  for `-d`/`-r` dual tests). So an upload test = connect to :5001 and stream.
- **UDP**: every datagram begins with a 12-byte `UDP_datagram` header
  (`int32 id`, `uint32 sec`, `uint32 usec`, network order). `id` counts up; the client
  ends the test by sending datagrams with a **negative `id`**. The server then returns
  a **`server_hdr`** report packet: a 12/16-byte datagram echo, then network int32
  `flags`(0x80000000 bit), `total_len1`, `total_len2`, `stop_sec`, `stop_usec`,
  `error_cnt`(lost), `outorder_cnt`, `datagrams`(total), `jitter1`, `jitter2`. Locate
  the struct by its flags word (the echo's FIN id also has the high bit, so skip the
  first 12 bytes).

Verified wire-compatible with stock `iperf`(2) both directions: TCP counters match
(15-18 Gbps loopback); UDP loss+jitter match exactly (`168/17114 0.98% 0.003ms` ==
iperf's own). The actual airOS `iperf 2.0.4` binary runs under `qemu-mips-static`
(`-L <rootfs>`) for byte-level checks, though its uClibc threads need a real radio to
run a full test. Live test against an airOS device is pending working credentials.
