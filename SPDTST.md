# Ubiquiti airOS "Speed Test" (`spdtst.ko`) - reverse-engineering notes

The airOS **Tools -> Speed Test** feature (Ubiquiti's equivalent of MikroTik's btest)
is **not iperf**. It is a custom kernel module, **`spdtst.ko`**, driven through
`/proc/net/spdtst/stctl`, with the two radios coordinating over their web UIs. (The
`/bin/iperf` on the box is `iperf 2.0.4`, used only by the manual CLI - that one is
implemented as [`blast iperf2`](blast/README.md).)

Reverse-engineered from airOS 6.x firmware (`spdtst.ko`, MIPS32 BE, kernel 2.6.32.71)
with Ghidra, cross-checked against the live web backend (`/usr/www/lib/sptest.inc`,
`sptest_action.cgi`) and a live XW.v6.3.11 radio. The proprietary module and its full
decompilation are **not** redistributed here; this is the protocol write-up.

## 1. How a test is driven

The web UI's `actionStart` does, per radio:

```
insmod /lib/modules/`uname -r`/spdtst.ko
echo "<ticket> init <peer-ip>  > /proc/net/spdtst/stctl"   # master only
echo "<ticket> duration <secs> > /proc/net/spdtst/stctl"   # 1..6000
echo "<ticket> direction <dir> > /proc/net/spdtst/stctl"   # rx | tx | dx
echo "<ticket> start          > /proc/net/spdtst/stctl"
# the slave side does: echo "<ticket> slave > /proc/net/spdtst/stctl"
# stop:                echo "<ticket> stop  > ..."
```

The **master** also calls the **slave's** web (`/sptest_action.cgi?action=slave`, with
the slave's login) so the slave loads the module and enters slave mode first. `stctl`
also takes `datasize <n>` / `datarate <n>`; reading it back gives `Session ID/State/
Flags/Out Dev/In Dev`, `Duration/Data size/Data rate`, and per-direction
`<pps>pps (<bps>bps) - time: <us>us`. State `10` == completed.

## 2. Transport + header (CONFIRMED)

spdtst rides **UDP** (the module hand-builds IP+UDP+payload skbs and `dev_queue_xmit`s
them). Every message's UDP payload starts with a 12-byte big-endian header:

```
off sz  field
0   4   magic     = 0xDA51A514
4   1   version   = 0x01
5   1   msg_type
6   2   length     (BE) = total message length incl. this header
8   4   session_id (BE)
12  ..  message payload
```

The receiver (`st_nf_rx`) is a netfilter hook that matches on the magic at IP-offset 28
(= IP[20]+UDP[8]) and `ip_total_len == spdtst_len + 28`. There is **no port match** -
matching is purely by magic.

## 3. Messages

`PARAMS` is fully decoded; the rest are named from the module's log strings + `skb_put`
sizes (non-PARAMS `msg_type` values are provisional - the decompiler inlined the
builders).

| message | payload | notes |
|---|---|---|
| **PARAMS** (type 1) | 12 B: `direction(u32) duration(u32) datasize(u16) datarate(u16)` | master -> slave |
| PARAMS_ACK | - | slave -> master |
| RX_READY | small | slave is ready to receive |
| DATA_START / DATA / DATA_ALIVE(42 B) / DATA_END | `datasize` filler | the throughput phase |
| RESULTS | 80 B of counters | exchanged after the run |
| FINISH | - | teardown |

Flow: `PARAMS -> PARAMS_ACK -> RX_READY -> DATA_START -> DATA/DATA_ALIVE... -> DATA_END
-> RESULTS -> FINISH`. `direction = dx` runs both ways.

## 4. It is a *link* tester, not host-to-host (key finding)

`st_nf_rx` only fires on traffic **bridged/forwarded** through the radio (it calls
`st_get_br_pdev` for the bridge *output* port, else "Cannot find bridge output port").
spdtst measures the throughput of the link a radio **bridges over** - a station/AP pair
with a real client behind the bridge. Verified on a live radio: driving `init <ip>;
start` toward a directly-addressed host stalls at **State 2** (no bridge port to forward
through), and a crafted packet to a radio's own IP is delivered locally so the hook
never sees it. A clean live exercise therefore needs a genuine bridged link, captured
**on a radio** (`tcpdump`).

## 5. `blast spdtst`

blast implements the confirmed wire format (UDP, magic, header, PARAMS, RESULTS) as a
client/server, and interoperates blast<->blast:

```bash
blast spdtst --server                       # slave (listen)
blast spdtst <peer> -d 10 -b 500            # master: tx for 10s, ~500 Mbit/s
blast spdtst <peer> -d 10 -D dx --datasize 1472
```

The master prints sent vs peer-received (from the RESULTS exchange) and loss. The
non-PARAMS message codes and the data-phase are faithful blast<->blast but provisional
against real airOS until validated on a bridged link (see s4).
