#!/usr/bin/env bash
# Automated blast <-> MikroTik btest matrix.
#
# Usage:   scripts/test-mikrotik.sh <host> [user] [password]
# Example: scripts/test-mikrotik.sh 192.0.2.1
#          scripts/test-mikrotik.sh 192.0.2.1 admin 'secret'   # auth (RouterOS >=6.43 = EC-SRP5)
#
# Runs the client-side matrix (blast -> MikroTik): TCP/UDP x download/upload,
# a rate-limit sweep, and a packet-size sweep. Prints avg tx/rx, the peer's
# actually-received rate (from 07 heartbeats), and UDP loss%.
set -u
HOST="${1:?usage: test-mikrotik.sh <host> [user] [password]}"
USER="${2:-}"
PASS="${3:-}"
DUR="${DUR:-4}"
BLAST="${BLAST:-$(dirname "$0")/../target/release/blast}"
AUTH=(); [ -n "$USER" ] && AUTH=(--user "$USER" --password "$PASS")

j() { # extract a numeric json field
  sed -nE "s/.*\"$2\":([0-9.]+).*/\1/p" <<<"$1" | head -1
}
mbps() { awk -v b="${1:-0}" 'BEGIN{printf "%.1f", b/1e6}'; }

run() { # label  proto-flag  dir  extra-args...
  local label="$1" proto="$2" dir="$3"; shift 3
  local out
  out=$(timeout $((DUR+8)) "$BLAST" client "$HOST" --mode compat "$proto" -D "$dir" -d "$DUR" "${AUTH[@]}" "$@" --json 2>&1)
  if grep -q '"seconds"' <<<"$out"; then
    printf "  %-26s tx=%-8s rx=%-8s peer=%-8s loss=%s%%\n" \
      "$label" \
      "$(mbps "$(j "$out" avg_tx_bps)")" "$(mbps "$(j "$out" avg_rx_bps)")" \
      "$(mbps "$(j "$out" peer_avg_bps)")" "$(j "$out" loss_pct)"
  else
    printf "  %-26s ERROR: %s\n" "$label" "$(grep -oE 'Error.*' <<<"$out" | head -1)"
  fi
}

echo "blast <-> MikroTik @ $HOST  (duration ${DUR}s${USER:+, auth as $USER})"
echo "[ protocol x direction ]"
run "TCP download"  -t rx
run "TCP upload"    -t tx
run "UDP download"  -u rx
run "UDP upload"    -u tx
echo "[ UDP upload rate sweep ]  (peer-received reveals real ingest capacity)"
for r in 50M 100M 300M 1G unlimited; do
  [ "$r" = unlimited ] && run "UDP up ($r)" -u tx || run "UDP up ($r)" -u tx -b "$r"
done
echo "[ UDP upload packet-size sweep @ -b 100M ]"
for s in 256 512 1000 1432; do run "UDP up size=$s" -u tx --size "$s" -b 100M; done
echo "done."
