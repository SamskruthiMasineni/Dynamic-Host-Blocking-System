#!/usr/bin/env bash
# Repeated TCP SYN port scans (use on h6).
#   attack_portscan.sh [TARGET=10.0.0.1] [DURATION=60] [MAX_RATE=] [RANGE=1-1000]
# MAX_RATE (packets/s) is optional; empty = full speed. Falls back to a plain
# Python connect-scan if nmap is not installed.
target="${1:-10.0.0.1}"; dur="${2:-60}"; rate="${3:-}"; range="${4:-1-1000}"
end=$(( $(date +%s) + dur ))
while [ "$(date +%s)" -lt "$end" ]; do
  remaining=$(( end - $(date +%s) ))
  [ "$remaining" -le 0 ] && break
  if command -v nmap >/dev/null 2>&1; then
    extra=""; [ -n "$rate" ] && extra="--max-rate $rate"
    timeout "$remaining" nmap -sS -Pn -n -T4 $extra -p "$range" "$target" >/dev/null 2>&1
  else
    python3 - "$target" "$range" "$remaining" <<'PY'
import socket, sys, time
t, rng, rem = sys.argv[1], sys.argv[2], float(sys.argv[3])
a, b = map(int, rng.split("-")); end = time.time() + rem
for p in range(a, b + 1):
    if time.time() > end:
        break
    s = socket.socket(); s.settimeout(0.2)
    try:
        s.connect((t, p))
    except Exception:
        pass
    finally:
        s.close()
PY
  fi
  sleep 1
done
exit 0
