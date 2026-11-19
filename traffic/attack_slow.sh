#!/usr/bin/env bash
# Low-rate attack to test threshold sensitivity.
#   attack_slow.sh [TARGET] [DURATION] [MODE=syn|scan] [RATE=5]   (RATE = packets/s)
target="${1:-10.0.0.1}"; dur="${2:-60}"; mode="${3:-syn}"; rate="${4:-5}"
here="$(cd "$(dirname "$0")" && pwd)"
if [ "$mode" = "scan" ]; then
  exec bash "$here/attack_portscan.sh" "$target" "$dur" "$rate"
else
  exec bash "$here/attack_syn_flood.sh" "$target" "$dur" "$rate"
fi
