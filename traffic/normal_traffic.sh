#!/usr/bin/env bash
# Normal (benign) TCP traffic.
#   normal_traffic.sh server [webroot]
#   normal_traffic.sh client TARGET DURATION_S [mode=mixed|http|iperf] [name] [outdir]
# Server (h1): HTTP on :80 plus iperf on :5001. Runs until killed.
# Client (h2-h4): random curl / iperf sessions with random pauses. Every request
# is logged to <outdir>/latency_<name>.csv (epoch,type,ok,time_s) so we can show
# that legitimate users keep working while an attacker is blocked.

role="$1"

if [ "$role" = "server" ]; then
  root="${2:-/tmp/dhbs_www}"
  mkdir -p "$root"
  [ -f "$root/index.html" ] || echo "<html><body>DHBS test server</body></html>" > "$root/index.html"
  [ -f "$root/file.bin" ] || head -c 1048576 /dev/urandom > "$root/file.bin"
  iperf -s >/dev/null 2>&1 &
  exec python3 -m http.server 80 --directory "$root" >/dev/null 2>&1
fi

if [ "$role" = "client" ]; then
  target="${2:?target ip}"; dur="${3:?duration}"; mode="${4:-mixed}"
  name="${5:-client}"; outdir="${6:-.}"
  out="$outdir/latency_${name}.csv"
  mkdir -p "$outdir"
  [ -f "$out" ] || echo "epoch,type,ok,time_s" > "$out"
  end=$(( $(date +%s) + dur ))
  while [ "$(date +%s)" -lt "$end" ]; do
    kind="$mode"
    if [ "$mode" = "mixed" ]; then
      if [ $((RANDOM % 2)) -eq 0 ]; then kind=http; else kind=iperf; fi
    fi
    start=$(date +%s.%N)
    if [ "$kind" = "http" ]; then
      code=$(curl -s -o /dev/null --max-time 5 -w '%{http_code}' "http://$target/file.bin"); rc=$?
      ok=0; [ $rc -eq 0 ] && [ "$code" = "200" ] && ok=1
    else
      timeout 6 iperf -c "$target" -t 2 >/dev/null 2>&1; rc=$?
      ok=0; [ $rc -eq 0 ] && ok=1
    fi
    stop=$(date +%s.%N)
    echo "$start,$kind,$ok,$(awk -v a="$start" -v b="$stop" 'BEGIN{printf "%.4f", b-a}')" >> "$out"
    sleep "$(awk -v r=$RANDOM 'BEGIN{printf "%.2f", 0.5 + r/32767*2.5}')"
  done
  exit 0
fi

echo "usage: $0 server [webroot] | client TARGET DURATION [mode] [name] [outdir]" >&2
exit 1
