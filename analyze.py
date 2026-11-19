#!/usr/bin/env python3
"""
Turn one experiment run into numbers and graphs (Person 1).

    python3 results/analyze.py results/<run_dir> [--block h5=42.5] [--window 5]

Outputs, inside the run directory:
    summary.md          phase table, SYN offered vs delivered, estimated time-to-block
    baseline.json       per-host normal-traffic statistics + suggested thresholds
                        (hand this to Person 3 -> config.py)
    pps_per_host.png    packets/s each host sends into the switch
    syn_rate.png        SYN/s per host; dashed = SYNs that still reach the server
    server_rx_pps.png   packets/s delivered to the server port
    latency.png         every client request (red x = failed)

--block h5=42.5 draws a vertical line where the controller log says h5 was blocked
(seconds since the run started). Repeat the flag for more hosts.

"offered" = traffic the host sent into the switch (port rx). The drop rule discards
it inside the switch, so offered load stays high while "delivered" falls to zero.
"""
import argparse
import csv
import json
import math
import os
import re
from collections import defaultdict

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    plt = None

SYN_RE = re.compile(r"^(\d+\.\d+)\s+IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):")
HOSTS = range(1, 7)
CLIENTS = (2, 3, 4)
ATTACKERS = (5, 6)


def pct(vals, p):
    if not vals:
        return 0.0
    s = sorted(vals)
    k = (len(s) - 1) * p / 100.0
    f, c = math.floor(k), math.ceil(k)
    return s[f] if f == c else s[f] + (s[c] - s[f]) * (k - f)


def load_ports(run, t0):
    d = defaultdict(list)
    with open(os.path.join(run, "ports.csv")) as f:
        for r in csv.DictReader(f):
            d[int(r["port"])].append((float(r["epoch"]) - t0, int(r["rx_pkts"]), int(r["tx_pkts"])))
    return d


def rate(series, idx):
    out = []
    for p, q in zip(series, series[1:]):
        dt = q[0] - p[0]
        if dt > 0:
            out.append((q[0], max(0, q[idx] - p[idx]) / dt))
    return out


def load_syns(path, t0):
    ev = []
    if os.path.exists(path):
        with open(path, errors="ignore") as f:
            for line in f:
                m = SYN_RE.match(line)
                if m:
                    ev.append((float(m.group(1)) - t0, m.group(2), int(m.group(5))))
    return ev


def per_second(events, ip):
    c = defaultdict(int)
    for t, src, _ in events:
        if src == ip:
            c[int(math.floor(t))] += 1
    return c


def ports_per_window(events, ip, lo, hi, w):
    out, s = [], int(lo)
    mine = [(t, p) for t, src, p in events if src == ip]
    while s + w <= hi:
        out.append(len({p for t, p in mine if s <= t < s + w}))
        s += w
    return out


def load_latency(run, t0):
    rows = {}
    for h in CLIENTS:
        path = os.path.join(run, "latency_h%d.csv" % h)
        rows[h] = []
        if os.path.exists(path):
            with open(path) as f:
                for r in csv.DictReader(f):
                    rows[h].append((float(r["epoch"]) - t0, r["type"], int(r["ok"]), float(r["time_s"])))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir")
    ap.add_argument("--window", type=int, default=5, help="window (s) for distinct-ports metric")
    ap.add_argument("--warmup", type=float, default=5, help="seconds ignored at start")
    ap.add_argument("--block", action="append", default=[], help="host=seconds_since_start")
    a = ap.parse_args()

    run = a.run_dir.rstrip("/")
    meta = json.load(open(os.path.join(run, "events.json")))
    t0, dur = meta["t0"], meta["duration"]
    a0, a1 = meta.get("attack_start"), meta.get("attack_end")
    has_attack = a0 is not None and any(e["kind"] != "normal" for e in meta["events"])
    blocks = {}
    for b in a.block:
        h, v = b.split("=")
        blocks[h] = float(v)

    ports = load_ports(run, t0)
    sent_pps = {h: rate(ports[h], 1) for h in HOSTS}          # host -> switch
    server_rx = rate(ports[1], 2)                              # switch -> h1 (tx on port 1)
    syns = {h: load_syns(os.path.join(run, "syn_h%d.txt" % h), t0) for h in HOSTS}
    delivered = syns[1]                                        # SYNs that were forwarded to h1
    lat = load_latency(run, t0)

    lo = a.warmup
    hi = a0 if has_attack else dur

    # ---------- baseline statistics (normal period only, clients h2-h4) ----------
    base = {}
    for h in CLIENTS:
        ip = "10.0.0.%d" % h
        pps = [v for t, v in sent_pps[h] if lo <= t < hi]
        sps = per_second(syns[h], ip)
        syn1 = [sps.get(s, 0) for s in range(int(lo), int(hi))]
        ports_w = ports_per_window(syns[h], ip, lo, hi, a.window)
        base["h%d" % h] = dict(
            pps_mean=round(sum(pps) / len(pps), 1) if pps else 0, pps_p95=round(pct(pps, 95), 1),
            pps_max=round(max(pps), 1) if pps else 0,
            syn_per_s_mean=round(sum(syn1) / len(syn1), 2) if syn1 else 0,
            syn_per_s_p95=round(pct(syn1, 95), 2), syn_per_s_max=max(syn1) if syn1 else 0,
            distinct_ports_max=max(ports_w) if ports_w else 0,
        )
    mx = lambda k: max((v[k] for v in base.values()), default=0)
    suggest = dict(
        SYN_RATE_MAX=max(10, math.ceil(2 * mx("syn_per_s_max"))),
        PORTS_MAX=max(20, math.ceil(2 * mx("distinct_ports_max"))),
        PPS_MAX=int(math.ceil(max(200, 2 * mx("pps_max")) / 100.0) * 100),
        window_s=a.window,
        note="starting points = 2x the worst normal value seen. Iperf bursts make pps spiky, so "
             "prefer SYN rate / distinct ports as the main rules. Re-check with the 'normal' scenario.",
    )
    with open(os.path.join(run, "baseline.json"), "w") as f:
        json.dump(dict(window_s=a.window, normal_period_s=[lo, hi], per_host=base, suggested=suggest), f, indent=2)

    # ---------- summary.md ----------
    L = ["# Run summary: %s" % meta["name"], "",
         "Scenario `%s`, label `%s`, duration %d s%s" % (
             meta["scenario"], meta["label"] or "-", dur,
             ", attack %s-%s s" % (a0, a1) if has_attack else ", no attack"), ""]

    phases = [("pre-attack", lo, a0), ("attack", a0, a1), ("post-attack", a1, dur)] if has_attack \
        else [("all", lo, dur)]
    L += ["## Legitimate clients (h2-h4)", "",
          "| phase | requests | success % | mean latency of OK requests (s) |", "|---|---|---|---|"]
    for name, p0, p1 in phases:
        reqs = [r for h in CLIENTS for r in lat[h] if p0 <= r[0] < p1]
        oks = [r for r in reqs if r[2]]
        L.append("| %s (%d-%d s) | %d | %s | %s |" % (
            name, p0, p1, len(reqs),
            "%.1f" % (100.0 * len(oks) / len(reqs)) if reqs else "-",
            "%.3f" % (sum(r[3] for r in oks) / len(oks)) if oks else "-"))
    L.append("")

    if has_attack:
        L += ["## Attackers: offered vs delivered SYNs", "",
              "| host | SYNs offered in attack | SYNs delivered to server | delivered % | "
              "est. time to effective block (s) |", "|---|---|---|---|---|"]
        for h in ATTACKERS:
            ip = "10.0.0.%d" % h
            off, dlv = per_second(syns[h], ip), per_second(delivered, ip)
            tot_o = sum(off.get(s, 0) for s in range(int(a0), int(a1)))
            if tot_o == 0:
                continue
            tot_d = sum(dlv.get(s, 0) for s in range(int(a0), int(a1)))
            ttb = None
            for s in range(int(a0), int(a1) - 2):
                if all(off.get(s + k, 0) > 0 and dlv.get(s + k, 0) <= 0.1 * off.get(s + k, 0) for k in range(3)):
                    ttb = s - a0
                    break
            L.append("| h%d | %d | %d | %.1f | %s |" % (
                h, tot_o, tot_d, 100.0 * tot_d / tot_o, "%.0f" % ttb if ttb is not None else "never blocked"))
        L += ["", "Time to effective block = first second after attack start from which, for 3 s in a row, "
                  "at most 10% of the attacker's SYNs still reach the server (1 s resolution).", ""]

    L += ["## Baseline (normal period) and suggested thresholds", "", "```",
          json.dumps(dict(per_host=base, suggested=suggest), indent=2), "```", ""]
    with open(os.path.join(run, "summary.md"), "w") as f:
        f.write("\n".join(L))
    print("\n".join(L))

    # ---------- plots ----------
    if plt is None:
        print("matplotlib not installed: skipped plots (pip3 install matplotlib)")
        return

    def decorate(ax, title, ylabel):
        if has_attack:
            ax.axvspan(a0, a1, color="red", alpha=0.08, label="attack window")
        for h, t in blocks.items():
            ax.axvline(t, color="black", linestyle="--", linewidth=1)
            ax.text(t, ax.get_ylim()[1], " %s blocked" % h, rotation=90, va="top", fontsize=8)
        ax.set_title(title)
        ax.set_xlabel("time since start (s)")
        ax.set_ylabel(ylabel)
        ax.set_xlim(0, dur)
        ax.grid(alpha=0.3)
        ax.legend(fontsize=7, ncol=2)

    fig, ax = plt.subplots(figsize=(9, 4.5))
    for h in HOSTS:
        ax.plot([t for t, _ in sent_pps[h]], [v for _, v in sent_pps[h]], label="h%d" % h)
    ax.set_yscale("symlog", linthresh=10)
    decorate(ax, "Packets/s each host sends into the switch (offered load)", "packets/s")
    fig.tight_layout(); fig.savefig(os.path.join(run, "pps_per_host.png"), dpi=150); plt.close(fig)

    fig, ax = plt.subplots(figsize=(9, 4.5))
    for h in HOSTS:
        ip = "10.0.0.%d" % h
        c = per_second(syns[h], ip)
        if any(c.values()):
            ax.plot(range(int(dur)), [c.get(s, 0) for s in range(int(dur))], label="h%d offered" % h)
    for h in ATTACKERS:
        c = per_second(delivered, "10.0.0.%d" % h)
        if any(c.values()):
            ax.plot(range(int(dur)), [c.get(s, 0) for s in range(int(dur))], "--", label="h%d reaching server" % h)
    ax.set_yscale("symlog", linthresh=10)
    decorate(ax, "New TCP connections (SYN) per second", "SYN/s")
    fig.tight_layout(); fig.savefig(os.path.join(run, "syn_rate.png"), dpi=150); plt.close(fig)

    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.plot([t for t, _ in server_rx], [v for _, v in server_rx], label="to server (s1-eth1 tx)")
    decorate(ax, "Packets/s delivered to the server port", "packets/s")
    fig.tight_layout(); fig.savefig(os.path.join(run, "server_rx_pps.png"), dpi=150); plt.close(fig)

    fig, ax = plt.subplots(figsize=(9, 4.5))
    for h in CLIENTS:
        good = [r for r in lat[h] if r[2]]
        bad = [r for r in lat[h] if not r[2]]
        ax.scatter([r[0] for r in good], [r[3] for r in good], s=12, label="h%d ok" % h)
        if bad:
            ax.scatter([r[0] for r in bad], [r[3] for r in bad], s=30, marker="x", color="red",
                       label="h%d failed" % h)
    decorate(ax, "Legitimate client request time", "seconds")
    fig.tight_layout(); fig.savefig(os.path.join(run, "latency.png"), dpi=150); plt.close(fig)
    print("plots written to", run)


if __name__ == "__main__":
    main()
