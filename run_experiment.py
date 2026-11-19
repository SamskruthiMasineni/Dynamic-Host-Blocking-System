#!/usr/bin/env python3
"""
Experiment driver (Person 1). Use via ./run_experiment.sh <scenario> [options].

Builds the Mininet topology, starts the server and clients, launches attacks on a
schedule, and records evidence into results/<run>/ :
    ports.csv       per-port packet/byte counters, sampled every 1 s
    syn_hN.txt      tcpdump of SYN packets seen on switch port N
    flows.log       `ovs-ofctl dump-flows s1` every 5 s (shows drop rules appear)
    latency_hN.csv  every curl/iperf request made by client hN (ok + time)
    events.json     schedule, start times and settings (read by analyze.py)

Scenarios (times in seconds; override with --duration/--attack-start/--attack-end)
    baseline  normal traffic only, 60 s      -> numbers for Person 3's thresholds
    normal    normal traffic only, 90 s      -> false-positive test
    syn       h5 SYN flood 30-90 of 120      -> single attacker
    scan      h6 port scan 30-90 of 120
    mixed     h5 SYN flood + h6 port scan together with normal clients
    slow      h5 slow SYN (5/s) + h6 slow scan -> threshold sensitivity
    expiry    h5 SYN flood 30-170 of 180     -> watch block, UNBLOCK, re-block
"""
import argparse
import csv
import datetime
import json
import os
import shutil
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from topo import build_net, N_HOSTS            # noqa: E402
from mininet.log import setLogLevel, info, error  # noqa: E402

TRAFFIC = os.path.join(ROOT, "traffic")
SERVER_IP = "10.0.0.1"
WEBROOT = "/tmp/dhbs_www"
TOOLS = ["hping3", "nmap", "iperf", "curl", "tcpdump", "ovs-ofctl"]

# scenario -> (default duration, default attack start, default attack end)
DEFAULTS = {
    "baseline": (60, None, None),
    "normal": (90, None, None),
    "syn": (120, 30, 90),
    "scan": (120, 30, 90),
    "mixed": (120, 30, 90),
    "slow": (120, 30, 90),
    "expiry": (180, 30, 170),
}


def build_events(scn, duration, a0, a1, rate, slow_rate, outdir):
    ev = []
    for host, offset, mode in (("h2", 0, "mixed"), ("h3", 1, "http"), ("h4", 2, "mixed")):
        ev.append(dict(host=host, kind="normal", script="normal_traffic.sh",
                       start=offset, end=duration,
                       args=["client", SERVER_IP, duration - offset, mode, host, outdir]))

    def syn(host):
        return dict(host=host, kind="syn_flood", script="attack_syn_flood.sh", start=a0, end=a1,
                    args=[SERVER_IP, a1 - a0, rate])

    def scan(host):
        return dict(host=host, kind="port_scan", script="attack_portscan.sh", start=a0, end=a1,
                    args=[SERVER_IP, a1 - a0])

    def slow_syn(host):
        return dict(host=host, kind="slow_syn", script="attack_slow.sh", start=a0, end=a1,
                    args=[SERVER_IP, a1 - a0, "syn", slow_rate])

    def slow_scan(host):
        return dict(host=host, kind="slow_scan", script="attack_slow.sh", start=a0, end=a1,
                    args=[SERVER_IP, a1 - a0, "scan", slow_rate])

    if scn in ("syn", "expiry"):
        ev.append(syn("h5"))
    elif scn == "scan":
        ev.append(scan("h6"))
    elif scn == "mixed":
        ev += [syn("h5"), scan("h6")]
    elif scn == "slow":
        ev += [slow_syn("h5"), slow_scan("h6")]
    return ev


def read_int(path):
    try:
        with open(path) as f:
            return int(f.read().strip())
    except Exception:
        return 0


class Sampler(threading.Thread):
    """Samples switch-port counters every second and dumps flows every 5 s."""

    def __init__(self, outdir, stop):
        super().__init__(daemon=True)
        self.outdir, self.stop = outdir, stop

    def run(self):
        f = open(os.path.join(self.outdir, "ports.csv"), "w", newline="")
        w = csv.writer(f)
        w.writerow(["epoch", "port", "rx_pkts", "rx_bytes", "tx_pkts", "tx_bytes"])
        flows = open(os.path.join(self.outdir, "flows.log"), "w")
        next_flow = 0
        while not self.stop.is_set():
            now = time.time()
            for p in range(1, N_HOSTS + 1):
                base = "/sys/class/net/s1-eth%d/statistics/" % p
                w.writerow(["%.3f" % now, p] +
                           [read_int(base + k) for k in ("rx_packets", "rx_bytes", "tx_packets", "tx_bytes")])
            f.flush()
            if now >= next_flow:
                try:
                    out = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"],
                                         capture_output=True, text=True, timeout=3).stdout
                    flows.write("=== %.3f ===\n%s\n" % (now, out))
                    flows.flush()
                except Exception:
                    pass
                next_flow = now + 5
            self.stop.wait(max(0.0, 1.0 - (time.time() - now)))
        f.close()
        flows.close()


def start_captures(outdir):
    procs = []
    syn_filter = "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"   # SYN without ACK
    for i in range(1, N_HOSTS + 1):
        f = open(os.path.join(outdir, "syn_h%d.txt" % i), "w")
        p = subprocess.Popen(["tcpdump", "-i", "s1-eth%d" % i, "-l", "-n", "-tt", "-s", "96", syn_filter],
                             stdout=f, stderr=subprocess.DEVNULL)
        procs.append((p, f))
    return procs


def launch(net, ev, outdir, procs):
    host = net.get(ev["host"])
    log = open(os.path.join(outdir, "logs", "%s_%s.log" % (ev["host"], ev["kind"])), "w")
    cmd = ["bash", os.path.join(TRAFFIC, ev["script"])] + [str(a) for a in ev["args"]]
    ev["epoch_start"] = time.time()
    procs.append((host.popen(cmd, stdout=log, stderr=subprocess.STDOUT), log))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", choices=sorted(DEFAULTS))
    ap.add_argument("--duration", type=int)
    ap.add_argument("--attack-start", type=int)
    ap.add_argument("--attack-end", type=int)
    ap.add_argument("--rate", default="1000", help="SYN flood rate in SYN/s, or 'flood' (default 1000)")
    ap.add_argument("--slow-rate", type=int, default=5, help="slow-attack packets/s (default 5)")
    ap.add_argument("--label", default="", help="tag, e.g. 'sdn' or 'no_protection' (baseline for comparison)")
    ap.add_argument("--bw", type=float, help="per-link bandwidth in Mbit/s (optional)")
    ap.add_argument("--controller-ip", default="127.0.0.1")
    ap.add_argument("--controller-port", type=int, default=6653)
    ap.add_argument("--no-capture", action="store_true", help="skip tcpdump (use with --rate flood)")
    ap.add_argument("--cli", action="store_true", help="open the Mininet CLI after the run")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Run as root (sudo ./run_experiment.sh ...)")
    missing = [t for t in TOOLS if shutil.which(t) is None]
    if missing:
        error("*** missing tools: %s  (sudo apt install hping3 nmap iperf curl tcpdump)\n" % ", ".join(missing))

    d_dur, d_a0, d_a1 = DEFAULTS[a.scenario]
    duration = a.duration or d_dur
    a0 = a.attack_start if a.attack_start is not None else d_a0
    a1 = a.attack_end if a.attack_end is not None else d_a1
    if a0 is not None and a1 is not None:
        a1 = min(a1, duration)
        if a1 <= a0:
            sys.exit("attack end must be after attack start")

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    name = "_".join(x for x in (stamp, a.scenario, a.label) if x)
    outdir = os.path.join(ROOT, "results", name)
    os.makedirs(os.path.join(outdir, "logs"))
    events = build_events(a.scenario, duration, a0, a1, a.rate, a.slow_rate, outdir)

    setLogLevel("info")
    net = build_net(a.controller_ip, a.controller_port, a.bw)
    net.start()
    procs, caps, stop = [], [], threading.Event()
    sampler = None
    try:
        if not net.waitConnected(timeout=15):
            error("*** s1 not connected to controller %s:%d. Start Ryu first.\n" %
                  (a.controller_ip, a.controller_port))
            return 1
        net.pingAll()
        loss = net.pingAll()
        info("*** pingall loss before run: %s%%\n" % loss)

        os.makedirs(WEBROOT, exist_ok=True)
        launch(net, dict(host="h1", kind="server", script="normal_traffic.sh", args=["server", WEBROOT]),
               outdir, procs)
        time.sleep(1.5)
        if not a.no_capture:
            caps = start_captures(outdir)
        sampler = Sampler(outdir, stop)
        sampler.start()
        time.sleep(1.0)

        t0 = time.time()
        info("*** run '%s' started, %d s total\n" % (name, duration))
        pending = sorted(events, key=lambda e: e["start"])
        last_print = -10
        while True:
            el = time.time() - t0
            if el >= duration:
                break
            while pending and pending[0]["start"] <= el:
                ev = pending.pop(0)
                if ev["kind"] != "normal":
                    info("*** t=%3.0fs  START %s on %s\n" % (el, ev["kind"], ev["host"]))
                launch(net, ev, outdir, procs)
            if el - last_print >= 10:
                info("    t=%3.0f / %d s\n" % (el, duration))
                last_print = el
            time.sleep(0.1)

        meta = dict(name=name, scenario=a.scenario, label=a.label, t0=t0, duration=duration,
                    attack_start=a0, attack_end=a1, rate=a.rate, slow_rate=a.slow_rate, bw=a.bw,
                    events=[{k: v for k, v in e.items() if k != "args"} for e in events])
        with open(os.path.join(outdir, "events.json"), "w") as f:
            json.dump(meta, f, indent=2)
        info("*** run finished. Evidence in %s\n" % outdir)
        if a.cli:
            from mininet.cli import CLI
            CLI(net)
    finally:
        stop.set()
        if sampler:
            sampler.join(timeout=3)
        for p, f in procs + caps:
            try:
                p.terminate()
            except Exception:
                pass
            f.close()
        subprocess.run(["pkill", "-f", "hping3|nmap|iperf|dhbs_www"], stderr=subprocess.DEVNULL)
        net.stop()
        if os.environ.get("SUDO_USER"):
            subprocess.run(["chown", "-R", os.environ["SUDO_USER"], outdir], stderr=subprocess.DEVNULL)
    return 0


if __name__ == "__main__":
    sys.exit(main())
