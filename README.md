# Dynamic Host Blocking System (DHBS)

An SDN security project that detects abnormal TCP traffic (SYN floods and port scans) and automatically blocks the offending hosts with OpenFlow drop rules. Built with Mininet, Open vSwitch and a Ryu controller.

Computer Networks course project, Topic 12.

## How it works

The controller watches every new TCP connection in a small virtual network. If one host opens connections much faster than normal, the controller blocks that host on the switch and unblocks it after a timeout.

```
 Mininet network                         Ryu controller (dhbs_controller.py)
 ---------------                         -----------------------------------
 h1  server (whitelisted)                Learning switch  -> forwarding flows
 h2-h4 normal clients     <-- PacketIn / flow stats --     Monitor  -> SYN rate per host
 h5  SYN flood attacker   -- drop FlowMod (priority 100) ->  Detector -> rate > SYN_RATE_MAX ?
 h6  port-scan attacker                                      Blocker  -> blocklist + drop rule
        |                                                    Logger   -> logs/dhbs.log
   OpenFlow 1.3 switch s1
```

The architecture diagram is in `docs/architecture_diagram.png`.

### Detection

- Every TCP packet with SYN set and ACK not set counts as a new connection from its source IP.
- Forwarding flows for TCP match the full 5-tuple, so every new connection reaches the controller and is counted.
- Every `STATS_INTERVAL` seconds (default 5) the counts are turned into connections per second.
- A host above `SYN_RATE_MAX` (default 20 per second) is marked suspicious. Whitelisted hosts (the server) are never blocked.
- The controller also requests flow statistics (packets, bytes, active flows per source IP) every interval and logs them.

### Blocking

- The host is added to an in-memory blocklist with its block time, expiry and reason.
- The controller sends an OpenFlow `FlowMod` with priority 100, matching `eth_type=0x0800` and `ipv4_src=<host>`, with no actions (drop). Forwarding flows use priorities 10, 5 and 1, so the drop rule always wins.
- After `BLOCK_DURATION` seconds (default 60) the rule is deleted, the host is removed from the blocklist and the event is logged.

### Logging

Events are written with timestamps to the console and to `logs/dhbs.log`:

```
INFO    [RATE] 10.0.0.5: 2204 new TCP connections in 5s (440.8/s)
WARNING DETECTED 10.0.0.5 syn_rate=440.8/s limit=20/s
WARNING BLOCKED 10.0.0.5 for 60s (syn_rate=440.8/s limit=20/s)
INFO    UNBLOCKED 10.0.0.5 (block duration expired)
```

## Repository layout

```
controller/dhbs_controller.py   Ryu app: learning switch, monitor, detector, blocker, logger
topology/topo.py                Mininet topology: s1 + h1..h6, remote controller, OpenFlow 1.3
topology/run_experiment.py      Scenario driver and evidence recorder
traffic/normal_traffic.sh       HTTP/iperf server and random curl/iperf clients
traffic/attack_syn_flood.sh     hping3 SYN flood
traffic/attack_portscan.sh      nmap SYN port scan
traffic/attack_slow.sh          low-rate attack for threshold sensitivity
results/analyze.py              graphs, summary.md and baseline.json for a run
run_experiment.sh               one-command experiment launcher
docs/                           architecture diagram and report
logs/                           controller log (created at run time)
```

## Network

| Host | IP | Role |
| --- | --- | --- |
| h1 | 10.0.0.1 | Web and iperf server (whitelisted) |
| h2, h3, h4 | 10.0.0.2 to 10.0.0.4 | Normal clients |
| h5 | 10.0.0.5 | SYN flood attacker |
| h6 | 10.0.0.6 | Port-scan attacker |

One OpenFlow 1.3 switch (`s1`), controller at `127.0.0.1:6653`.

## Requirements

- Ubuntu (tested in a VirtualBox VM)
- Mininet and Open vSwitch
- Ryu 4.34 with Python 3.9 and eventlet 0.30.2 (newer Python versions are not compatible with this eventlet)
- Traffic tools: `hping3`, `nmap`, `iperf`, `curl`, `tcpdump`
- `python3-matplotlib` for the result graphs

## Setup

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch hping3 nmap iperf curl tcpdump python3-matplotlib

# Python 3.9 virtual environment for Ryu (using uv)
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv venv --python 3.9 ryu-env
source ryu-env/bin/activate
uv pip install "setuptools<58" wheel pbr
uv pip install --no-build-isolation eventlet==0.30.2 ryu==4.34
ryu-manager --version

chmod +x run_experiment.sh traffic/*.sh
```

## Running the demo

Use three terminals, and start Ryu before Mininet.

**Terminal 1: controller** (from the repository root, with `ryu-env` active)

```bash
source ryu-env/bin/activate
ryu-manager controller/dhbs_controller.py
```

**Terminal 2: network and traffic**

```bash
sudo mn -c
sudo python3 topology/topo.py
```

At the `mininet>` prompt:

```
h1 python3 -m http.server 80 &
h2 curl -s -o /dev/null -w "%{http_code}\n" http://10.0.0.1
h5 timeout 20 hping3 -S -p 80 -i u1000 10.0.0.1 > /dev/null 2>&1 &
```

Within about 5 seconds the controller log shows `DETECTED` and `BLOCKED` for 10.0.0.5.

**Terminal 3: verify**

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100
tail -f logs/dhbs.log
```

The drop rule (`nw_src=10.0.0.5 actions=drop`) is visible while the block is active. Back at `mininet>`, `h5 ping -c 3 10.0.0.1` fails and `h2 curl ...` still returns `200`. After 60 seconds `UNBLOCKED` appears and h5 can reach h1 again.

## Running the experiments

Restart the controller between runs, because the blocklist is kept in memory.

```bash
./run_experiment.sh baseline              # normal traffic only, measures normal behaviour
./run_experiment.sh normal                # false-positive check
./run_experiment.sh syn --label sdn       # single SYN flood attacker
./run_experiment.sh mixed --label sdn     # SYN flood and port scan with normal clients
./run_experiment.sh slow                  # low-rate attack (threshold sensitivity)
./run_experiment.sh expiry                # block, unblock, re-block
python3 results/analyze.py results/<run_folder> --block h5=<seconds>
```

Each run saves port counters, SYN captures, `ovs-ofctl dump-flows` snapshots, request latencies, graphs and a `summary.md` in `results/<run>/`. See `README_person1.md` for details of the experiment tooling.

## Configuration

Settings are constants at the top of `controller/dhbs_controller.py`.

| Setting | Default | Meaning |
| --- | --- | --- |
| `STATS_INTERVAL` | 5 s | Measurement window |
| `SYN_RATE_MAX` | 20 /s | New connections per second that mark a host suspicious |
| `BLOCK_DURATION` | 60 s | How long a host stays blocked |
| `BLOCK_PRIORITY` | 100 | Priority of the drop rule |
| `WHITELIST` | `{"10.0.0.1"}` | Hosts that are never blocked |

The threshold should be chosen from a baseline run: measure normal traffic first, then set the limit well above the normal peak and well below the attack rate. In our test the SYN flood reached about 440 new connections per second against a limit of 20.

## Results

| Scenario | Expected result |
| --- | --- |
| Normal traffic only | No host detected or blocked |
| SYN flood from h5 | `DETECTED` and `BLOCKED` within one or two intervals, drop rule visible in the switch |
| Attack with normal clients | Only the attacker is blocked, h2 to h4 keep working |
| After the block duration | `UNBLOCKED`, rule removed, traffic resumes |
| Slow attack below the limit | Not detected (known limitation) |

## Limitations and future work

- Detection uses only the SYN rate. A port-scan rule (distinct destination ports per source), a packets-per-second rule and a requirement of two consecutive intervals above the limit are planned.
- A fixed threshold cannot see slow attacks below it.
- Blocking is by source IP, so spoofed source addresses could cause innocent addresses to be blocked.
- The controller is a single point of failure, and a very large flood of PacketIn messages can overload it. Blocking quickly keeps the flood away from the controller.
- The blocklist is kept in memory and is lost when the controller restarts.

## Troubleshooting

- `RTNETLINK answers: File exists` when starting Mininet: run `sudo mn -c` and try again.
- `Switch did not connect`: start Ryu first and check that it listens on port 6653.
- `ryu-manager` fails to import `imp`: the virtual environment is using Python 3.12 or newer. Rebuild it with Python 3.9.
- Ryu lags during a flood: use a lower rate, for example `./run_experiment.sh syn --label sdn --rate 300`, and avoid `--rate flood`.

## Team

- Person 1: topology, traffic generation, experiment runner and graphs: [name]
- Person 2: Mininet integration, learning switch and flow statistics: [name]
- Person 3: detection, blocking, logging, architecture and report: [name]

## License

[Add a license, for example MIT, or state that this is a coursework project.]
