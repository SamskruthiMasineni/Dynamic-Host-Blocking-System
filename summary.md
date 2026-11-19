# Run summary: 20261118_183516_syn_sdn

Scenario `syn`, label `sdn`, duration 120 s, attack 30-90 s

## Legitimate clients (h2-h4)

| phase | requests | success % | mean latency of OK requests (s) |
|---|---|---|---|
| pre-attack (5-30 s) | 33 | 100.0 | 0.407 |
| attack (30-90 s) | 71 | 100.0 | 0.667 |
| post-attack (90-120 s) | 39 | 100.0 | 0.512 |

## Attackers: offered vs delivered SYNs

| host | SYNs offered in attack | SYNs delivered to server | delivered % | est. time to effective block (s) |
|---|---|---|---|---|
| h5 | 27140 | 2266 | 8.3 | 6 |

Time to effective block = first second after attack start from which, for 3 s in a row, at most 10% of the attacker's SYNs still reach the server (1 s resolution).

## Baseline (normal period) and suggested thresholds

```
{
  "per_host": {
    "h2": {
      "pps_mean": 33057.7,
      "pps_p95": 90191.2,
      "pps_max": 103481.5,
      "syn_per_s_mean": 0.28,
      "syn_per_s_p95": 1.0,
      "syn_per_s_max": 1,
      "distinct_ports_max": 2
    },
    "h3": {
      "pps_mean": 45.0,
      "pps_p95": 105.3,
      "pps_max": 143.0,
      "syn_per_s_mean": 0.64,
      "syn_per_s_p95": 1.0,
      "syn_per_s_max": 1,
      "distinct_ports_max": 1
    },
    "h4": {
      "pps_mean": 19492.9,
      "pps_p95": 82974.9,
      "pps_max": 101640.0,
      "syn_per_s_mean": 0.4,
      "syn_per_s_p95": 1.0,
      "syn_per_s_max": 1,
      "distinct_ports_max": 2
    }
  },
  "suggested": {
    "SYN_RATE_MAX": 10,
    "PORTS_MAX": 20,
    "PPS_MAX": 207000,
    "window_s": 5,
    "note": "starting points = 2x the worst normal value seen. Iperf bursts make pps spiky, so prefer SYN rate / distinct ports as the main rules. Re-check with the 'normal' scenario."
  }
}
```
