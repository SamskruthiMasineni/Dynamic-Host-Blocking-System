#!/usr/bin/env bash
# One-command experiment launcher (Person 1).
#   ./run_experiment.sh <baseline|normal|syn|scan|mixed|slow|expiry> [options]
#   ./run_experiment.sh syn --label sdn --rate 1000
#   ./run_experiment.sh --help
# Start the Ryu controller first (separate terminal), and restart it between runs
# so the previous run's blocklist does not carry over.
cd "$(dirname "$0")"
if [ "$EUID" -ne 0 ]; then exec sudo -E python3 topology/run_experiment.py "$@"; fi
exec python3 topology/run_experiment.py "$@"
