#!/usr/bin/env bash
# Runs every test scenario 5 times and analyses the results.
#   sudo ./run_experiments.sh          Linux: real tc/netem in network namespaces + tcpdump pcaps
#   ./run_experiments.sh sim           any OS, no root: built-in impairment on localhost
set -e
cd "$(dirname "$0")"
MODE="${1:-netns}"
SCENARIOS="${SCENARIOS:-baseline,loss2,loss5,loss10,asym,churn}"
REPS="${REPS:-5}"
SEED_BASE="${SEED_BASE:-100}"
python3 run_experiments.py --mode "$MODE" --scenarios "$SCENARIOS" --reps "$REPS" --seed-base "$SEED_BASE"
LATEST="$(ls -d results/*/ | sort | tail -1)"
python3 analyze.py "$LATEST"
