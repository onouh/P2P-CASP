#!/usr/bin/env bash
# Phase 1 deliverable: one automated 'Baseline local' run (1 server + 4 clients on localhost).
set -e
cd "$(dirname "$0")"
python3 run_experiments.py --mode sim --scenarios baseline --reps 1
