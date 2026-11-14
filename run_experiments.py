#!/usr/bin/env python3
"""
Reproducible experiment runner for P2P-CASP (1 server + 4 clients).

Two modes:
  --mode netns  Linux + root. Builds one network namespace per node, joined by a bridge,
                applies the spec's tc/netem commands per node and captures a pcap with
                tcpdump. Use this for the graded results.
  --mode sim    Any OS, no root. All nodes run on localhost and the impairment is applied
                by the program itself on egress (same loss / delay / jitter numbers,
                seeded). pcaps are written by the program.

Scenarios (spec section 3):
  baseline   no impairment                     -> all 4 complete < 5 s, server <= 50 kbps
  loss5      loss 5% on every node             -> completes, duplicates <= 2 %
  asym       delay 100ms 20ms on clients 1, 2  -> clients 3, 4 serve > 75 % of P2P transfers
  churn      client 2 hard-killed at 50 %      -> the others detect it and still finish
  lossN      any other loss percentage (e.g. loss2, loss10) for the loss-rate sweep

Example:
  python3 run_experiments.py --mode sim --reps 5
  sudo python3 run_experiments.py --mode netns --reps 5 --scenarios baseline,loss5,asym,churn
"""
import argparse
import collections
import csv
import datetime
import os
import platform
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
N_CLIENTS = 4
FAST_CLIENTS = (3, 4)
SUBNET = "10.77.0."
BRIDGE = "caspbr0"


def scenario_config(name):
    """Returns per-node impairment: {node: {"loss": pct, "delay": ms, "jitter": ms}}, plus die_at."""
    nodes = ["server"] + ["c%d" % i for i in range(1, N_CLIENTS + 1)]
    imp = {n: {"loss": 0.0, "delay": 0.0, "jitter": 0.0} for n in nodes}
    die_at = {}
    if name == "baseline":
        pass
    elif name.startswith("loss"):
        pct = float(name[4:])
        for n in nodes:
            imp[n]["loss"] = pct
    elif name == "asym":
        for n in ("c1", "c2"):
            imp[n]["delay"], imp[n]["jitter"] = 100.0, 20.0
    elif name == "churn":
        die_at[2] = 0.5
    else:
        sys.exit("unknown scenario: " + name)
    return imp, die_at


def netem_args(i):
    parts = []
    if i["delay"]:
        parts.append("delay %gms" % i["delay"] + (" %gms" % i["jitter"] if i["jitter"] else ""))
    if i["loss"]:
        parts.append("loss %g%%" % i["loss"])
    return " ".join(parts)


def sh(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


# ---------------------------------------------------------------- netns
class NetnsTopology:
    """server = 10.77.0.1, client i = 10.77.0.(10+i); each in namespace casp-<node>."""

    def __init__(self):
        if platform.system() != "Linux" or os.geteuid() != 0:
            sys.exit("--mode netns needs Linux and root (sudo). Use --mode sim otherwise.")
        for tool in ("ip", "tc"):
            if not shutil.which(tool):
                sys.exit("missing tool: %s (install iproute2)" % tool)
        self.nodes = ["server"] + ["c%d" % i for i in range(1, N_CLIENTS + 1)]
        self.teardown()
        sh("ip link add %s type bridge" % BRIDGE)
        sh("ip link set %s up" % BRIDGE)
        for n in self.nodes:
            ns, dev = "casp-" + n, "v-" + n
            sh("ip netns add %s" % ns)
            sh("ip link add %s type veth peer name %s-br" % (dev, dev))
            sh("ip link set %s netns %s" % (dev, ns))
            sh("ip link set %s-br master %s" % (dev, BRIDGE))
            sh("ip link set %s-br up" % dev)
            sh("ip -n %s addr add %s/24 dev %s" % (ns, self.ip(n), dev))
            sh("ip -n %s link set %s up" % (ns, dev))
            sh("ip -n %s link set lo up" % ns)

    def ip(self, node):
        return SUBNET + ("1" if node == "server" else str(10 + int(node[1:])))

    def prefix(self, node):
        return ["ip", "netns", "exec", "casp-" + node]

    def apply(self, imp, run_dir):
        lines = []
        for n in self.nodes:
            sh("ip netns exec casp-%s tc qdisc del dev v-%s root" % (n, n), check=False)
            args = netem_args(imp[n])
            if args:
                cmd = "ip netns exec casp-%s tc qdisc add dev v-%s root netem %s" % (n, n, args)
                sh(cmd)
                lines.append(cmd)
        with open(os.path.join(run_dir, "netem_commands.txt"), "w") as f:
            f.write("\n".join(lines) + "\n" if lines else "(no impairment)\n")

    def start_capture(self, run_dir):
        if not shutil.which("tcpdump"):
            print("  tcpdump not found: no pcap for this run")
            return None
        return subprocess.Popen(["tcpdump", "-i", BRIDGE, "-w", os.path.join(run_dir, "trace.pcap"),
                                 "-U", "udp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def teardown(self):
        for n in ["server"] + ["c%d" % i for i in range(1, N_CLIENTS + 1)]:
            sh("ip netns del casp-%s" % n, check=False)
        sh("ip link del %s" % BRIDGE, check=False)


# ------------------------------------------------------------------ run
def run_once(args, topo, scenario, rep, seed, run_dir, port):
    os.makedirs(run_dir, exist_ok=True)
    imp, die_at = scenario_config(scenario)
    sim = topo is None
    py = [sys.executable, "-u"]
    capture = None
    if not sim:
        topo.apply(imp, run_dir)
        capture = topo.start_capture(run_dir)
        time.sleep(0.5)
    else:
        with open(os.path.join(run_dir, "netem_commands.txt"), "w") as f:
            f.write("built-in impairment (sim mode), netem equivalent per node:\n")
            for n, i in imp.items():
                f.write("  %s: %s\n" % (n, netem_args(i) or "none"))

    def sim_flags(node):
        if not sim:
            return []
        i = imp[node]
        return ["--sim-loss", str(i["loss"] / 100.0), "--sim-delay", str(i["delay"]),
                "--sim-jitter", str(i["jitter"]), "--pcap"]

    server_ip = "127.0.0.1" if sim else topo.ip("server")
    procs = []
    out = open(os.path.join(run_dir, "console.log"), "w")
    cmd = (([] if sim else topo.prefix("server")) + py + [os.path.join(HERE, "server.py"),
           "--bind", server_ip, "--port", str(port), "--seed", str(seed),
           "--expect", str(N_CLIENTS), "--out", run_dir, "--max-time", str(args.max_time)]
           + sim_flags("server"))
    server = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT)
    time.sleep(0.4)
    for cid in range(1, N_CLIENTS + 1):
        node = "c%d" % cid
        cmd = (([] if sim else topo.prefix(node)) + py + [os.path.join(HERE, "client.py"),
               "--id", str(cid), "--server", "%s:%d" % (server_ip, port),
               "--bind", "127.0.0.1" if sim else topo.ip(node), "--seed", str(seed),
               "--out", run_dir, "--max-time", str(args.max_time)] + sim_flags(node))
        if cid in die_at:
            cmd += ["--die-at", str(die_at[cid])]
        procs.append(subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT))
    for p in [server] + procs:
        try:
            p.wait(timeout=args.max_time + 10)
        except subprocess.TimeoutExpired:
            p.kill()
    if capture:
        time.sleep(0.5)
        capture.terminate()
        capture.wait()
    out.close()
    return summarise(scenario, rep, seed, run_dir, die_at, "sim" if sim else "netns")


def read_one(path):
    if not os.path.exists(path):
        return None
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    return rows[0] if rows else None


def server_peak_kbps(run_dir):
    """Independent check of the throttle: max IP-level bits sent in any 1 s window, from the log."""
    path = os.path.join(run_dir, "server_packets.csv")
    if not os.path.exists(path):
        return float("nan")
    window, total, peak = collections.deque(), 0, 0
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if not row["dir"].startswith("TX"):
                continue
            t, size = float(row["t_ms"]) / 1000.0, int(row["datagram_len"]) + 28
            window.append((t, size))
            total += size
            while window[0][0] <= t - 1.0:
                total -= window.popleft()[1]
            peak = max(peak, total)
    return peak * 8 / 1000.0


def parse_pairs(text):
    return {int(k): float(v) for k, v in (item.split(":") for item in text.split(";") if item)}


def summarise(scenario, rep, seed, run_dir, die_at, mode):
    clients = []
    for cid in range(1, N_CLIENTS + 1):
        row = read_one(os.path.join(run_dir, "metrics_client%d.csv" % cid))
        if row:
            clients.append(row)
    survivors = [c for c in clients if int(c["peer_id"]) not in die_at]
    done = [c for c in survivors if c["completed"] == "1"]
    times = [float(c["completion_time_ms"]) for c in done]
    served = collections.Counter()
    for c in clients:
        for _dst, n in parse_pairs(c["chunks_served_to_each_peer"]).items():
            served[int(c["peer_id"])] += n
    # count only transfers the receiver accepted (not duplicates)
    accepted = collections.Counter()
    for c in clients:
        for src, n in parse_pairs(c["chunks_from_each_peer"]).items():
            accepted[src] += n
    p2p_total = sum(accepted.values())
    fast_share = sum(accepted[i] for i in FAST_CLIENTS) / p2p_total if p2p_total else float("nan")
    dups = sum(int(c["duplicate_chunk_count"]) for c in survivors)
    got = sum(int(c["chunks_from_server"]) + int(c["chunks_from_peers"]) for c in survivors)
    rtts = [v for c in survivors for v in parse_pairs(c["mean_rtt_per_peer_ms"]).values()]
    srv = read_one(os.path.join(run_dir, "metrics_server.csv")) or {}
    valid_peers = set(srv.get("valid_peers", "").split(";"))      # the server is the state authority
    peak = server_peak_kbps(run_dir)
    res = {
        "scenario": scenario, "rep": rep, "seed": seed, "mode": mode,
        "clients_expected": len(survivors),
        "clients_completed": len(done),
        "clients_validated": sum(1 for c in done if c["peer_id"] in valid_peers),
        "completion_time_ms": "%.1f" % max(times) if len(done) == len(survivors) and times else "",
        "completion_time_ms_fastest": "%.1f" % min(times) if times else "",
        "p2p_transfer_ratio": "%.4f" % (sum(float(c["p2p_transfer_ratio"]) for c in done) / len(done)) if done else "",
        "duplicate_chunk_count": dups,
        "duplicate_ratio": "%.4f" % (dups / (got + dups)) if got else "",
        "signaling_overhead": "%.4f" % (sum(float(c["signaling_overhead"]) for c in done) / len(done)) if done else "",
        "mean_rtt_ms": "%.2f" % (sum(rtts) / len(rtts)) if rtts else "",
        "fast_peer_share": "%.4f" % fast_share,
        "chunk_timeouts": sum(int(c["chunk_timeouts"]) for c in survivors),
        "peer_timeouts_detected": sum(int(c["peer_timeouts_detected"]) for c in survivors),
        "server_peak_kbps": "%.2f" % peak,
        "server_chunks_sent": srv.get("chunks_sent", ""),
    }
    all_ok = res["clients_completed"] == res["clients_expected"] == res["clients_validated"]
    if scenario == "baseline":
        ok = all_ok and len(survivors) == N_CLIENTS and max(times) < 5000 and peak <= 50.0
    elif scenario.startswith("loss"):
        ok = all_ok and dups / (got + dups) <= 0.02
    elif scenario == "asym":
        ok = all_ok and fast_share > 0.75
    else:  # churn
        ok = all_ok and all(int(c["peer_timeouts_detected"]) >= 1 for c in survivors)
    res["acceptance"] = "PASS" if ok else "FAIL"
    return res, clients


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["sim", "netns"], default="sim")
    ap.add_argument("--scenarios", default="baseline,loss5,asym,churn")
    ap.add_argument("--reps", type=int, default=5, help="repetitions per scenario (spec: at least 5)")
    ap.add_argument("--seed-base", type=int, default=100, help="rep k uses seed seed-base + k")
    ap.add_argument("--out", default=os.path.join(HERE, "results"))
    ap.add_argument("--max-time", type=float, default=40.0)
    ap.add_argument("--port", type=int, default=9000)
    args = ap.parse_args()

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    root = os.path.join(args.out, "%s_%s_seed%d" % (stamp, args.mode, args.seed_base))
    os.makedirs(root)
    with open(os.path.join(root, "environment.txt"), "w") as f:
        f.write("date: %s\nos: %s\npython: %s\nmode: %s\ncommand: %s\n" %
                (stamp, platform.platform(), sys.version.replace("\n", " "), args.mode, " ".join(sys.argv)))

    topo = NetnsTopology() if args.mode == "netns" else None
    results, client_rows, n = [], [], 0
    try:
        for scenario in args.scenarios.split(","):
            for rep in range(1, args.reps + 1):
                seed = args.seed_base + rep
                run_dir = os.path.join(root, scenario, "rep%d_seed%d" % (rep, seed))
                n += 1
                res, clients = run_once(args, topo, scenario, rep, seed, run_dir, args.port + n)
                results.append(res)
                for c in clients:
                    client_rows.append(dict(c, scenario=scenario, rep=rep))
                print("%-9s rep %d seed %d: %s  completion=%s ms  p2p=%s  dup=%s  fast_share=%s  "
                      "server_peak=%s kbps" % (scenario, rep, seed, res["acceptance"],
                                               res["completion_time_ms"] or "-", res["p2p_transfer_ratio"],
                                               res["duplicate_ratio"], res["fast_peer_share"],
                                               res["server_peak_kbps"]), flush=True)
    finally:
        if topo:
            topo.teardown()
        for name, rows in (("results.csv", results), ("clients.csv", client_rows)):
            if rows:
                with open(os.path.join(root, name), "w", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                    w.writeheader()
                    w.writerows(rows)
    print("\nraw data: %s\nnext:     python3 analyze.py %s" % (root, root))


if __name__ == "__main__":
    main()
