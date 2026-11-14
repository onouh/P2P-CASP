#!/usr/bin/env python3
"""
Turns the raw CSVs of one experiment batch into the tables and plots for the report.

    python3 analyze.py results/<batch directory>

Writes into <batch>/analysis/:
    summary.csv                  min / median / max of every metric per scenario
    acceptance.csv               pass count per scenario against the spec's criteria
    completion_by_scenario.png   median completion time with min-max range
    completion_vs_loss.png       completion time vs loss rate (needs >= 2 loss levels)
    p2p_sources_asym.png         who served the P2P transfers under asymmetric delay
    server_rate_baseline.png     server outbound rate over time vs the 50 kbps limit
"""
import collections
import csv
import os
import statistics
import sys

METRICS = ["completion_time_ms", "p2p_transfer_ratio", "duplicate_chunk_count", "duplicate_ratio",
           "signaling_overhead", "mean_rtt_ms", "fast_peer_share", "chunk_timeouts", "server_peak_kbps"]
BLUE, INK, MUTED, GRID, SURFACE, LIMIT = "#2a78d6", "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb", "#e34948"


def load(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def style(ax, xlabel, ylabel, title):
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=MUTED, length=0)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_xlabel(xlabel, color=MUTED)
    ax.set_ylabel(ylabel, color=MUTED)
    ax.set_title(title, color=INK, loc="left", fontsize=11, fontweight="bold")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = sys.argv[1]
    out = os.path.join(root, "analysis")
    os.makedirs(out, exist_ok=True)
    runs = load(os.path.join(root, "results.csv"))
    clients = load(os.path.join(root, "clients.csv"))
    by = collections.OrderedDict()
    for r in runs:
        by.setdefault(r["scenario"], []).append(r)

    # ---- summary table: min / median / max -------------------------------
    with open(os.path.join(out, "summary.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "metric", "runs", "min", "median", "max"])
        for sc, rows in by.items():
            for m in METRICS:
                vals = [float(r[m]) for r in rows if r[m] not in ("", "nan")]
                if vals:
                    w.writerow([sc, m, len(vals), "%.4g" % min(vals),
                                "%.4g" % statistics.median(vals), "%.4g" % max(vals)])
    with open(os.path.join(out, "acceptance.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "runs", "passed"])
        for sc, rows in by.items():
            w.writerow([sc, len(rows), sum(r["acceptance"] == "PASS" for r in rows)])

    print("%-10s %-22s %10s %10s %10s" % ("scenario", "metric", "min", "median", "max"))
    for row in load(os.path.join(out, "summary.csv")):
        print("%-10s %-22s %10s %10s %10s" % (row["scenario"], row["metric"], row["min"], row["median"], row["max"]))
    print()
    for row in load(os.path.join(out, "acceptance.csv")):
        print("acceptance %-10s %s/%s runs passed" % (row["scenario"], row["passed"], row["runs"]))

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\nmatplotlib not installed: tables written, plots skipped (pip install matplotlib)")
        return

    def times(rows):
        return [float(r["completion_time_ms"]) / 1000 for r in rows if r["completion_time_ms"]]

    # ---- 1. completion time per scenario ---------------------------------
    fig, ax = plt.subplots(figsize=(7, 4), facecolor=SURFACE)
    names = [s for s in by if times(by[s])]
    for i, sc in enumerate(names):
        t = times(by[sc])
        ax.plot([i, i], [min(t), max(t)], color=BLUE, linewidth=2, solid_capstyle="round")
        ax.plot(i, statistics.median(t), "o", color=BLUE, markersize=8, markeredgecolor=SURFACE, markeredgewidth=2)
        ax.annotate("%.2f s" % statistics.median(t), (i, statistics.median(t)), xytext=(10, -3),
                    textcoords="offset points", color=INK, fontsize=9)
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels(names)
    ax.set_xlim(-0.5, len(names) - 0.3)
    ax.set_ylim(0, None)
    style(ax, "scenario", "seconds until every surviving client is complete",
          "Completion time per scenario (dot = median, line = min to max)")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "completion_by_scenario.png"), dpi=150)
    plt.close(fig)

    # ---- 2. completion time vs loss rate ---------------------------------
    pts = []
    for sc, rows in by.items():
        if (sc == "baseline" or sc.startswith("loss")) and times(rows):
            pts.append((0.0 if sc == "baseline" else float(sc[4:]), times(rows)))
    pts.sort()
    if len(pts) >= 2:
        fig, ax = plt.subplots(figsize=(7, 4), facecolor=SURFACE)
        xs = [p[0] for p in pts]
        ax.fill_between(xs, [min(p[1]) for p in pts], [max(p[1]) for p in pts], color=BLUE, alpha=0.15, linewidth=0)
        ax.plot(xs, [statistics.median(p[1]) for p in pts], "-o", color=BLUE, linewidth=2, markersize=8,
                markeredgecolor=SURFACE, markeredgewidth=2)
        for x, t in pts:
            ax.annotate("%.2f s" % statistics.median(t), (x, statistics.median(t)), xytext=(0, 10),
                        textcoords="offset points", ha="center", color=INK, fontsize=9)
        ax.set_xticks(xs)
        ax.set_xticklabels(["%g%%" % x for x in xs])
        ax.set_ylim(0, None)
        style(ax, "packet loss applied on every node", "seconds",
              "Completion time vs loss rate (line = median, band = min to max)")
        fig.tight_layout()
        fig.savefig(os.path.join(out, "completion_vs_loss.png"), dpi=150)
        plt.close(fig)

    # ---- 3. who served the P2P transfers under asymmetric delay ----------
    asym = [c for c in clients if c["scenario"] == "asym"]
    if asym:
        per_run = collections.defaultdict(collections.Counter)
        for c in asym:
            for item in c["chunks_from_each_peer"].split(";"):
                if item:
                    src, n = item.split(":")
                    per_run[c["rep"]][int(src)] += int(n)
        ids = sorted({i for run in per_run.values() for i in run})
        shares = {i: [100.0 * run[i] / sum(run.values()) for run in per_run.values()] for i in ids}
        fig, ax = plt.subplots(figsize=(7, 4), facecolor=SURFACE)
        for k, i in enumerate(ids):
            med = statistics.median(shares[i])
            ax.bar(k, med, width=0.5, color=BLUE)
            ax.annotate("%.0f%%" % med, (k, med), xytext=(0, 4), textcoords="offset points",
                        ha="center", color=INK, fontsize=9)
        ax.set_xticks(range(len(ids)))
        ax.set_xticklabels(["client %d\n(%s)" % (i, "100 ms delay" if i in (1, 2) else "unimpaired") for i in ids])
        style(ax, "", "share of all P2P chunk transfers served (median)",
              "Asymmetric delay: which client served the P2P transfers")
        fig.tight_layout()
        fig.savefig(os.path.join(out, "p2p_sources_asym.png"), dpi=150)
        plt.close(fig)

    # ---- 4. server outbound rate over time (first baseline run) ----------
    first = sorted(d for d in os.listdir(os.path.join(root, "baseline"))) if "baseline" in by else []
    log = os.path.join(root, "baseline", first[0], "server_packets.csv") if first else ""
    if os.path.exists(log):
        tx = [(float(r["t_ms"]) / 1000, int(r["datagram_len"]) + 28) for r in load(log) if r["dir"].startswith("TX")]
        ts, rate, window, total = [], [], collections.deque(), 0
        for t, size in tx:
            window.append((t, size))
            total += size
            while window[0][0] <= t - 1.0:
                total -= window.popleft()[1]
            ts.append(t)
            rate.append(total * 8 / 1000)
        fig, ax = plt.subplots(figsize=(7, 4), facecolor=SURFACE)
        ax.plot(ts, rate, color=BLUE, linewidth=2)
        ax.axhline(50, color=LIMIT, linewidth=1.2, linestyle="--")
        ax.annotate("50 kbps limit", (ts[-1], 50), xytext=(0, 5), textcoords="offset points",
                    ha="right", color=INK, fontsize=9)
        ax.set_ylim(0, 60)
        style(ax, "seconds since server start", "kbps sent in the previous 1 s (IP level)",
              "Server outbound rate, baseline run 1")
        fig.tight_layout()
        fig.savefig(os.path.join(out, "server_rate_baseline.png"), dpi=150)
        plt.close(fig)
    print("\ntables and plots written to", out)


if __name__ == "__main__":
    main()
