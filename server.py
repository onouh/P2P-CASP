#!/usr/bin/env python3
"""
P2P-CASP server: bootstrap tracker + rate-limited initial seeder + state authority.

  * Tracker        : keeps the registry of active peers, answers REGISTER with PEER_LIST.
  * Seeder         : answers CHUNK_REQ, but every outbound byte goes through a hard
                     throttle (pacing + strict sliding 1-second cap <= 50 kbps).
  * State authority: validates MAP_COMPLETE (SHA-256 of the assembled map).

Usage:  python3 server.py --port 9000 --seed 42 --expect 4 --out logs/run1
"""
import argparse
import collections
import csv
import os
import sys
import time

from casp import mapgen
from casp import protocol as P
from casp.net import Endpoint

PEER_TIMEOUT = 4.0          # s without any packet -> peer removed from the registry
REQ_MAX_AGE = 0.40          # s; a queued CHUNK_REQ older than this is stale (client timed out)
SEED_HOLD = 2.0             # s; a chunk just seeded to peer A is not re-seeded to peer B
HOLDER_FRESH = 0.6          # s; ... as long as peer A has been heard from this recently
MANIFEST_MIN_GAP = 0.9      # s; ignore REGISTER retries while a manifest is on its way


class Throttle:
    """Hard outbound limit. Counts IP-level bytes (datagram + 28 bytes IPv4/UDP header)."""

    def __init__(self, pace_bps, cap_bps, overhead):
        self.pace = pace_bps / 8.0             # bytes per second used for pacing
        self.cap = cap_bps / 8.0               # bytes allowed in ANY 1-second window
        self.overhead = overhead
        self.next_free = 0.0
        self.window = collections.deque()      # (time, bytes) of the last second
        self.window_sum = 0
        self.total = 0
        self.max_window = 0

    def can_send(self, size, now):
        size += self.overhead
        while self.window and self.window[0][0] <= now - 1.0:
            self.window_sum -= self.window.popleft()[1]
        return now >= self.next_free and self.window_sum + size <= self.cap

    def account(self, size, now):
        size += self.overhead
        self.next_free = max(self.next_free, now - 0.01) + size / self.pace
        self.window.append((now, size))
        self.window_sum += size
        self.total += size
        self.max_window = max(self.max_window, self.window_sum)


class Server:
    def __init__(self, args):
        self.args = args
        os.makedirs(args.out, exist_ok=True)
        self.ep = Endpoint(args.bind, args.port, P.SERVER_ID,
                           log_path=os.path.join(args.out, "server_packets.csv"),
                           pcap_path=os.path.join(args.out, "server.pcap") if args.pcap else None,
                           sim_loss=args.sim_loss, sim_delay_ms=args.sim_delay,
                           sim_jitter_ms=args.sim_jitter, sim_seed=args.seed * 1000)
        self.map = mapgen.build_full_map(args.seed, args.cell_bytes)
        self.digest = self.map.digest()
        self.tags = [mapgen.tag(self.map.get(c)) for c in range(mapgen.N_CHUNKS)]
        self.manifest = P.enc_manifest(mapgen.N_CHUNKS, mapgen.chunk_size(args.cell_bytes), self.tags)
        self.manifest_id = P.manifest_digest(self.manifest)
        self.throttle = Throttle(args.pace_kbps * 1000.0, args.cap_kbps * 1000.0, P.IP_UDP_OVERHEAD)

        self.peers = {}             # peer_id -> {"addr", "last_seen", "complete", "manifest_at"}
        self.ever = set()
        self.list_version = 0
        self.ctrl_q = collections.deque()      # (msg_type, payload, addr, info) - sent first
        self.chunk_q = collections.deque()     # (arrival, peer_id, chunk_id)
        self.queued = set()                    # (peer_id, chunk_id) currently in chunk_q
        self.seeded = {}                       # chunk_id -> (peer_id, time sent)
        self.completions = {}                  # peer_id -> dict reported by the client
        self.stats = collections.Counter()
        self.ending_at = None
        self.start = time.monotonic()

    # ------------------------------------------------------------------
    def broadcast_peer_list(self):
        self.list_version += 1
        entries = [(pid, p["addr"][0], p["addr"][1]) for pid, p in sorted(self.peers.items())]
        payload = P.enc_peer_list(self.list_version, entries, self.manifest_id)
        for p in self.peers.values():
            self.ctrl_q.append((P.MSG_PEER_LIST, payload, p["addr"], "v=%d" % self.list_version))

    def send_peer_list(self, addr):
        entries = [(pid, p["addr"][0], p["addr"][1]) for pid, p in sorted(self.peers.items())]
        self.ctrl_q.append((P.MSG_PEER_LIST, P.enc_peer_list(self.list_version, entries, self.manifest_id), addr,
                            "v=%d" % self.list_version))

    def handle(self, msg_type, seq, pid, payload, addr, now):
        if pid in self.peers:
            self.peers[pid]["last_seen"] = now
            self.peers[pid]["addr"] = addr

        if msg_type == P.MSG_REGISTER:
            if pid not in self.peers:
                self.peers[pid] = {"addr": addr, "last_seen": now, "complete": False, "manifest_at": -9.0}
                self.ever.add(pid)
                print("[server] peer %d registered from %s:%d" % (pid, addr[0], addr[1]), flush=True)
                self.broadcast_peer_list()
            else:
                self.send_peer_list(addr)
            peer = self.peers[pid]
            want_manifest = payload[:1] == b"\x01"
            if want_manifest and now - peer["manifest_at"] > MANIFEST_MIN_GAP:   # retry suppression
                peer["manifest_at"] = now
                self.ctrl_q.append((P.MSG_MANIFEST, self.manifest, addr, ""))

        elif msg_type == P.MSG_PEER_HEARTBEAT:
            ts_us, _have = P.dec_heartbeat(payload)
            self.ctrl_q.appendleft((P.MSG_HEARTBEAT_ACK,
                                    P.enc_hb_ack(ts_us, mapgen.N_CHUNKS, self.list_version), addr, ""))

        elif msg_type == P.MSG_CHUNK_REQ:
            chunk = P.dec_chunk_req(payload)
            if pid in self.peers and chunk < mapgen.N_CHUNKS and (pid, chunk) not in self.queued:
                self.queued.add((pid, chunk))
                self.chunk_q.append((now, pid, chunk))

        elif msg_type == P.MSG_MAP_COMPLETE:
            digest, completion_ms, dups, p2p = P.dec_complete(payload)
            ok = digest == self.digest
            if pid in self.peers:
                self.peers[pid]["complete"] = ok
            if pid not in self.completions:
                self.completions[pid] = {"valid": ok, "completion_ms": completion_ms,
                                         "dups": dups, "p2p_chunks": p2p,
                                         "server_time_s": now - self.start}
                print("[server] MAP_COMPLETE from peer %d: %s (%d ms)" %
                      (pid, "VALID" if ok else "INVALID", completion_ms), flush=True)
            self.ctrl_q.appendleft((P.MSG_COMPLETE_ACK, bytes([1 if ok else 0]), addr, ""))

    # ------------------------------------------------------------------
    def drain(self, now):
        """Send as much as the throttle allows: control messages first, then chunk data."""
        while True:
            if self.ctrl_q:
                msg_type, payload, addr, info = self.ctrl_q[0]
                if not self.throttle.can_send(P.HEADER_LEN + len(payload), now):
                    return
                self.ctrl_q.popleft()
                n = self.ep.send(msg_type, payload, addr, info)
                self.throttle.account(n, now)
                continue
            if not self.chunk_q:
                return
            arrival, pid, chunk = self.chunk_q[0]
            if now - arrival > REQ_MAX_AGE or pid not in self.peers:
                self.chunk_q.popleft()
                self.queued.discard((pid, chunk))
                self.stats["stale_requests_dropped"] += 1
                continue
            holder = self.seeded.get(chunk)
            if (holder and holder[0] != pid and holder[0] in self.peers and now - holder[1] < SEED_HOLD
                    and now - self.peers[holder[0]]["last_seen"] < HOLDER_FRESH):
                # Already handed to another live peer a moment ago: the requester should
                # pull it from that peer instead of spending server bandwidth twice.
                self.chunk_q.popleft()
                self.queued.discard((pid, chunk))
                self.stats["requests_deferred_to_p2p"] += 1
                continue
            data = self.map.get(chunk)
            if not self.throttle.can_send(P.HEADER_LEN + 2 + len(data), now):
                return
            self.chunk_q.popleft()
            self.queued.discard((pid, chunk))
            n = self.ep.send(P.MSG_CHUNK_DATA, P.enc_chunk_data(chunk, data),
                             self.peers[pid]["addr"], "chunk=%d" % chunk)
            self.throttle.account(n, now)
            self.seeded[chunk] = (pid, now)
            self.stats["chunks_sent"] += 1

    def housekeeping(self, now):
        dead = [pid for pid, p in self.peers.items() if now - p["last_seen"] > PEER_TIMEOUT]
        for pid in dead:
            print("[server] peer %d timed out, removed from registry" % pid, flush=True)
            del self.peers[pid]
        if dead:
            self.broadcast_peer_list()
        if (self.ending_at is None and len(self.ever) >= self.args.expect and self.peers
                and all(p["complete"] for p in self.peers.values())):
            print("[server] all live peers validated, ending session", flush=True)
            for _ in range(3):
                for p in self.peers.values():
                    self.ctrl_q.append((P.MSG_SESSION_END, b"", p["addr"], ""))
            self.ending_at = now + 1.0

    def run(self):
        print("[server] P2P-CASP v%d tracker/seeder on port %d, seed=%d, throttle=%.1f kbps" %
              (P.VERSION, self.ep.addr[1], self.args.seed, self.args.cap_kbps), flush=True)
        last_house = 0.0
        while True:
            self.ep.wait(0.003)
            now = time.monotonic()
            for msg_type, seq, pid, payload, addr in self.ep.recv_all():
                try:
                    self.handle(msg_type, seq, pid, payload, addr, now)
                except Exception as exc:           # malformed payload: log and keep serving
                    self.stats["bad_payloads"] += 1
                    print("[server] bad payload from %s: %s" % (addr, exc), flush=True)
            self.drain(now)
            self.ep.pump()
            if now - last_house > 0.1:
                last_house = now
                self.housekeeping(now)
            if self.ending_at and now > self.ending_at and not self.ctrl_q:
                break
            if now - self.start > self.args.max_time:
                print("[server] max run time reached", flush=True)
                break
        self.finish()

    def finish(self):
        path = os.path.join(self.args.out, "metrics_server.csv")
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["seed", "peers_registered", "valid_completions", "chunks_sent",
                        "valid_peers", "requests_deferred_to_p2p", "stale_requests_dropped",
                        "total_out_bytes_ip", "max_1s_window_kbps", "run_time_s"])
            w.writerow([self.args.seed, len(self.ever),
                        sum(1 for c in self.completions.values() if c["valid"]),
                        self.stats["chunks_sent"],
                        ";".join(str(p) for p, c in sorted(self.completions.items()) if c["valid"]),
                        self.stats["requests_deferred_to_p2p"],
                        self.stats["stale_requests_dropped"], self.throttle.total,
                        "%.2f" % (self.throttle.max_window * 8 / 1000.0),
                        "%.3f" % (time.monotonic() - self.start)])
        self.ep.close()


def main():
    ap = argparse.ArgumentParser(description="P2P-CASP tracker / rate-limited seeder")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--seed", type=int, default=42, help="map generator seed (deterministic)")
    ap.add_argument("--cell-bytes", type=int, default=1)
    ap.add_argument("--expect", type=int, default=4, help="clients expected before the session can end")
    ap.add_argument("--cap-kbps", type=float, default=49.5, help="strict limit for any 1 s window")
    ap.add_argument("--pace-kbps", type=float, default=48.5, help="steady pacing rate")
    ap.add_argument("--out", default="logs/server")
    ap.add_argument("--pcap", action="store_true", help="also write a pcap from inside the program")
    ap.add_argument("--max-time", type=float, default=60.0)
    ap.add_argument("--sim-loss", type=float, default=0.0, help="built-in egress loss probability (0..1)")
    ap.add_argument("--sim-delay", type=float, default=0.0, help="built-in egress delay, ms")
    ap.add_argument("--sim-jitter", type=float, default=0.0, help="built-in egress jitter, ms")
    args = ap.parse_args()
    if args.cap_kbps > 50:
        sys.exit("the spec caps the server at 50 kbps")
    Server(args).run()


if __name__ == "__main__":
    main()
