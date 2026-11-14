#!/usr/bin/env python3
"""
P2P-CASP client (peer).

Every client is both a downloader and a seeder:
  * registers with the tracker, receives the peer list and the chunk manifest
  * measures RTT / loss to every peer with PEER_HEARTBEAT
  * advertises what it holds with CHUNK_BITMAP (delta on change, full periodically)
  * pulls missing chunks with CHUNK_REQ from the best-scoring peer that has them,
    falling back to the throttled server only for chunks nobody else holds
  * verifies each CHUNK_DATA against the manifest tag, assembles out of order,
    discards duplicates, and finally sends MAP_COMPLETE to the server

Usage:  python3 client.py --id 1 --server 127.0.0.1:9000 --out logs/run1
"""
import argparse
import collections
import csv
import os
import random
import time

from casp import mapgen
from casp import protocol as P
from casp.net import Endpoint

HB_INTERVAL = 0.20          # s between heartbeats to each peer
HB_SERVER_INTERVAL = 1.0    # s between heartbeats to the server (keeps its bandwidth for data)
HB_LOSS_AFTER = 0.5         # s; an unanswered heartbeat counts as lost
PEER_DEAD_AFTER = 1.0       # s of silence -> peer considered gone
SERVER_DEAD_AFTER = 6.0
BITMAP_FULL_INTERVAL = 0.5  # s; periodic full bitfield (repairs lost deltas)
BITMAP_DELTA_DELAY = 0.02   # s; batch window for delta advertisements
CHUNK_TTL = 0.5             # s; spec: max wait for a chunk before asking a new peer
RTO_MIN = 0.15
SERVER_WINDOW = 2           # outstanding CHUNK_REQ to the server
PEER_WINDOW = 8             # outstanding CHUNK_REQ to a good peer
SLOW_PEER_WINDOW = 1        # ... to a peer scoring much worse than the best one
SLOW_FACTOR = 1.5
SLOW_HOLDOFF_MAX = 0.6      # s; longest a client defers pulling from a slow-only holder
LOSS_WEIGHT = 10.0          # score = srtt * (1 + LOSS_WEIGHT * loss)
DEFAULT_RTT = 0.05          # s, assumed until the first sample
REGISTER_RETRY = 0.3
MANIFEST_PEER_WAIT = 0.15   # s to wait for a peer to answer MANIFEST_REQ
MANIFEST_PEER_TRIES = 3     # then fall back to the (throttled) server
MANIFEST_SERVER_WAIT = 1.0
COMPLETE_RETRY = 0.3


class Peer:
    def __init__(self, pid, addr, now):
        self.pid = pid
        self.addr = addr
        self.have = set()
        self.alive = True
        self.last_seen = now
        self.srtt = None
        self.rttvar = 0.0
        self.loss = 0.0
        self.rtt_sum = 0.0
        self.rtt_n = 0
        self.hb_sent = {}           # ts_us -> monotonic send time
        self.next_hb = now
        self.inflight = 0
        self.next_full_bitmap = now
        self.delta = []             # chunk ids not yet advertised to this peer
        self.delta_due = None
        self.given = 0              # chunks we accepted from this peer
        self.timeouts = 0

    def rtt_sample(self, rtt):
        self.rtt_sum += rtt
        self.rtt_n += 1
        if self.srtt is None:
            self.srtt, self.rttvar = rtt, rtt / 2
        else:                                       # RFC 6298 style estimator
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - rtt)
            self.srtt = 0.875 * self.srtt + 0.125 * rtt

    def loss_sample(self, lost):
        self.loss = 0.9 * self.loss + (0.1 if lost else 0.0)

    def score(self):
        """Lower is better: smoothed RTT inflated by the observed loss rate."""
        rtt = self.srtt if self.srtt is not None else DEFAULT_RTT
        return rtt * (1.0 + LOSS_WEIGHT * self.loss)

    def rto(self):
        if self.srtt is None:
            return CHUNK_TTL
        return min(CHUNK_TTL, max(RTO_MIN, 2 * self.srtt + 4 * self.rttvar))


class Client:
    def __init__(self, args):
        self.args = args
        os.makedirs(args.out, exist_ok=True)
        host, port = args.server.rsplit(":", 1)
        self.server_addr = (host, int(port))
        self.ep = Endpoint(args.bind, args.port, args.id,
                           log_path=os.path.join(args.out, "client%d_packets.csv" % args.id),
                           pcap_path=os.path.join(args.out, "client%d.pcap" % args.id) if args.pcap else None,
                           sim_loss=args.sim_loss, sim_delay_ms=args.sim_delay,
                           sim_jitter_ms=args.sim_jitter, sim_seed=args.seed * 1000 + args.id)
        self.rng = random.Random(args.seed * 7919 + args.id)
        self.start = time.monotonic()
        now = self.start
        self.server = Peer(P.SERVER_ID, self.server_addr, now)
        self.peers = {}                 # peer_id -> Peer (other clients only)
        self.list_version = -1
        self.tags = None                # manifest
        self.manifest_raw = None
        self.manifest_id = None
        self.manifest_tries = 0
        self.next_manifest = now
        self.slow_since = {}            # chunk_id -> when we first saw it held only by slow peers
        self.at_completion = None       # byte counters frozen when the map completed
        self.store = None
        self.order = []                 # this client's shuffled chunk order
        self.pending = {}               # chunk_id -> (Peer, send_time, deadline)
        self.failures = collections.Counter()
        self.last_failed = {}           # chunk_id -> peer_id that timed out last
        self.next_register = now
        self.list_stale = False
        self.completed_at = None
        self.complete_acked = False
        self.next_complete = 0.0
        self.session_over = False
        self.stats = collections.Counter()
        self.served_to = collections.Counter()
        self.died = False

    # ------------------------------------------------------------ helpers
    def log(self, text):
        print("[client %d] %s" % (self.args.id, text), flush=True)

    def have_count(self):
        return len(self.store.have) if self.store else 0

    def peer_for(self, pid, addr, now):
        if pid == P.SERVER_ID:
            return self.server
        peer = self.peers.get(pid)
        if peer is None:                           # learned from traffic, not only from the tracker
            peer = self.peers[pid] = Peer(pid, addr, now)
            self.log("discovered peer %d at %s:%d" % (pid, addr[0], addr[1]))
        return peer

    # ----------------------------------------------------------- receive
    def handle(self, msg_type, seq, pid, payload, addr, now):
        if pid == self.args.id:
            return
        peer = self.peer_for(pid, addr, now)
        peer.last_seen = now
        if not peer.alive:
            peer.alive = True
            peer.next_full_bitmap = now
            self.log("peer %d is back" % pid)

        if msg_type == P.MSG_PEER_LIST:
            version, entries, self.manifest_id = P.dec_peer_list(payload)
            self.list_version = version
            for epid, ip, port in entries:
                if epid != self.args.id and epid not in self.peers:
                    self.peers[epid] = Peer(epid, (ip, port), now)
                    self.log("tracker gave peer %d at %s:%d" % (epid, ip, port))

        elif msg_type == P.MSG_MANIFEST:
            if self.tags is None and self.manifest_id and P.manifest_digest(payload) == self.manifest_id:
                n, size, tags = P.dec_manifest(payload)
                self.tags = tags
                self.manifest_raw = payload
                self.stats["manifest_from_peer"] = int(pid != P.SERVER_ID)
                self.store = mapgen.MapStore(self.args.cell_bytes)
                self.order = list(range(n))
                self.rng.shuffle(self.order)
                self.log("manifest received: %d chunks of %d bytes" % (n, size))

        elif msg_type == P.MSG_PEER_HEARTBEAT:
            ts_us, _have = P.dec_heartbeat(payload)
            self.ep.send(P.MSG_HEARTBEAT_ACK, P.enc_hb_ack(ts_us, self.have_count()), addr)

        elif msg_type == P.MSG_HEARTBEAT_ACK:
            ts_us, _have, version = P.dec_hb_ack(payload)
            sent = peer.hb_sent.pop(ts_us, None)
            if sent is not None:
                peer.rtt_sample(now - sent)
                peer.loss_sample(False)
            if pid == P.SERVER_ID and version != self.list_version:
                self.list_stale = True                 # tracker has a newer peer list: refresh

        elif msg_type == P.MSG_CHUNK_BITMAP:
            if self.tags is None:
                return
            mode, ids = P.dec_bitmap(payload, len(self.tags))
            if mode == P.BITMAP_FULL:
                peer.have = ids
            else:
                peer.have |= ids
            # A chunk we are still waiting for from the throttled server just became
            # available from a peer: stop waiting and pull it peer-to-peer.
            for chunk in ids:
                p = self.pending.get(chunk)
                if p and p[0] is self.server:
                    self.cancel(chunk)
                    self.stats["rerouted_from_server"] += 1

        elif msg_type == P.MSG_CHUNK_REQ:
            chunk = P.dec_chunk_req(payload)
            if self.store and chunk in self.store.have:
                self.ep.send(P.MSG_CHUNK_DATA, P.enc_chunk_data(chunk, self.store.get(chunk)),
                             addr, "chunk=%d" % chunk)
                self.served_to[pid] += 1

        elif msg_type == P.MSG_CHUNK_DATA:
            self.on_chunk(peer, payload, now)

        elif msg_type == P.MSG_COMPLETE_ACK:
            if not self.complete_acked:
                self.complete_acked = True
                self.log("server validated our map: %s" % ("OK" if payload[:1] == b"\x01" else "REJECTED"))
                self.stats["validated"] = 1 if payload[:1] == b"\x01" else 0

        elif msg_type == P.MSG_MANIFEST_REQ:
            if self.manifest_raw:
                self.ep.send(P.MSG_MANIFEST, self.manifest_raw, addr)

        elif msg_type == P.MSG_SESSION_END:
            self.session_over = True
            if self.completed_at:          # the tracker only ends once every live peer validated
                self.complete_acked = True
                self.stats["validated"] = 1

    def on_chunk(self, peer, payload, now):
        if self.tags is None:
            return
        chunk, data = P.dec_chunk_data(payload)
        if chunk >= len(self.tags):
            return
        if mapgen.tag(data) != self.tags[chunk]:
            self.stats["corrupt_chunks"] += 1            # content address mismatch: drop
            return
        p = self.pending.get(chunk)
        if p and p[0] is peer:
            peer.rtt_sample(now - p[1])
            peer.loss_sample(False)
            self.cancel(chunk)
        if chunk in self.store.have:
            self.stats["duplicate_chunk_count"] += 1     # duplicate suppression
            return
        if p and p[0] is not peer:
            self.cancel(chunk)                           # late answer from an earlier attempt
        self.store.put(chunk, data)                      # out-of-order assembly by chunk id
        self.stats["chunks_received"] += 1
        if peer is self.server:
            self.stats["from_server"] += 1
        else:
            self.stats["from_peers"] += 1
            peer.given += 1
        for other in self.peers.values():
            other.delta.append(chunk)
        if self.store.complete() and self.completed_at is None:
            self.completed_at = now
            self.at_completion = (dict(self.ep.bytes_out), dict(self.ep.bytes_in))
            self.log("map complete in %.0f ms (server %d, peers %d, duplicates %d)" %
                     ((now - self.start) * 1000, self.stats["from_server"],
                      self.stats["from_peers"], self.stats["duplicate_chunk_count"]))
        if (self.args.die_at > 0 and not self.died
                and len(self.store.have) >= self.args.die_at * len(self.tags)):
            self.died = True

    def cancel(self, chunk):
        p = self.pending.pop(chunk, None)
        if p:
            p[0].inflight -= 1

    # ------------------------------------------------------------ timers
    def timers(self, now):
        # registration / peer-list refresh
        if now >= self.next_register and (self.list_version < 0 or self.list_stale):
            self.ep.send(P.MSG_REGISTER, b"\x00", self.server_addr)
            self.next_register = now + REGISTER_RETRY
            self.list_stale = False
        # manifest bootstrap: try peers first (free), the throttled server as a fallback
        if self.tags is None and self.list_version >= 0 and now >= self.next_manifest:
            alive = sorted((p for p in self.peers.values() if p.alive), key=lambda p: p.pid)
            if alive and self.manifest_tries < MANIFEST_PEER_TRIES:
                target = alive[self.manifest_tries % len(alive)]
                self.ep.send(P.MSG_MANIFEST_REQ, b"", target.addr)
                self.next_manifest = now + MANIFEST_PEER_WAIT
            else:
                self.ep.send(P.MSG_REGISTER, b"\x01", self.server_addr)     # 0x01 = "send me the manifest"
                self.next_manifest = now + MANIFEST_SERVER_WAIT
            self.manifest_tries += 1
        # heartbeats + liveness
        for peer in [self.server] + list(self.peers.values()):
            interval = HB_SERVER_INTERVAL if peer is self.server else HB_INTERVAL
            dead_after = SERVER_DEAD_AFTER if peer is self.server else PEER_DEAD_AFTER
            if peer.alive and now - peer.last_seen > dead_after:
                peer.alive = False
                peer.have = set()
                self.stats["peer_timeouts_detected"] += 1
                self.log("peer %d timed out -> removed from routing" % peer.pid)
                for chunk in [c for c, p in self.pending.items() if p[0] is peer]:
                    self.cancel(chunk)
            if now >= peer.next_hb:
                ts = self.ep.ts_us()
                peer.hb_sent[ts] = now
                self.ep.send(P.MSG_PEER_HEARTBEAT, P.enc_heartbeat(ts, self.have_count()), peer.addr)
                peer.next_hb = now + interval
            for ts in [t for t, sent in peer.hb_sent.items() if now - sent > HB_LOSS_AFTER]:
                del peer.hb_sent[ts]
                peer.loss_sample(True)
        # bitmap advertisements
        if self.store:
            for peer in self.peers.values():
                if not peer.alive:
                    continue
                if now >= peer.next_full_bitmap:
                    self.ep.send(P.MSG_CHUNK_BITMAP,
                                 P.enc_bitmap_full(self.store.have, len(self.tags)), peer.addr, "full")
                    peer.next_full_bitmap = now + BITMAP_FULL_INTERVAL
                    peer.delta = []
                    peer.delta_due = None
                elif peer.delta:
                    if peer.delta_due is None:
                        peer.delta_due = now + BITMAP_DELTA_DELAY
                    elif now >= peer.delta_due:
                        self.ep.send(P.MSG_CHUNK_BITMAP, P.enc_bitmap_delta(peer.delta), peer.addr,
                                     "delta=%d" % len(peer.delta))
                        peer.delta = []
                        peer.delta_due = None
        # chunk request timeouts -> re-route
        for chunk, (peer, sent, deadline) in list(self.pending.items()):
            if now >= deadline:
                self.cancel(chunk)
                peer.loss_sample(True)
                peer.timeouts += 1
                self.failures[chunk] += 1
                self.last_failed[chunk] = peer.pid
                self.stats["chunk_timeouts"] += 1
        # completion declaration
        if self.completed_at and not self.complete_acked and now >= self.next_complete:
            self.ep.send(P.MSG_MAP_COMPLETE,
                         P.enc_complete(self.store.digest(), int((self.completed_at - self.start) * 1000),
                                        self.stats["duplicate_chunk_count"], self.stats["from_peers"]),
                         self.server_addr)
            self.next_complete = now + COMPLETE_RETRY

    # --------------------------------------------------------- scheduling
    def schedule(self, now):
        """Dynamic peer selection: route each missing chunk to the best-scoring holder."""
        if self.store is None or self.store.complete():
            return
        alive = [p for p in self.peers.values() if p.alive]
        best = min((p.score() for p in alive), default=None)
        ids = sorted([self.args.id] + [p.pid for p in alive])
        rank, n = ids.index(self.args.id), len(ids)
        peer_jobs, server_jobs = [], []
        for pos, chunk in enumerate(self.order):
            if chunk in self.store.have or chunk in self.pending:
                continue
            holders = [p for p in alive if chunk in p.have]
            if len(holders) > 1:                         # "request from a new peer" after a timeout
                holders = [p for p in holders if p.pid != self.last_failed.get(chunk)] or holders
            if holders and self.failures[chunk] < 4:
                p = min(holders, key=lambda q: q.score())
                if p.score() > SLOW_FACTOR * best + 0.005:
                    # Only slow peers hold it. Clients take turns (staggered by chunk id and
                    # rank) so one of them fetches it over the slow path and the rest can
                    # then pull it from that faster copy instead of all hitting the slow peer.
                    since = self.slow_since.setdefault(chunk, now)
                    turn = (chunk + rank) % n
                    if now - since < min(SLOW_HOLDOFF_MAX, 2.0 * p.score() * turn):
                        continue
                peer_jobs.append((p.score(), pos, chunk, holders))
            else:
                # Nobody has it yet: ask the server. Chunks of "our" stripe first, so the
                # clients do not all spend the server's 50 kbps on the same chunks.
                server_jobs.append((0 if chunk % n == rank else 1, pos, chunk))
        peer_jobs.sort()
        for _score, _pos, chunk, holders in peer_jobs:
            for p in sorted(holders, key=lambda q: q.score()):
                cap = PEER_WINDOW if p.score() <= SLOW_FACTOR * best + 0.005 else SLOW_PEER_WINDOW
                if p.inflight < cap:
                    self.request(chunk, p, now, p.rto())
                    break
        if self.server.alive:
            server_jobs.sort()
            for _stripe, _pos, chunk in server_jobs:
                if self.server.inflight >= SERVER_WINDOW:
                    break
                self.request(chunk, self.server, now, CHUNK_TTL)

    def request(self, chunk, peer, now, timeout):
        self.ep.send(P.MSG_CHUNK_REQ, P.enc_chunk_req(chunk), peer.addr, "chunk=%d" % chunk)
        self.pending[chunk] = (peer, now, now + timeout)
        peer.inflight += 1
        self.stats["requests_sent"] += 1

    # --------------------------------------------------------------- main
    def run(self):
        self.log("P2P-CASP v%d peer on port %d, tracker %s:%d" %
                 (P.VERSION, self.ep.addr[1], self.server_addr[0], self.server_addr[1]))
        done_since = None
        while True:
            self.ep.wait(0.004)
            now = time.monotonic()
            for msg_type, seq, pid, payload, addr in self.ep.recv_all():
                try:
                    self.handle(msg_type, seq, pid, payload, addr, now)
                except Exception as exc:
                    self.stats["bad_payloads"] += 1
                    self.log("bad payload from %s: %s" % (addr, exc))
            if self.died:
                self.log("HARD KILL at %d%% (peer churn test)" % int(self.args.die_at * 100))
                self.finish()
                os._exit(0)                         # no goodbye on the wire: peers must detect it
            self.timers(now)
            self.schedule(now)
            self.ep.pump()
            if self.session_over:
                break
            if self.completed_at and not self.server.alive:
                break                               # server gone after we finished
            if now - self.start > self.args.max_time:
                self.log("max run time reached (have %d chunks)" % self.have_count())
                break
        self.finish()

    def finish(self):
        s = self.stats
        # byte counters as they were when the map completed (so idle seeding time is not counted)
        b_out, b_in = self.at_completion or (self.ep.bytes_out, self.ep.bytes_in)
        sig = sum(b_out.get(t, 0) + b_in.get(t, 0) for t in P.SIGNALING_TYPES)
        data = b_out.get(P.MSG_CHUNK_DATA, 0) + b_in.get(P.MSG_CHUNK_DATA, 0)
        received = s["from_server"] + s["from_peers"]
        everyone = [self.server] + list(self.peers.values())
        rtts = ";".join("%d:%.2f" % (p.pid, 1000 * p.rtt_sum / p.rtt_n) for p in everyone if p.rtt_n)
        got = ";".join("%d:%d" % (p.pid, p.given) for p in self.peers.values())
        served = ";".join("%d:%d" % (k, v) for k, v in sorted(self.served_to.items()))
        path = os.path.join(self.args.out, "metrics_client%d.csv" % self.args.id)
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["peer_id", "seed", "completed", "validated", "completion_time_ms",
                        "p2p_transfer_ratio", "duplicate_chunk_count", "duplicate_ratio",
                        "signaling_bytes", "chunk_data_bytes", "signaling_overhead",
                        "mean_rtt_per_peer_ms", "chunks_from_server", "chunks_from_peers",
                        "chunks_from_each_peer", "chunks_served_to_each_peer", "chunk_timeouts",
                        "rerouted_from_server", "peer_timeouts_detected", "corrupt_chunks", "killed"])
            w.writerow([self.args.id, self.args.seed, int(self.completed_at is not None),
                        s["validated"],
                        "%.1f" % ((self.completed_at - self.start) * 1000) if self.completed_at else "",
                        "%.4f" % (s["from_peers"] / received) if received else "",
                        s["duplicate_chunk_count"],
                        "%.4f" % (s["duplicate_chunk_count"] / (received + s["duplicate_chunk_count"]))
                        if received else "",
                        sig, data, "%.4f" % (sig / data) if data else "",
                        rtts, s["from_server"], s["from_peers"], got, served, s["chunk_timeouts"],
                        s["rerouted_from_server"], s["peer_timeouts_detected"], s["corrupt_chunks"],
                        int(self.died)])
        self.ep.close()


def main():
    ap = argparse.ArgumentParser(description="P2P-CASP peer")
    ap.add_argument("--id", type=int, required=True, help="unique peer id (1, 2, 3, ...)")
    ap.add_argument("--server", default="127.0.0.1:9000", help="tracker ip:port")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=0, help="local UDP port (0 = any free port)")
    ap.add_argument("--seed", type=int, default=42, help="seed for this client's random choices")
    ap.add_argument("--cell-bytes", type=int, default=1)
    ap.add_argument("--out", default="logs/client")
    ap.add_argument("--pcap", action="store_true", help="also write a pcap from inside the program")
    ap.add_argument("--max-time", type=float, default=60.0)
    ap.add_argument("--die-at", type=float, default=0.0,
                    help="hard-kill this client when this fraction of the map is assembled (churn test)")
    ap.add_argument("--sim-loss", type=float, default=0.0, help="built-in egress loss probability (0..1)")
    ap.add_argument("--sim-delay", type=float, default=0.0, help="built-in egress delay, ms")
    ap.add_argument("--sim-jitter", type=float, default=0.0, help="built-in egress jitter, ms")
    Client(ap.parse_args()).run()


if __name__ == "__main__":
    main()
