"""
UDP endpoint used by both the server and the clients.

Adds three things on top of a plain non-blocking UDP socket:
  * a packet log (CSV): every datagram sent / received, with timestamps and metadata
  * an optional built-in pcap writer, so traces can be opened in Wireshark even on
    machines without tcpdump
  * an optional egress impairment (loss / delay / jitter, seeded) for development on
    Windows or without root. Real experiments on Linux should use tc/netem instead.
"""
import csv
import heapq
import random
import select
import socket
import struct
import time

from . import protocol as P


class PcapWriter:
    """Minimal pcap writer (LINKTYPE_RAW = raw IPv4). Builds the IP + UDP headers itself."""

    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))

    def write(self, ts, src, dst, data):
        try:
            sip, dip = socket.inet_aton(src[0]), socket.inet_aton(dst[0])
        except OSError:
            return
        udp = struct.pack("!HHHH", src[1], dst[1], 8 + len(data), 0) + data
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, sip, dip)
        pkt = ip + udp
        sec = int(ts)
        self.f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(pkt), len(pkt)) + pkt)

    def close(self):
        self.f.close()


class Endpoint:
    def __init__(self, bind_ip, port, peer_id, log_path=None, pcap_path=None,
                 sim_loss=0.0, sim_delay_ms=0.0, sim_jitter_ms=0.0, sim_seed=0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_ip, port))
        self.sock.setblocking(False)
        self.addr = self.sock.getsockname()
        self.public_ip = bind_ip if bind_ip not in ("", "0.0.0.0") else "127.0.0.1"
        self.peer_id = peer_id
        self.seq = 0
        self.t0 = time.monotonic()

        self.sim_loss = sim_loss
        self.sim_delay = sim_delay_ms / 1000.0
        self.sim_jitter = sim_jitter_ms / 1000.0
        self.rng = random.Random(sim_seed)
        self._delayed = []            # heap of (release_time, n, datagram, addr)
        self._n = 0

        self.bytes_out = {}           # msg_type -> application bytes sent
        self.bytes_in = {}
        self._log_file = open(log_path, "w", newline="") if log_path else None
        self._log = csv.writer(self._log_file) if self._log_file else None
        if self._log:
            self._log.writerow(["unix_time", "t_ms", "dir", "remote_ip", "remote_port", "msg_type",
                                "seq", "peer_id", "payload_len", "datagram_len", "info"])
        self._pcap = PcapWriter(pcap_path) if pcap_path else None

    # -- time helpers ------------------------------------------------------
    def now_ms(self):
        return (time.monotonic() - self.t0) * 1000.0

    def ts_us(self):
        """32-bit wrapping microsecond clock carried in heartbeats."""
        return int((time.monotonic() - self.t0) * 1e6) & 0xFFFFFFFF

    # -- sending -----------------------------------------------------------
    def send(self, msg_type, payload, addr, info=""):
        self.seq += 1
        datagram = P.pack(msg_type, self.seq, self.peer_id, payload)
        self.bytes_out[msg_type] = self.bytes_out.get(msg_type, 0) + len(datagram)
        dropped = self.sim_loss > 0 and self.rng.random() < self.sim_loss
        self._record("TX" if not dropped else "TX-SIMDROP", addr, msg_type, self.seq,
                     self.peer_id, len(payload), len(datagram), info, datagram)
        if dropped:
            return len(datagram)
        if self.sim_delay > 0 or self.sim_jitter > 0:
            d = self.sim_delay + self.rng.uniform(-self.sim_jitter, self.sim_jitter)
            self._n += 1
            heapq.heappush(self._delayed, (time.monotonic() + max(0.0, d), self._n, datagram, addr))
        else:
            self._raw_send(datagram, addr)
        return len(datagram)

    def _raw_send(self, datagram, addr):
        try:
            self.sock.sendto(datagram, addr)
        except OSError:
            pass                       # e.g. peer vanished; the protocol's timers deal with it

    def pump(self):
        """Release delayed datagrams whose time has come (only used with built-in impairment)."""
        now = time.monotonic()
        while self._delayed and self._delayed[0][0] <= now:
            _, _, datagram, addr = heapq.heappop(self._delayed)
            self._raw_send(datagram, addr)

    # -- receiving ---------------------------------------------------------
    def wait(self, timeout):
        if self._delayed:
            timeout = max(0.0, min(timeout, self._delayed[0][0] - time.monotonic()))
        try:
            select.select([self.sock], [], [], timeout)
        except (OSError, ValueError):
            pass

    def recv_all(self):
        """Yield (msg_type, seq, peer_id, payload, addr) for every valid queued datagram."""
        out = []
        while True:
            try:
                datagram, addr = self.sock.recvfrom(2048)
            except BlockingIOError:
                break
            except ConnectionResetError:
                continue               # Windows reports ICMP port-unreachable this way
            except OSError:
                break
            try:
                msg_type, seq, pid, payload = P.unpack(datagram)
            except P.ProtocolError as exc:
                self._record("RX-BAD", addr, 0, 0, 0, 0, len(datagram), str(exc), None)
                continue
            self.bytes_in[msg_type] = self.bytes_in.get(msg_type, 0) + len(datagram)
            info = ""
            if msg_type in (P.MSG_CHUNK_REQ, P.MSG_CHUNK_DATA) and len(payload) >= 2:
                info = "chunk=%d" % struct.unpack_from("!H", payload)[0]
            self._record("RX", addr, msg_type, seq, pid, len(payload), len(datagram), info, datagram)
            out.append((msg_type, seq, pid, payload, addr))
        return out

    # -- logging -----------------------------------------------------------
    def _record(self, direction, addr, msg_type, seq, pid, plen, dlen, info, datagram):
        now = time.time()
        if self._log:
            self._log.writerow(["%.6f" % now, "%.3f" % self.now_ms(), direction, addr[0], addr[1],
                                P.MSG_NAMES.get(msg_type, msg_type), seq, pid, plen, dlen, info])
        if self._pcap and datagram is not None and direction in ("TX", "RX"):
            me = (self.public_ip, self.addr[1])
            if direction == "TX":
                self._pcap.write(now, me, addr, datagram)
            else:
                self._pcap.write(now, addr, me, datagram)

    def close(self):
        if self._log_file:
            self._log_file.close()
        if self._pcap:
            self._pcap.close()
        self.sock.close()
