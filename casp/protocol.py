"""
P2P-CASP wire format: 16-byte binary header, message types and payload codecs.

Header (network byte order, struct format "!HBBIIHH", 16 bytes):

    offset  size  field
    0       2     Protocol_ID     constant 0xCA5B, lets a node drop foreign traffic
    2       1     Version         currently 1
    3       1     Message_Type    see MSG_* below
    4       4     Sequence_Num    per-sender counter, +1 for every packet sent
    8       4     Peer_ID         sender's id (0 = tracker/server)
    12      2     Payload_Length  bytes following the header
    14      2     Checksum        low 16 bits of CRC-32 over header (checksum=0) + payload
"""
import struct
import zlib

PROTOCOL_ID = 0xCA5B
VERSION = 1
HEADER = struct.Struct("!HBBIIHH")
HEADER_LEN = HEADER.size                      # 16
MAX_DATAGRAM = 1200                           # MTU limit from the spec (application payload)
SERVER_ID = 0
IP_UDP_OVERHEAD = 28                          # IPv4 (20) + UDP (8), used for bandwidth accounting

# ---- message types -------------------------------------------------------
MSG_REGISTER = 1        # client -> tracker   : join / refresh
MSG_PEER_LIST = 2       # tracker -> client   : (peer_id, ip, port) tuples
MSG_MANIFEST = 3        # tracker -> client   : per-chunk content tags
MSG_PEER_HEARTBEAT = 4  # any -> any          : RTT probe
MSG_HEARTBEAT_ACK = 5   # any -> any          : RTT probe echo
MSG_CHUNK_BITMAP = 6    # client -> client    : chunk availability (full or delta)
MSG_CHUNK_REQ = 7       # client -> any       : explicit pull request
MSG_CHUNK_DATA = 8      # any -> client       : payload delivery
MSG_MAP_COMPLETE = 9    # client -> tracker   : final state declaration
MSG_COMPLETE_ACK = 10   # tracker -> client   : validation result
MSG_SESSION_END = 11    # tracker -> client   : everybody is done
MSG_MANIFEST_REQ = 12   # client -> client    : ask a peer for the manifest (saves server bandwidth)

MSG_NAMES = {
    1: "REGISTER", 2: "PEER_LIST", 3: "MANIFEST", 4: "PEER_HEARTBEAT",
    5: "HEARTBEAT_ACK", 6: "CHUNK_BITMAP", 7: "CHUNK_REQ", 8: "CHUNK_DATA",
    9: "MAP_COMPLETE", 10: "COMPLETE_ACK", 11: "SESSION_END", 12: "MANIFEST_REQ",
}
SIGNALING_TYPES = (MSG_PEER_HEARTBEAT, MSG_HEARTBEAT_ACK, MSG_CHUNK_BITMAP)

BITMAP_FULL = 0
BITMAP_DELTA = 1


class ProtocolError(Exception):
    pass


def _checksum(buf):
    return zlib.crc32(buf) & 0xFFFF


def pack(msg_type, seq, peer_id, payload=b""):
    """Build one datagram: header + payload."""
    if HEADER_LEN + len(payload) > MAX_DATAGRAM:
        raise ProtocolError("datagram would exceed the %d byte MTU limit" % MAX_DATAGRAM)
    head = HEADER.pack(PROTOCOL_ID, VERSION, msg_type, seq & 0xFFFFFFFF, peer_id, len(payload), 0)
    cks = _checksum(head + payload)
    return HEADER.pack(PROTOCOL_ID, VERSION, msg_type, seq & 0xFFFFFFFF, peer_id, len(payload), cks) + payload


def unpack(datagram):
    """Parse and validate a datagram. Returns (msg_type, seq, peer_id, payload)."""
    if len(datagram) < HEADER_LEN:
        raise ProtocolError("short datagram")
    proto, ver, msg_type, seq, peer_id, plen, cks = HEADER.unpack_from(datagram)
    if proto != PROTOCOL_ID:
        raise ProtocolError("bad protocol id")
    if ver != VERSION:
        raise ProtocolError("unsupported version %d" % ver)
    if plen != len(datagram) - HEADER_LEN:
        raise ProtocolError("payload length mismatch")
    zeroed = datagram[:14] + b"\x00\x00" + datagram[HEADER_LEN:]
    if _checksum(zeroed) != cks:
        raise ProtocolError("checksum mismatch")
    return msg_type, seq, peer_id, datagram[HEADER_LEN:]


# ---- payload codecs ------------------------------------------------------
_PEER_ENTRY = struct.Struct("!I4sH")           # peer_id, IPv4, port  (10 bytes)
_LIST_HEAD = struct.Struct("!HB8s")            # list_version, count, manifest digest
_MANIFEST_HEAD = struct.Struct("!HHB")         # n_chunks, chunk_size, tag_len
_HEARTBEAT = struct.Struct("!IH")              # ts_us, have_count
_HB_ACK = struct.Struct("!IHH")                # echo_ts_us, have_count, list_version
_CHUNK_ID = struct.Struct("!H")
_COMPLETE = struct.Struct("!32sIHH")           # sha256(map), completion_ms, dup_count, p2p_chunks


def enc_peer_list(version, peers, manifest_digest):
    """peers: iterable of (peer_id, ip_string, port)."""
    import socket
    peers = list(peers)
    out = [_LIST_HEAD.pack(version & 0xFFFF, len(peers), manifest_digest)]
    for pid, ip, port in peers:
        out.append(_PEER_ENTRY.pack(pid, socket.inet_aton(ip), port))
    return b"".join(out)


def dec_peer_list(payload):
    import socket
    version, count, manifest_digest = _LIST_HEAD.unpack_from(payload)
    peers = []
    off = _LIST_HEAD.size
    for _ in range(count):
        pid, ip, port = _PEER_ENTRY.unpack_from(payload, off)
        peers.append((pid, socket.inet_ntoa(ip), port))
        off += _PEER_ENTRY.size
    return version, peers, manifest_digest


def enc_manifest(n_chunks, chunk_size, tags):
    tag_len = len(tags[0])
    return _MANIFEST_HEAD.pack(n_chunks, chunk_size, tag_len) + b"".join(tags)


def manifest_digest(manifest_payload):
    """8-byte identifier of a manifest (like a torrent info-hash); the tracker hands it out."""
    import hashlib
    return hashlib.sha256(manifest_payload).digest()[:8]


def dec_manifest(payload):
    n_chunks, chunk_size, tag_len = _MANIFEST_HEAD.unpack_from(payload)
    body = payload[_MANIFEST_HEAD.size:]
    if len(body) != n_chunks * tag_len:
        raise ProtocolError("manifest size mismatch")
    tags = [body[i * tag_len:(i + 1) * tag_len] for i in range(n_chunks)]
    return n_chunks, chunk_size, tags


def enc_heartbeat(ts_us, have_count):
    return _HEARTBEAT.pack(ts_us & 0xFFFFFFFF, have_count)


def dec_heartbeat(payload):
    return _HEARTBEAT.unpack(payload)


def enc_hb_ack(echo_ts_us, have_count, list_version=0):
    return _HB_ACK.pack(echo_ts_us & 0xFFFFFFFF, have_count, list_version & 0xFFFF)


def dec_hb_ack(payload):
    return _HB_ACK.unpack(payload)


def enc_bitmap_full(have, n_chunks):
    """have: set of chunk ids. Bit i of the bitfield (MSB first in each byte) = chunk i."""
    bits = bytearray((n_chunks + 7) // 8)
    for c in have:
        bits[c >> 3] |= 0x80 >> (c & 7)
    return bytes([BITMAP_FULL]) + bytes(bits)


def enc_bitmap_delta(new_chunks):
    """Delta form: only the chunk ids gained since the last advertisement (2 bytes each)."""
    return bytes([BITMAP_DELTA]) + b"".join(_CHUNK_ID.pack(c) for c in new_chunks)


def dec_bitmap(payload, n_chunks):
    """Returns (mode, set_of_chunk_ids)."""
    mode = payload[0]
    body = payload[1:]
    if mode == BITMAP_FULL:
        have = set()
        for c in range(min(n_chunks, len(body) * 8)):
            if body[c >> 3] & (0x80 >> (c & 7)):
                have.add(c)
        return mode, have
    if mode == BITMAP_DELTA:
        ids = {_CHUNK_ID.unpack_from(body, i)[0] for i in range(0, len(body) - 1, 2)}
        return mode, {c for c in ids if c < n_chunks}
    raise ProtocolError("unknown bitmap mode")


def enc_chunk_req(chunk_id):
    return _CHUNK_ID.pack(chunk_id)


def dec_chunk_req(payload):
    return _CHUNK_ID.unpack(payload)[0]


def enc_chunk_data(chunk_id, data):
    return _CHUNK_ID.pack(chunk_id) + data


def dec_chunk_data(payload):
    return _CHUNK_ID.unpack_from(payload)[0], payload[2:]


def enc_complete(map_digest, completion_ms, dup_count, p2p_chunks):
    return _COMPLETE.pack(map_digest, min(completion_ms, 0xFFFFFFFF), min(dup_count, 0xFFFF), min(p2p_chunks, 0xFFFF))


def dec_complete(payload):
    return _COMPLETE.unpack(payload)
