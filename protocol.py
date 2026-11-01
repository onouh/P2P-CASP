
import struct

PROTOCOL_ID = 0xCA5F
VERSION = 1

HEADER_FORMAT = "!HBBIHH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

INIT = 1
PEER_LIST = 2
CHUNK_REQ = 3
CHUNK_DATA = 4
PEER_HEARTBEAT = 5
CHUNK_BITMAP = 6
MAP_COMPLETE = 7


def pack_message(msg_type, sequence_num, peer_id, payload=b""):
    if len(payload) > 1200:
        raise ValueError("Payload exceeds 1200 bytes")

    header = struct.pack(
        HEADER_FORMAT,
        PROTOCOL_ID,
        VERSION,
        msg_type,
        sequence_num,
        peer_id,
        len(payload)
    )

    return header + payload


def unpack_message(data):
    if len(data) < HEADER_SIZE:
        raise ValueError("Incomplete header")

    header = data[:HEADER_SIZE]

    protocol_id, version, msg_type, seq, peer_id, length = struct.unpack(
        HEADER_FORMAT, header
    )

    if protocol_id != PROTOCOL_ID:
        raise ValueError("Invalid protocol ID")

    if version != VERSION:
        raise ValueError("Unsupported version")

    if msg_type not in range(1, 8):
        raise ValueError("Unknown message type")

    if length > 1200 or len(data) != HEADER_SIZE + length:
        raise ValueError("Invalid payload length")

    payload = data[HEADER_SIZE:]

    return msg_type, seq, peer_id, payload
