"""
Deterministic synthetic map generator.

The shared "map" is a 64 x 64 grid of cells (1 byte per cell by default). It is split
into 256 chunks, each chunk being a 4 x 4 block of cells (16 bytes). Chunk i covers
block row i // 16 and block column i % 16. Every chunk is addressed by a content tag:
the first 4 bytes of SHA-256(chunk bytes). The list of tags is the manifest.
"""
import hashlib

GRID = 64            # cells per side
BLOCK = 4            # cells per chunk side
BLOCKS_PER_SIDE = GRID // BLOCK          # 16
N_CHUNKS = BLOCKS_PER_SIDE ** 2          # 256
TAG_LEN = 4


def chunk_size(cell_bytes=1):
    return BLOCK * BLOCK * cell_bytes


def gen_chunk(seed, chunk_id, cell_bytes=1):
    """Pseudo-random chunk content, identical on every OS / Python version."""
    need = chunk_size(cell_bytes)
    out = b""
    counter = 0
    while len(out) < need:
        out += hashlib.sha256(b"CASP-MAP|%d|%d|%d" % (seed, chunk_id, counter)).digest()
        counter += 1
    return out[:need]


def tag(data):
    return hashlib.sha256(data).digest()[:TAG_LEN]


class MapStore:
    """Holds the grid and places chunks at their block position (out-of-order assembly)."""

    def __init__(self, cell_bytes=1):
        self.cell_bytes = cell_bytes
        self.row_bytes = GRID * cell_bytes
        self.grid = bytearray(GRID * self.row_bytes)
        self.have = set()

    def put(self, chunk_id, data):
        brow, bcol = divmod(chunk_id, BLOCKS_PER_SIDE)
        w = BLOCK * self.cell_bytes                       # bytes per chunk row
        for r in range(BLOCK):
            start = (brow * BLOCK + r) * self.row_bytes + bcol * w
            self.grid[start:start + w] = data[r * w:(r + 1) * w]
        self.have.add(chunk_id)

    def get(self, chunk_id):
        brow, bcol = divmod(chunk_id, BLOCKS_PER_SIDE)
        w = BLOCK * self.cell_bytes
        parts = []
        for r in range(BLOCK):
            start = (brow * BLOCK + r) * self.row_bytes + bcol * w
            parts.append(bytes(self.grid[start:start + w]))
        return b"".join(parts)

    def complete(self):
        return len(self.have) == N_CHUNKS

    def digest(self):
        return hashlib.sha256(bytes(self.grid)).digest()


def build_full_map(seed, cell_bytes=1):
    store = MapStore(cell_bytes)
    for c in range(N_CHUNKS):
        store.put(c, gen_chunk(seed, c, cell_bytes))
    return store
