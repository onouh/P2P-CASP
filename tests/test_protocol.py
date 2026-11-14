"""Unit tests for the wire format and the map store.  Run:  python3 -m unittest discover -s tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from casp import mapgen                     # noqa: E402
from casp import protocol as P              # noqa: E402


class HeaderTests(unittest.TestCase):
    def test_header_is_16_bytes(self):
        self.assertEqual(P.HEADER_LEN, 16)

    def test_roundtrip(self):
        d = P.pack(P.MSG_CHUNK_REQ, 77, 3, P.enc_chunk_req(200))
        self.assertEqual(P.unpack(d), (P.MSG_CHUNK_REQ, 77, 3, P.enc_chunk_req(200)))

    def test_corruption_is_detected(self):
        d = bytearray(P.pack(P.MSG_CHUNK_DATA, 1, 1, P.enc_chunk_data(5, b"x" * 16)))
        d[-1] ^= 0x01
        with self.assertRaises(P.ProtocolError):
            P.unpack(bytes(d))

    def test_foreign_and_short_datagrams_rejected(self):
        for bad in (b"", b"hello", b"\x00" * 16):
            with self.assertRaises(P.ProtocolError):
                P.unpack(bad)

    def test_mtu_limit(self):
        with self.assertRaises(P.ProtocolError):
            P.pack(P.MSG_CHUNK_DATA, 1, 1, b"x" * 1185)


class PayloadTests(unittest.TestCase):
    def test_bitmap_full_and_delta(self):
        have = {0, 7, 8, 100, 255}
        self.assertEqual(P.dec_bitmap(P.enc_bitmap_full(have, 256), 256), (P.BITMAP_FULL, have))
        self.assertEqual(len(P.enc_bitmap_full(have, 256)), 33)
        self.assertEqual(P.dec_bitmap(P.enc_bitmap_delta([3, 250]), 256), (P.BITMAP_DELTA, {3, 250}))

    def test_peer_list(self):
        peers = [(1, "10.77.0.11", 5000), (2, "127.0.0.1", 65535)]
        self.assertEqual(P.dec_peer_list(P.enc_peer_list(9, peers, b"ABCDEFGH")), (9, peers, b"ABCDEFGH"))

    def test_manifest_fits_in_one_datagram(self):
        full = mapgen.build_full_map(42)
        tags = [mapgen.tag(full.get(c)) for c in range(mapgen.N_CHUNKS)]
        payload = P.enc_manifest(mapgen.N_CHUNKS, 16, tags)
        self.assertLessEqual(P.HEADER_LEN + len(payload), P.MAX_DATAGRAM)
        self.assertEqual(P.dec_manifest(payload), (256, 16, tags))


class MapTests(unittest.TestCase):
    def test_generator_is_deterministic(self):
        self.assertEqual(mapgen.gen_chunk(42, 9), mapgen.gen_chunk(42, 9))
        self.assertNotEqual(mapgen.gen_chunk(42, 9), mapgen.gen_chunk(43, 9))

    def test_out_of_order_assembly_gives_same_map(self):
        full = mapgen.build_full_map(7)
        other = mapgen.MapStore()
        for c in reversed(range(mapgen.N_CHUNKS)):
            other.put(c, full.get(c))
        self.assertTrue(other.complete())
        self.assertEqual(other.digest(), full.digest())
        self.assertEqual(len(full.grid), 64 * 64)


if __name__ == "__main__":
    unittest.main()
