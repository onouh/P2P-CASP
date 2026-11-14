# P2P-CASP — CSE361 Project 1 (Decentralized Cartographer)

P2P Content-Addressable Chunk Streaming Protocol over UDP: 1 tracker/seeder + N peers
assemble a 64 x 64 map split into 256 content-addressed chunks. Python 3.8+, standard
library only (matplotlib is needed only for the plots).

> Demo video link: **TODO — paste your "anyone with the link" URL here**

## Files

| File | Role |
|---|---|
| `casp/protocol.py` | 16-byte header, message types, payload encoders/decoders |
| `casp/mapgen.py` | deterministic map generator, chunk tags, out-of-order map store |
| `casp/net.py` | UDP endpoint: packet log (CSV), pcap writer, optional built-in impairment |
| `server.py` | bootstrap tracker, 50 kbps rate-limited seeder, MAP_COMPLETE validation |
| `client.py` | peer: heartbeats/RTT, bitmaps, peer selection, chunk pull, assembly |
| `run_experiments.py` / `.sh` | runs every scenario N times (netem or built-in impairment) |
| `run_baseline.sh` | one "Baseline local" run (Phase 1 deliverable) |
| `analyze.py` | min/median/max tables, acceptance check, plots |
| `tests/test_protocol.py` | unit tests for the wire format |

## Quick start (any OS)

```
python3 -m unittest discover -s tests          # 10 tests
./run_baseline.sh                              # or: python3 run_experiments.py --mode sim --scenarios baseline --reps 1
```

By hand, in five terminals:

```
python3 server.py --port 9000 --seed 42 --expect 4 --out logs/demo
python3 client.py --id 1 --server 127.0.0.1:9000 --out logs/demo      # then --id 2, 3, 4
```

Each node writes `*_packets.csv` (every packet sent/received with timestamps) and
`metrics_*.csv` into `--out`. Add `--pcap` for a Wireshark-readable trace.

## Full experiments

```
sudo ./run_experiments.sh        # Linux: tc/netem in network namespaces + tcpdump   (graded results)
./run_experiments.sh sim         # any OS, no root: same impairments applied by the program
```

Environment variables: `SCENARIOS=baseline,loss5,asym,churn REPS=5 SEED_BASE=100`.
Rep k uses seed `SEED_BASE + k`, so runs are repeatable. Output goes to
`results/<timestamp>_<mode>_seed<base>/<scenario>/rep<k>_seed<s>/` plus `results.csv`,
`clients.csv` and `analysis/` (summary table and PNG plots).

### netem commands used (netns mode)

Each node lives in namespace `casp-<node>` with interface `v-<node>` (server 10.77.0.1,
client i 10.77.0.1i), all joined by bridge `caspbr0`.

| Scenario | Command (run inside the node's namespace) | Nodes |
|---|---|---|
| baseline | none | — |
| loss5 | `tc qdisc add dev v-<node> root netem loss 5%` | server + all clients |
| asym | `tc qdisc add dev v-<node> root netem delay 100ms 20ms` | c1, c2 |
| churn | none; client 2 runs with `--die-at 0.5` (`os._exit`, nothing sent on exit) | c2 |
| remove | `tc qdisc del dev v-<node> root` | all |

The exact commands of every run are saved in its `netem_commands.txt`.

## Protocol summary

Header, 16 bytes, `struct.pack("!HBBIIHH", ...)`:

| Offset | Bytes | Field | Notes |
|---|---|---|---|
| 0 | 2 | Protocol_ID | 0xCA5B |
| 2 | 1 | Version | 1 |
| 3 | 1 | Message_Type | table below |
| 4 | 4 | Sequence_Num | per-sender counter |
| 8 | 4 | Peer_ID | 0 = server |
| 12 | 2 | Payload_Length | bytes after the header |
| 14 | 2 | Checksum | low 16 bits of CRC-32 over header + payload |

| Type | Name | Direction | Payload |
|---|---|---|---|
| 1 | REGISTER | client → server | 1 byte: 0 = peer list only, 1 = also send manifest |
| 2 | PEER_LIST | server → client | list_version(2) count(1) manifest_id(8) + count × [peer_id(4) ip(4) port(2)] |
| 3 | MANIFEST | server or peer → client | n_chunks(2) chunk_size(2) tag_len(1) + n × tag |
| 4 | PEER_HEARTBEAT | any → any | ts_us(4) have_count(2) |
| 5 | HEARTBEAT_ACK | any → any | echo_ts_us(4) have_count(2) list_version(2) |
| 6 | CHUNK_BITMAP | client → client | mode(1): 0 = full 32-byte bitfield, 1 = delta list of chunk ids (2 bytes each) |
| 7 | CHUNK_REQ | client → any | chunk_id(2) |
| 8 | CHUNK_DATA | any → client | chunk_id(2) + 16 data bytes |
| 9 | MAP_COMPLETE | client → server | sha256(map)(32) completion_ms(4) dup_count(2) p2p_chunks(2) |
| 10 | COMPLETE_ACK | server → client | 1 byte: 1 = valid |
| 11 | SESSION_END | server → client | — |
| 12 | MANIFEST_REQ | client → client | — |

Key mechanisms (all in `client.py` / `server.py`, constants at the top of each file):

- **Peer score** = SRTT × (1 + 10 × loss). SRTT/RTTVAR use the RFC 6298 EWMA, fed by
  heartbeats (every 200 ms) and by answered chunk requests; loss is an EWMA over
  unanswered heartbeats and timed-out requests. Each missing chunk goes to the
  lowest-scoring live holder.
- **Request timeout** = min(500 ms, max(150 ms, 2·SRTT + 4·RTTVAR)); on expiry the chunk
  is re-routed to a different holder when one exists.
- **Bitmap encoding**: delta lists batched every 20 ms, full bitfield every 500 ms to
  repair lost deltas.
- **Server throttle**: pacing at 48.5 kbps plus a strict sliding-window cap of 49.5 kbps
  in any 1 s, counted at IP level (datagram + 28 bytes).
- **Seed hold**: the server does not send the same chunk to a second peer within 2 s if
  the first receiver is still alive; the second peer pulls it P2P instead.
- **Striped seeding**: clients ask the server first for chunks where
  `chunk_id % n_peers == own rank`, so they do not spend server bandwidth on the same chunks.
- **Slow-holder turn-taking**: when only slow peers hold a chunk, clients stagger their
  requests so one fetches it and the rest copy it from the faster peer.
- **Manifest from peers**: the tracker hands out an 8-byte manifest id; clients fetch the
  1 KB manifest from a peer when possible and verify it against the id.
- **Churn**: a peer silent for 1 s is dropped from routing, its bitmap cleared and its
  pending requests re-issued; the tracker drops it after 4 s.

## Things you must know before submitting

- **Chunk size is 16 bytes** (1 byte per cell, 4 x 4 cells). This is forced by the spec:
  every chunk must leave the 50 kbps server once, so in 5 s at most ~31 KB can enter the
  swarm. Change `--cell-bytes` on server and clients to experiment; baseline < 5 s will fail
  above roughly 2 bytes per cell.
- **Bandwidth is counted at IP level** (payload + 28). If your TA measures Ethernet frames
  (+14 more per packet) lower `--cap-kbps` / `--pace-kbps` accordingly.
- **`sample_results_sim/` was produced with the built-in impairment on localhost**, not
  with netem. The netns/netem mode of `run_experiments.py` has not been run yet; run it on
  your Linux VM and use those results and tcpdump pcaps in the report.
- `signaling_overhead` is above 1 (more signaling bytes than chunk bytes) because chunks
  are so small; discuss this in Limitations.
