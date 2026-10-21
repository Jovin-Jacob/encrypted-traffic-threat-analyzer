"""Generate a small offline TCP SYN-flood demonstration PCAP.

All endpoints use RFC 5737 documentation-only IP ranges. Packets are written
to a file and are never transmitted onto a network.
"""

from __future__ import annotations

import random
import struct
from pathlib import Path

from generate_demo_data import tcp_packet


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "demo_dos_syn_flood.pcap"
BASE_TIME = 1_768_000_000  # Synthetic timestamp: 2026-01-14 UTC


def make_capture() -> list[tuple[float, bytes]]:
    rng = random.Random(83021)
    events: list[tuple[float, bytes]] = []
    ident = 1

    def emit(offset, src, dst, sport, dport, seq, ack, flags, payload=b""):
        nonlocal ident
        events.append((BASE_TIME + offset,
                       tcp_packet(src, dst, sport, dport, seq, ack, flags, payload, ident)))
        ident = ident % 65535 + 1

    # Ten ordinary short TCP sessions provide benign comparison traffic.
    for flow in range(10):
        src = f"192.0.2.{20 + flow}"       # RFC 5737 TEST-NET-1
        dst = f"203.0.113.{10 + flow}"     # RFC 5737 TEST-NET-3
        sport, dport = 41000 + flow, 443 if flow % 2 else 80
        client_seq = rng.randrange(100_000, 900_000)
        server_seq = rng.randrange(100_000, 900_000)
        start = flow * 0.31
        emit(start, src, dst, sport, dport, client_seq, 0, 0x02)  # SYN
        emit(start + .012, dst, src, dport, sport, server_seq, client_seq + 1, 0x12)  # SYN/ACK
        emit(start + .020, src, dst, sport, dport, client_seq + 1, server_seq + 1, 0x10)  # ACK
        cseq, sseq = client_seq + 1, server_seq + 1
        for packet_index in range(rng.randint(5, 12)):
            payload = b"GET /demo HTTP/1.1\r\nHost: example.invalid\r\n\r\n" if packet_index == 0 else b"x" * rng.randint(120, 700)
            when = start + .05 + packet_index * rng.uniform(.035, .075)
            emit(when, src, dst, sport, dport, cseq, sseq, 0x18, payload)
            cseq += len(payload)
            if packet_index % 3 == 1:
                reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                emit(when + .012, dst, src, dport, sport, sseq, cseq, 0x18, reply)
                sseq += len(reply)
        emit(start + 1.05, src, dst, sport, dport, cseq, sseq, 0x11)  # FIN/ACK
        emit(start + 1.07, dst, src, dport, sport, sseq, cseq + 1, 0x11)

    # A SYN flood: repeated SYN-only packets from four synthetic sources to
    # one documentation-only victim and service port. No handshake completes.
    victim = "198.51.100.42"                 # RFC 5737 TEST-NET-2
    for source_index in range(4):
        source = f"192.0.2.{100 + source_index}"  # TEST-NET-1
        source_port = 50000 + source_index
        seq = 2_000_000 + source_index * 10_000
        for packet_index in range(4000):
            offset = 4.0 + packet_index * .0015 + source_index * .0002
            emit(offset, source, victim, source_port, 80,
                 seq + packet_index * 1000, 0, 0x02)  # SYN only

    events.sort(key=lambda item: item[0])
    return events


def main() -> None:
    events = make_capture()
    with OUTPUT.open("wb") as capture:
        # Classic little-endian PCAP, Ethernet link type.
        capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in events:
            seconds = int(timestamp)
            microseconds = int((timestamp - seconds) * 1_000_000)
            capture.write(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
            capture.write(frame)
    print(f"Created {OUTPUT} with {len(events)} synthetic packets")


if __name__ == "__main__":
    main()

