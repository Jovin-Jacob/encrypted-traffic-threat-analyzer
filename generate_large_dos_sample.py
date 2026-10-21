"""Generate a 100,000-packet offline SYN-flood demonstration PCAP.

All IP addresses are from documentation-only networks. The script only writes
synthetic packets to a local PCAP file; it never transmits network traffic.
"""

from __future__ import annotations

import random
import struct
from pathlib import Path

from generate_demo_data import tcp_packet


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "demo_dos_100k.pcap"
BASE_TIME = 1_792_000_000  # Synthetic timestamp: 2026-10-16 UTC
ATTACK_FLOWS = 40
PACKETS_PER_ATTACK_FLOW = 2_475
BACKGROUND_FLOWS = 20
PACKETS_PER_BACKGROUND_FLOW = 50
TOTAL_PACKETS = (ATTACK_FLOWS * PACKETS_PER_ATTACK_FLOW
                 + BACKGROUND_FLOWS * PACKETS_PER_BACKGROUND_FLOW)


def make_capture() -> list[tuple[float, bytes]]:
    rng = random.Random(100_042)
    events: list[tuple[float, bytes]] = []
    ident = 1

    def emit(offset, src, dst, sport, dport, seq, ack, flags, payload=b""):
        nonlocal ident
        frame = tcp_packet(src, dst, sport, dport, seq, ack, flags, payload, ident)
        events.append((BASE_TIME + offset, frame))
        ident = ident % 65_535 + 1

    # Forty distinct one-way SYN streams converge on two services at one
    # synthetic victim. The 99,000 SYN packets have no completing handshakes.
    victim = "198.51.100.42"  # RFC 5737 TEST-NET-2
    flow_index = 0
    for source_index in range(20):
        source = f"192.0.2.{source_index + 1}"  # RFC 5737 TEST-NET-1
        for destination_port in (80, 443):
            source_port = 40_000 + flow_index
            sequence_base = 1_000_000 + flow_index * 10_000
            flow_start = 0.05 + flow_index * 0.0005
            for packet_index in range(PACKETS_PER_ATTACK_FLOW):
                # 2,475 packets per flow over about five seconds, interleaved
                # among sources to resemble a distributed high-rate burst.
                offset = flow_start + packet_index * 0.002
                emit(offset, source, victim, source_port, destination_port,
                     sequence_base + packet_index * 1_000, 0, 0x02)
            flow_index += 1

    # Twenty modest, completed TCP sessions provide comparison traffic.
    for session_index in range(BACKGROUND_FLOWS):
        client = f"192.0.2.{101 + session_index}"
        server = f"203.0.113.{10 + session_index}"  # RFC 5737 TEST-NET-3
        client_port, server_port = 50_000 + session_index, 443
        client_seq = rng.randrange(100_000, 900_000)
        server_seq = rng.randrange(100_000, 900_000)
        start = 6.0 + session_index * 0.08
        emit(start, client, server, client_port, server_port, client_seq, 0, 0x02)
        emit(start + 0.01, server, client, server_port, client_port,
             server_seq, client_seq + 1, 0x12)
        emit(start + 0.02, client, server, client_port, server_port,
             client_seq + 1, server_seq + 1, 0x10)
        # 24 client-to-server and 23 server-to-client data packets complete
        # the 50-packet session. Payloads are inert synthetic bytes.
        for packet_index in range(47):
            offset = start + 0.04 + packet_index * 0.04
            if packet_index % 2 == 0:
                emit(offset, client, server, client_port, server_port,
                     client_seq + 1 + packet_index * 64, server_seq + 1,
                     0x18, b"D" * 64)
            else:
                emit(offset, server, client, server_port, client_port,
                     server_seq + 1 + packet_index * 64, client_seq + 65,
                     0x18, b"R" * 64)

    events.sort(key=lambda item: item[0])
    assert len(events) == TOTAL_PACKETS == 100_000
    return events


def main() -> None:
    events = make_capture()
    with OUTPUT.open("wb") as capture:
        # Classic little-endian PCAP, Ethernet link type.
        capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1))
        for timestamp, frame in events:
            seconds = int(timestamp)
            microseconds = int((timestamp - seconds) * 1_000_000)
            capture.write(struct.pack("<IIII", seconds, microseconds,
                                      len(frame), len(frame)))
            capture.write(frame)
    print(f"Created {OUTPUT} with {len(events):,} packets")
    print(f"Attack-indicator flows: {ATTACK_FLOWS} SYN-only flows")
    print(f"Background flows: {BACKGROUND_FLOWS} ordinary sessions")
    print(f"Total distinct flows: {ATTACK_FLOWS + BACKGROUND_FLOWS}")


if __name__ == "__main__":
    main()

