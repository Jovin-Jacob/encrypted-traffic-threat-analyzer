"""Create deterministic synthetic examples for demonstrating the app UI.

These are fabricated records, not observations from a real network. The PCAP
contains synthetic TCP packets with TLS-like application payload bytes.
"""

from __future__ import annotations

import csv
import ipaddress
import random
import struct
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
FIELDS = [
    "flow_id", "source_ip", "source_port", "destination_ip", "destination_port",
    "protocol", "duration_seconds", "packet_count", "total_bytes",
    "forward_packets", "reverse_packets", "forward_bytes", "reverse_bytes",
    "mean_packet_size", "std_packet_size", "mean_interarrival_seconds",
    "payload_bytes", "syn_count", "ack_count", "rst_count", "fin_count", "label",
]


def clamp_int(rng, low, high):
    return rng.randint(low, high)


def make_flow(rng, label, index):
    source = f"192.168.10.{(index % 240) + 10}"
    destination = f"203.0.113.{(index % 200) + 10}"
    source_port = clamp_int(rng, 32000, 64000)
    destination_port = rng.choice([443, 443, 443, 8443, 993])

    if label == "benign":
        duration = rng.uniform(.15, 18)
        packets = clamp_int(rng, 8, 75)
        forward_packets = max(2, int(packets * rng.uniform(.38, .67)))
        reverse_packets = packets - forward_packets
        fwd_bytes = forward_packets * clamp_int(rng, 180, 1050)
        rev_bytes = reverse_packets * clamp_int(rng, 160, 1000)
        syn, ack, rst, fin = 1, max(2, packets - 2), int(rng.random() < .025), 2
        payload = int((fwd_bytes + rev_bytes) * rng.uniform(.58, .88))
    elif label == "port_scan":
        destination_port = rng.choice([21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080])
        duration = rng.uniform(.001, .22)
        packets = clamp_int(rng, 1, 4)
        forward_packets = packets
        reverse_packets = int(rng.random() < .27)
        packets += reverse_packets
        fwd_bytes = forward_packets * clamp_int(rng, 54, 74)
        rev_bytes = reverse_packets * clamp_int(rng, 54, 100)
        syn, ack, rst, fin = forward_packets, int(rng.random() < .12), reverse_packets, 0
        payload = 0
    elif label == "dos":
        duration = rng.uniform(.08, 3.5)
        packets = clamp_int(rng, 180, 1100)
        forward_packets = int(packets * rng.uniform(.91, .99))
        reverse_packets = packets - forward_packets
        size = clamp_int(rng, 500, 1350)
        fwd_bytes = forward_packets * size
        rev_bytes = reverse_packets * clamp_int(rng, 60, 500)
        syn, ack, rst, fin = clamp_int(rng, 1, 6), int(packets * rng.uniform(.55, .92)), 0, 0
        payload = int(fwd_bytes * rng.uniform(.65, .92))
    else:  # possible_exfiltration
        duration = rng.uniform(12, 150)
        packets = clamp_int(rng, 70, 460)
        forward_packets = int(packets * rng.uniform(.88, .98))
        reverse_packets = packets - forward_packets
        fwd_bytes = forward_packets * clamp_int(rng, 850, 1400)
        rev_bytes = max(80, reverse_packets * clamp_int(rng, 60, 280))
        syn, ack, rst, fin = 1, max(2, packets - 2), 0, 2
        payload = int(fwd_bytes * rng.uniform(.72, .94))

    total = fwd_bytes + rev_bytes
    mean_size = total / max(1, packets)
    row = {
        "flow_id": f"SYN-{index:05d}", "source_ip": source, "source_port": source_port,
        "destination_ip": destination, "destination_port": destination_port,
        "protocol": "TCP", "duration_seconds": round(duration, 6), "packet_count": packets,
        "total_bytes": total, "forward_packets": forward_packets,
        "reverse_packets": reverse_packets, "forward_bytes": fwd_bytes,
        "reverse_bytes": rev_bytes, "mean_packet_size": round(mean_size, 3),
        "std_packet_size": round(mean_size * rng.uniform(.12, .7), 3),
        "mean_interarrival_seconds": round(duration / max(1, packets - 1), 7),
        "payload_bytes": payload, "syn_count": syn, "ack_count": ack,
        "rst_count": rst, "fin_count": fin, "label": label,
    }
    return row


def write_csvs():
    rng = random.Random(73104)
    rows = []
    labels = (["benign"] * 600 + ["port_scan"] * 140 + ["dos"] * 120 +
              ["possible_exfiltration"] * 140)
    rng.shuffle(labels)
    for i, label in enumerate(labels, 1):
        rows.append(make_flow(rng, label, i))
    with (ROOT / "demo_labeled_flows.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    rng2 = random.Random(96521)
    unlabeled_rows = []
    demo_labels = ["benign"] * 190 + ["port_scan"] * 35 + ["dos"] * 25 + ["possible_exfiltration"] * 30
    rng2.shuffle(demo_labels)
    for i, label in enumerate(demo_labels, 1):
        row = make_flow(rng2, label, 2000 + i)
        row.pop("label")
        unlabeled_rows.append(row)
    with (ROOT / "demo_unlabeled_flows.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[c for c in FIELDS if c != "label"])
        writer.writeheader()
        writer.writerows(unlabeled_rows)


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_packet(src, dst, sport, dport, seq, ack, flags, payload=b"", ident=1):
    src_bytes = ipaddress.IPv4Address(src).packed
    dst_bytes = ipaddress.IPv4Address(dst).packed
    tcp_offset_flags = (5 << 12) | flags
    tcp_wo_sum = struct.pack("!HHIIHHHH", sport, dport, seq, ack,
                             tcp_offset_flags, 64240, 0, 0) + payload
    pseudo = src_bytes + dst_bytes + struct.pack("!BBH", 0, 6, len(tcp_wo_sum))
    tcp_sum = checksum(pseudo + tcp_wo_sum)
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack,
                      tcp_offset_flags, 64240, tcp_sum, 0) + payload
    total_len = 20 + len(tcp)
    ip_wo_sum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident,
                            0x4000, 64, 6, 0, src_bytes, dst_bytes)
    ip_sum = checksum(ip_wo_sum)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident,
                     0x4000, 64, 6, ip_sum, src_bytes, dst_bytes)
    # Locally administered synthetic MAC addresses.
    src_mac = bytes.fromhex("020000000001")
    dst_mac = bytes.fromhex("020000000002")
    return dst_mac + src_mac + b"\x08\x00" + ip + tcp


def tls_like_record(rng, size):
    body_size = max(1, size - 5)
    return b"\x17\x03\x03" + struct.pack("!H", body_size) + rng.randbytes(body_size)


def pcap_packet_list():
    rng = random.Random(42671)
    events = []
    ident = 1
    base = 1_735_689_600  # 2025-01-01 UTC

    def emit(offset, src, dst, sport, dport, seq, ack, flags, payload=b""):
        nonlocal ident
        frame = tcp_packet(src, dst, sport, dport, seq, ack, flags, payload, ident)
        events.append((base + offset, frame))
        ident += 1

    # Ordinary bidirectional TLS-like sessions with modest data exchanges.
    t = 0.0
    for flow in range(52):
        src = f"192.168.10.{10 + flow}"
        dst = f"203.0.113.{10 + flow}"
        sport, dport = 40000 + flow, 443 if flow % 5 else 8443
        client_seq, server_seq = rng.randrange(100000, 800000), rng.randrange(100000, 800000)
        now = t + rng.uniform(.1, .8)
        emit(now, src, dst, sport, dport, client_seq, 0, 0x02)  # SYN
        emit(now + .010, dst, src, dport, sport, server_seq, client_seq + 1, 0x12)  # SYN/ACK
        emit(now + .016, src, dst, sport, dport, client_seq + 1, server_seq + 1, 0x10)  # ACK
        cseq, sseq = client_seq + 1, server_seq + 1
        data_count = rng.randint(5, 20)
        for j in range(data_count):
            size = rng.randint(180, 1150)
            payload = tls_like_record(rng, size)
            emit(now + .03 + j * rng.uniform(.012, .055), src, dst, sport, dport,
                 cseq, sseq, 0x18, payload)
            cseq += len(payload)
            if j % 3 == 1:
                reply = tls_like_record(rng, rng.randint(90, 700))
                emit(now + .04 + j * .06, dst, src, dport, sport, sseq, cseq, 0x18, reply)
                sseq += len(reply)
        emit(now + 1.2, src, dst, sport, dport, cseq, sseq, 0x11)
        emit(now + 1.21, dst, src, dport, sport, sseq, cseq + 1, 0x11)
        t += rng.uniform(1.2, 2.5)

    # One host probing many destination ports; only synthetic test addresses.
    scanner = "192.168.10.250"
    target = "203.0.113.250"
    for idx, dport in enumerate([21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 8080]):
        sport = 51000 + idx
        seq = 900000 + idx * 100
        now = t + idx * .025
        emit(now, scanner, target, sport, dport, seq, 0, 0x02)
        emit(now + .007, target, scanner, dport, sport, 720000 + idx * 100, seq + 1, 0x14)
    t += 1.0

    # A large one-way synthetic TLS-like transfer candidate.
    src, dst, sport, dport = "192.168.10.249", "203.0.113.249", 52111, 443
    cseq, sseq = 300000, 500000
    now = t + .2
    emit(now, src, dst, sport, dport, cseq, 0, 0x02)
    emit(now + .01, dst, src, dport, sport, sseq, cseq + 1, 0x12)
    emit(now + .02, src, dst, sport, dport, cseq + 1, sseq + 1, 0x10)
    cseq += 1
    for j in range(180):
        payload = tls_like_record(rng, rng.randint(1050, 1300))
        emit(now + .05 + j * .004, src, dst, sport, dport, cseq, sseq, 0x18, payload)
        cseq += len(payload)
    emit(now + 1.0, src, dst, sport, dport, cseq, sseq, 0x11)

    # Sort to maintain capture order. Timestamps are encoded with microseconds.
    events.sort(key=lambda pair: pair[0])
    return events


def write_pcap():
    events = pcap_packet_list()
    with (ROOT / "demo_encrypted_traffic.pcap").open("wb") as f:
        # Little-endian classic PCAP, Ethernet link type.
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for stamp, frame in events:
            sec = int(stamp)
            usec = int((stamp - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)


if __name__ == "__main__":
    write_csvs()
    write_pcap()
    print("Created synthetic demo CSVs and PCAP under", ROOT)
