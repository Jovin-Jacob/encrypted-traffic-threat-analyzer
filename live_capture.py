"""Local live flow capture. Packet payloads are inspected only for length and discarded."""

from __future__ import annotations

import ipaddress
import threading
import time
from datetime import datetime, timezone


class LiveFlowMonitor:
    """Capture packets on one local interface and retain bounded flow summaries."""

    def __init__(self, interface: str, max_minutes: int = 10, max_flows: int = 5000):
        self.interface = interface
        self.max_minutes = max(1, min(int(max_minutes), 60))
        self.max_flows = max_flows
        self._lock = threading.RLock()
        self._flows: dict[tuple, dict] = {}
        self._sniffer = None
        self._timer = None
        self._stop_requested = threading.Event()
        self._started_at = None
        self._error = None
        self._packet_total = 0
        self._flow_sequence = 0
        self._layers = None
        self._timed_out = False

    def start(self):
        try:
            from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, Raw
        except Exception as exc:
            raise RuntimeError("Scapy could not load. Reinstall the project requirements.") from exc
        self._layers = (IP, IPv6, TCP, UDP, Raw)
        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._on_packet,
                store=False,
                filter="ip or ip6",
            )
            self._sniffer.start()
        except Exception as exc:
            raise RuntimeError(
                "Could not start capture on this interface. On Windows, check that Npcap is installed, "
                "select an active network interface, and run the app as administrator. "
                f"Capture detail: {exc}"
            ) from exc
        self._started_at = time.time()
        self._timer = threading.Timer(self.max_minutes * 60, self._stop_at_limit)
        self._timer.daemon = True
        self._timer.start()

    def _stop_at_limit(self):
        self._timed_out = True
        self.stop()

    @property
    def is_running(self):
        sniffer = self._sniffer
        try:
            return bool(sniffer and sniffer.running and not self._stop_requested.is_set())
        except Exception:
            return False

    @property
    def error(self):
        with self._lock:
            return self._error

    @property
    def timed_out(self):
        return self._timed_out

    def stop(self):
        self._stop_requested.set()
        timer = self._timer
        if timer and timer is not threading.current_thread():
            timer.cancel()
        sniffer = self._sniffer
        if sniffer:
            try:
                if sniffer.running:
                    sniffer.stop(join=True)
            except Exception as exc:
                with self._lock:
                    self._error = self._error or f"Capture stopped with a warning: {exc}"

    def _on_packet(self, packet):
        try:
            if self._stop_requested.is_set():
                return
            IP, IPv6, TCP, UDP, Raw = self._layers
            layer = IP if packet.haslayer(IP) else IPv6 if packet.haslayer(IPv6) else None
            if layer is None:
                return
            src, dst = str(packet[layer].src), str(packet[layer].dst)
            if packet.haslayer(TCP):
                sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
                proto, flags = "TCP", int(packet[TCP].flags)
            elif packet.haslayer(UDP):
                sport, dport = int(packet[UDP].sport), int(packet[UDP].dport)
                proto, flags = "UDP", 0
            else:
                sport = dport = 0
                proto, flags = str(getattr(packet[layer], "nh", getattr(packet[layer], "proto", "IP"))), 0

            endpoint_a, endpoint_b = (src, sport), (dst, dport)
            left, right = sorted((endpoint_a, endpoint_b))
            key = (left, right, proto)
            now = float(packet.time)
            packet_size = int(len(packet))
            payload_size = len(bytes(packet[Raw].load)) if packet.haslayer(Raw) else 0
            outgoing = self._is_local_address(src) and not self._is_local_address(dst)
            incoming = self._is_local_address(dst) and not self._is_local_address(src)

            with self._lock:
                flow = self._flows.get(key)
                if flow is None:
                    self._flow_sequence += 1
                    flow = {
                        "flow_id": f"LIVE-{self._flow_sequence:06d}",
                        "source_ip": left[0], "source_port": left[1],
                        "destination_ip": right[0], "destination_port": right[1],
                        "protocol": proto, "start_time": now, "end_time": now,
                        "packet_count": 0, "total_bytes": 0, "forward_packets": 0,
                        "reverse_packets": 0, "forward_bytes": 0, "reverse_bytes": 0,
                        "payload_bytes": 0, "syn_count": 0, "ack_count": 0,
                        "rst_count": 0, "fin_count": 0, "_sum_packet_size": 0,
                        "_sum_packet_size_squared": 0, "_last_packet_time": now,
                        "outbound_bytes": 0, "inbound_bytes": 0,
                        "direction": "unclassified", "internal_ip": "", "remote_ip": "",
                        "remote_port": 0,
                    }
                    self._flows[key] = flow
                forward = endpoint_a == left
                flow["packet_count"] += 1
                flow["total_bytes"] += packet_size
                flow["payload_bytes"] += payload_size
                flow["start_time"] = min(flow["start_time"], now)
                flow["end_time"] = max(flow["end_time"], now)
                flow["_sum_packet_size"] += packet_size
                flow["_sum_packet_size_squared"] += packet_size * packet_size
                direction = "forward" if forward else "reverse"
                flow[f"{direction}_packets"] += 1
                flow[f"{direction}_bytes"] += packet_size
                if outgoing:
                    flow["outbound_bytes"] += packet_size
                    flow.update(internal_ip=src, remote_ip=dst, remote_port=dport)
                    if flow["direction"] in {"unclassified", "local"}:
                        flow["direction"] = "outgoing"
                elif incoming:
                    flow["inbound_bytes"] += packet_size
                    flow.update(internal_ip=dst, remote_ip=src, remote_port=sport)
                    if flow["direction"] in {"unclassified", "local"}:
                        flow["direction"] = "incoming"
                elif self._is_local_address(src) and self._is_local_address(dst):
                    flow["direction"] = "local"
                if proto == "TCP":
                    flow["syn_count"] += int(bool(flags & 0x02))
                    flow["ack_count"] += int(bool(flags & 0x10))
                    flow["rst_count"] += int(bool(flags & 0x04))
                    flow["fin_count"] += int(bool(flags & 0x01))
                self._packet_total += 1
                if self._packet_total % 500 == 0:
                    cutoff = now - 600
                    stale = [k for k, v in self._flows.items() if v["end_time"] < cutoff]
                    for stale_key in stale:
                        self._flows.pop(stale_key, None)
                    overflow = len(self._flows) - self.max_flows
                    if overflow > 0:
                        oldest = sorted(self._flows, key=lambda k: self._flows[k]["end_time"])[:overflow]
                        for old_key in oldest:
                            self._flows.pop(old_key, None)
        except Exception as exc:
            with self._lock:
                self._error = f"A packet could not be summarized: {exc}"

    @staticmethod
    def _is_local_address(address):
        try:
            return not ipaddress.ip_address(address).is_global
        except ValueError:
            return False

    def snapshot(self):
        with self._lock:
            rows = []
            for flow in self._flows.values():
                item = dict(flow)
                packets = max(1, item["packet_count"])
                duration = max(0.0, item["end_time"] - item["start_time"])
                mean_size = item["_sum_packet_size"] / packets
                variance = max(0.0, item["_sum_packet_size_squared"] / packets - mean_size ** 2)
                item["duration_seconds"] = duration
                item["mean_packet_size"] = mean_size
                item["std_packet_size"] = variance ** 0.5
                item["mean_interarrival_seconds"] = duration / max(1, packets - 1)
                item["start_time_utc"] = datetime.fromtimestamp(item["start_time"], timezone.utc).isoformat(timespec="seconds")
                for key in ("_sum_packet_size", "_sum_packet_size_squared", "_last_packet_time"):
                    item.pop(key, None)
                rows.append(item)
            rows.sort(key=lambda row: row["end_time"], reverse=True)
            return {
                "flows": rows,
                "packet_total": self._packet_total,
                "flow_total": len(self._flows),
                "started_at": self._started_at,
                "is_running": self.is_running,
                "error": self._error,
                "timed_out": self._timed_out,
            }
