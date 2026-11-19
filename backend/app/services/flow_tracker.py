"""Bidirectional transport flow tracking with bounded retransmission heuristics.

Five-tuples are aggregated for an entire capture session (no inactivity timeout).
Retransmissions count repeated TCP payload sequence/length pairs per direction;
they are estimates and can include duplicated interface captures.
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib


class FlowTracker:
    def __init__(self, max_seen_segments: int = 100_000):
        self._flows: dict[tuple, dict] = {}
        self._seen: OrderedDict[tuple, None] = OrderedDict()
        self.max_seen_segments = max_seen_segments

    def add(self, packet: dict) -> dict | None:
        source, destination = packet.get("src_ip"), packet.get("dst_ip")
        if not source or not destination:
            return None
        protocol = packet.get("transport_protocol") or packet.get("protocol", "OTHER")
        if protocol == "ARP":
            return None
        left = (source, packet.get("src_port") or 0)
        right = (destination, packet.get("dst_port") or 0)
        key = (*sorted((left, right)), protocol)
        timestamp = float(packet["timestamp"])
        flow = self._flows.get(key)
        if flow is None:
            flow = {"id": hashlib.sha256(repr(key).encode()).hexdigest()[:16],
                    "src_ip": source, "dst_ip": destination,
                    "src_port": packet.get("src_port"), "dst_port": packet.get("dst_port"),
                    "protocol": protocol, "start_time": timestamp, "end_time": timestamp,
                    "duration": 0.0, "packets": 0, "bytes": 0, "tcp_flags": [],
                    "application_protocols": [], "retransmissions": 0,
                    "retransmitted_bytes": 0, "state": "observed"}
            self._flows[key] = flow
        flow["start_time"] = min(flow["start_time"], timestamp)
        flow["end_time"] = max(flow["end_time"], timestamp)
        flow["duration"] = round(flow["end_time"] - flow["start_time"], 6)
        flow["packets"] += 1
        flow["bytes"] += int(packet.get("length", 0))
        application = packet.get("protocol", protocol)
        if application not in flow["application_protocols"]:
            flow["application_protocols"].append(application)
        tcp = packet.get("layers", {}).get("TCP", {})
        flags = str(tcp.get("flags", ""))
        for flag in flags:
            if flag not in flow["tcp_flags"]:
                flow["tcp_flags"].append(flag)
        if "R" in flags or "F" in flags:
            flow["state"] = "closed"
        elif protocol == "TCP" and flow["state"] != "closed":
            flow["state"] = "open"
        payload_length = int(tcp.get("payload_length") or 0)
        if protocol == "TCP" and payload_length > 0 and tcp.get("sequence") is not None:
            segment = (key, left, int(tcp["sequence"]), payload_length)
            if segment in self._seen:
                flow["retransmissions"] += 1
                flow["retransmitted_bytes"] += payload_length
                self._seen.move_to_end(segment)
            else:
                self._seen[segment] = None
                if len(self._seen) > self.max_seen_segments:
                    self._seen.popitem(last=False)
        return flow

    def results(self) -> list[dict]:
        return sorted(self._flows.values(), key=lambda row: row["bytes"], reverse=True)


def track_flows(packets) -> list[dict]:
    tracker = FlowTracker()
    for packet in packets:
        tracker.add(packet)
    return tracker.results()
