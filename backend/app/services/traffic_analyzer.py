"""Deterministic analytics derived exclusively from captured/imported metadata."""
from __future__ import annotations

from collections import Counter, defaultdict
import math

from .flow_tracker import track_flows


def overview(packets: list[dict], session=None) -> dict:
    count = len(packets)
    lengths = [int(packet.get("length", 0)) for packet in packets]
    total = sum(lengths)
    times = [float(packet["timestamp"]) for packet in packets]
    duration = max(max(times) - min(times), 1.0) if times else 1.0
    directions = Counter(packet.get("direction", "unknown") for packet in packets)
    tracked = track_flows(packets)
    return {"total_packets": count, "total_bytes": total,
            "average_size": round(total / count, 2) if count else 0,
            "min_size": min(lengths, default=0), "max_size": max(lengths, default=0),
            "packets_per_second": round(count / duration, 2),
            "bytes_per_second": round(total / duration, 2),
            "active_flows": sum(flow["state"] != "closed" for flow in tracked),
            "total_flows": len(tracked), "incoming": directions["incoming"],
            "outgoing": directions["outgoing"],
            "unknown": directions["unknown"], "loopback": directions["loopback"],
            "duration": round(duration, 6) if count else 0,
            "rate_basis": "capture span, minimum one second", "session": session}


def protocols(packets: list[dict]) -> list[dict]:
    groups = defaultdict(lambda: {"count": 0, "bytes": 0})
    for packet in packets:
        group = groups[packet.get("protocol", "OTHER")]
        group["count"] += 1
        group["bytes"] += int(packet.get("length", 0))
    count = len(packets)
    return sorted(({"protocol": protocol, **group,
                    "percentage": round(group["count"] / count * 100, 2)}
                   for protocol, group in groups.items()), key=lambda group: group["count"], reverse=True)


def bandwidth(packets: list[dict]) -> list[dict]:
    if not packets:
        return []
    first = math.floor(min(float(p["timestamp"]) for p in packets))
    last = math.floor(max(float(p["timestamp"]) for p in packets))
    # At most 600 chart points, including idle periods. Width is reported so
    # clients can display bytes/packets per second for aggregated intervals.
    width = max(1, math.ceil((last - first + 1) / 600))
    buckets = {stamp: {"timestamp": stamp, "packets": 0, "bytes": 0, "interval_seconds": width}
               for stamp in range(first, last + 1, width)}
    for packet in packets:
        stamp = first + (math.floor(float(packet["timestamp"])) - first) // width * width
        buckets[stamp]["packets"] += 1
        buckets[stamp]["bytes"] += int(packet.get("length", 0))
    return list(buckets.values())


def devices(packets: list[dict]) -> list[dict]:
    groups: dict[str, dict] = {}
    for packet in packets:
        for side, opposite in (("src", "sent"), ("dst", "received")):
            ip = packet.get(f"{side}_ip")
            if not ip:
                continue
            if ip not in groups:
                groups[ip] = {"ip": ip, "macs": set(), "packets": 0, "bytes": 0,
                              "sent_packets": 0, "received_packets": 0, "sent_bytes": 0,
                              "received_bytes": 0}
            group = groups[ip]
            mac = packet.get(f"{side}_mac")
            if mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                group["macs"].add(mac)
            group[f"{opposite}_packets"] += 1
            group[f"{opposite}_bytes"] += int(packet.get("length", 0))
            # A loopback packet touches the device once, while both directional
            # counters correctly record its source and destination roles.
            if side != "dst" or ip != packet.get("src_ip"):
                group["packets"] += 1
                group["bytes"] += int(packet.get("length", 0))
    return sorted(({**group, "macs": sorted(group["macs"])} for group in groups.values()),
                  key=lambda group: group["bytes"], reverse=True)


def flows(packets: list[dict]) -> list[dict]:
    return track_flows(packets)


def sizes(packets: list[dict]) -> list[dict]:
    bins = [("0–64 B", 64), ("65–128 B", 128), ("129–256 B", 256),
            ("257–512 B", 512), ("513–1024 B", 1024), ("1025–1518 B", 1518),
            ("1519+ B", float("inf"))]
    counts = {label: 0 for label, _ in bins}
    for packet in packets:
        for label, upper in bins:
            if int(packet.get("length", 0)) <= upper:
                counts[label] += 1
                break
    return [{"range": label, "count": count} for label, count in counts.items()]


def vlans(packets: list[dict]) -> list[dict]:
    groups = defaultdict(lambda: {"packets": 0, "bytes": 0})
    for packet in packets:
        group = groups[packet.get("vlan_id")]
        group["packets"] += 1
        group["bytes"] += int(packet.get("length", 0))
    return [{"vlan_id": vlan_id, **group} for vlan_id, group in
            sorted(groups.items(), key=lambda item: -item[1]["bytes"])]
