"""Bounded metadata extraction from genuine Scapy packets.

No application payloads are retained. HTTP/TLS recognition is deliberately
conservative; port-based labels are recorded as heuristics, not decryption.
"""
from __future__ import annotations

import math
import time
from typing import Any

from scapy.all import ARP, BOOTP, DHCP, DNS, Dot1Q, Ether, ICMP, IP, IPv6, TCP, UDP


def _text(value: Any, limit: int = 256) -> str:
    if isinstance(value, bytes):
        return value[:limit].decode("utf-8", errors="replace").rstrip("\x00")
    return str(value)[:limit]


def _integer(value: Any, default: int | None = None) -> int | None:
    try:
        return int(value) if value is not None else default
    except (ValueError, TypeError, OverflowError):
        return default


def _dns_records(records: Any, count: int, *, answers: bool = False) -> list[dict]:
    result = []
    # Scapy 2.6 exposes lists; older captures may use a linked payload chain.
    for index in range(min(count, 16)):
        try:
            record = records[index]
            item = {"name": _text(record.rrname if answers else record.qname),
                    "type": _integer(record.type if answers else record.qtype)}
            if answers:
                item.update(ttl=_integer(record.ttl), data=_text(record.rdata))
            result.append(item)
        except (AttributeError, IndexError, TypeError):
            break
    return result


def parse_packet(packet: Any, interface: str = "pcap", local_ips: set | None = None,
                 local_macs: set | None = None) -> dict:
    """Extract JSON-safe metadata, tolerating missing/truncated protocol layers.

    ``timestamp`` is UNIX seconds, not processing time. ``protocol`` is an
    application label where identifiable; ``transport_protocol`` drives flows.
    Direction remains unknown unless a local address is supplied by capture.
    """
    errors: list[str] = []
    try:
        timestamp = float(packet.time)
        if not math.isfinite(timestamp):
            raise ValueError("non-finite timestamp")
    except (AttributeError, TypeError, ValueError, OverflowError):
        timestamp = time.time()
        errors.append("Packet timestamp unavailable; used processing time")
    try:
        length = len(packet)
    except Exception:
        length = 0
        errors.append("Packet length unavailable")
    result = {"timestamp": timestamp, "src_ip": None, "dst_ip": None,
              "src_mac": None, "dst_mac": None, "protocol": "OTHER",
              "transport_protocol": "OTHER", "length": length,
              "src_port": None, "dst_port": None, "vlan_id": None,
              "info": "Unrecognized or non-IP packet", "direction": "unknown",
              "interface": interface, "layers": {}}
    layers = result["layers"]
    network_layer = None
    transport_layer = None
    current = packet
    for _ in range(32):
        if isinstance(current, (IP, IPv6, ARP)):
            network_layer = current
            break
        following = getattr(current, "payload", None)
        if following is None or following is current:
            break
        current = following
    current = getattr(network_layer, "payload", None)
    for _ in range(16):
        if isinstance(current, (TCP, UDP, ICMP)) or type(current).__name__.startswith("ICMPv6"):
            transport_layer = current
            break
        if not type(current).__name__.startswith("IPv6ExtHdr"):
            break
        current = getattr(current, "payload", None)

    def extract(name: str, callback):
        try:
            callback()
        except Exception as exc:
            errors.append(f"{name}: {type(exc).__name__}")

    def ethernet():
        if Ether in packet:
            layer = packet[Ether]
            result.update(src_mac=layer.src, dst_mac=layer.dst)
            layers["Ethernet"] = {"source": layer.src, "destination": layer.dst,
                                  "ethertype": _integer(layer.type)}

    def vlan():
        current = packet
        tags = []
        for _ in range(32):
            if isinstance(current, Dot1Q):
                tags.append({"vlan_id": int(current.vlan), "pcp": int(current.prio),
                             "dei": int(current.dei), "ethertype": int(current.type)})
            following = getattr(current, "payload", None)
            if following is None or following is current:
                break
            current = following
        if tags:
            result["vlan_id"] = tags[-1]["vlan_id"]
            layers["802.1Q"] = {**tags[-1], "tags": tags}

    def network():
        if isinstance(network_layer, IP):
            layer = network_layer
            result.update(src_ip=layer.src, dst_ip=layer.dst, protocol="IPv4",
                          transport_protocol="IPv4")
            layers["IPv4"] = {"source": layer.src, "destination": layer.dst,
                              "version": 4, "ttl": _integer(layer.ttl),
                              "header_length": int(layer.ihl) * 4 if layer.ihl else None,
                              "total_length": _integer(layer.len), "id": _integer(layer.id),
                              "flags": str(layer.flags), "fragment_offset": _integer(layer.frag),
                              "protocol_number": _integer(layer.proto),
                              "checksum": _integer(layer.chksum)}
            result["info"] = f"IPv4 {layer.src} → {layer.dst}"
        elif isinstance(network_layer, IPv6):
            layer = network_layer
            result.update(src_ip=layer.src, dst_ip=layer.dst, protocol="IPv6",
                          transport_protocol="IPv6")
            layers["IPv6"] = {"source": layer.src, "destination": layer.dst,
                              "version": 6, "hop_limit": _integer(layer.hlim),
                              "payload_length": _integer(layer.plen),
                              "next_header": _integer(layer.nh),
                              "traffic_class": _integer(layer.tc), "flow_label": _integer(layer.fl)}
            result["info"] = f"IPv6 {layer.src} → {layer.dst}"
        if isinstance(network_layer, ARP):
            layer = network_layer
            result.update(src_ip=layer.psrc, dst_ip=layer.pdst, src_mac=layer.hwsrc,
                          dst_mac=layer.hwdst, protocol="ARP", transport_protocol="ARP")
            layers["ARP"] = {"sender_ip": layer.psrc, "target_ip": layer.pdst,
                             "sender_mac": layer.hwsrc, "target_mac": layer.hwdst,
                             "operation": _integer(layer.op)}
            result["info"] = (f"Who has {layer.pdst}? Tell {layer.psrc}" if layer.op == 1
                              else f"{layer.psrc} is at {layer.hwsrc}")

    def transport():
        if isinstance(transport_layer, TCP):
            layer = transport_layer
            result.update(protocol="TCP", transport_protocol="TCP", src_port=int(layer.sport),
                          dst_port=int(layer.dport))
            try:
                payload_length = len(bytes(layer.payload))
            except Exception:
                payload_length = 0
            layers["TCP"] = {"source_port": int(layer.sport), "destination_port": int(layer.dport),
                             "sequence": _integer(layer.seq), "acknowledgment": _integer(layer.ack),
                             "flags": str(layer.flags), "window": _integer(layer.window),
                             "header_length": int(layer.dataofs) * 4 if layer.dataofs else None,
                             "payload_length": payload_length, "checksum": _integer(layer.chksum)}
            result["info"] = f"{layer.sport} → {layer.dport} [{layer.flags}] Seq={layer.seq} Ack={layer.ack}"
            ports = {int(layer.sport), int(layer.dport)}
            if 443 in ports or 8443 in ports:
                result["protocol"] = "HTTPS/TLS"
                layers["TLS"] = {"identification": "Port-based heuristic; TLS not decrypted",
                                 "encrypted": True,
                                 "note": "Encrypted application payload cannot be inspected without appropriate decryption access."}
                result["info"] = f"TLS candidate {layer.sport} → {layer.dport} · encrypted payload"
            elif 80 in ports or 8080 in ports:
                result["protocol"] = "HTTP"
                layers["HTTP"] = {"identification": "Port-based heuristic", "payload_stored": False}
        elif isinstance(transport_layer, UDP):
            layer = transport_layer
            result.update(protocol="UDP", transport_protocol="UDP", src_port=int(layer.sport),
                          dst_port=int(layer.dport))
            layers["UDP"] = {"source_port": int(layer.sport), "destination_port": int(layer.dport),
                             "length": _integer(layer.len), "checksum": _integer(layer.chksum)}
            result["info"] = f"{layer.sport} → {layer.dport} UDP"
        elif isinstance(transport_layer, ICMP):
            layer = transport_layer
            result.update(protocol="ICMP", transport_protocol="ICMP")
            layers["ICMP"] = {"type": _integer(layer.type), "code": _integer(layer.code),
                              "id": _integer(getattr(layer, "id", None)),
                              "sequence": _integer(getattr(layer, "seq", None))}
            result["info"] = f"ICMP type={layer.type} code={layer.code}"
        else:
            if type(transport_layer).__name__.startswith("ICMPv6"):
                result.update(protocol="ICMPv6", transport_protocol="ICMPv6")
                layers["ICMPv6"] = {"type": _integer(transport_layer.type), "code": _integer(transport_layer.code)}
                result["info"] = f"ICMPv6 type={transport_layer.type} code={transport_layer.code}"

    def application():
        payload = getattr(transport_layer, "payload", None)
        if isinstance(payload, DNS):
            layer = payload
            questions = _dns_records(layer.qd, _integer(layer.qdcount, len(layer.qd)) or 0)
            answers = _dns_records(layer.an, _integer(layer.ancount, len(layer.an)) or 0, answers=True)
            result["protocol"] = "DNS"
            layers["DNS"] = {"id": _integer(layer.id), "is_response": bool(layer.qr),
                             "response_code": _integer(layer.rcode), "questions": questions,
                             "answers": answers, "answer_count": _integer(layer.ancount, len(answers)),
                             "query_name": questions[0]["name"] if questions else None,
                             "query_type": questions[0]["type"] if questions else None}
            name = questions[0]["name"] if questions else "(no question)"
            result["info"] = f"DNS {'response' if layer.qr else 'query'} {name}"
        if isinstance(payload, BOOTP):
            result["protocol"] = "DHCP"
            layer = payload
            options = {}
            if DHCP in payload:
                for option in payload[DHCP].options[:32]:
                    if isinstance(option, tuple) and len(option) >= 2:
                        options[_text(option[0])] = _text(option[1])
            layers["DHCP"] = {"options": options}
            if layer is not None:
                layers["DHCP"].update(operation=_integer(layer.op), transaction_id=_integer(layer.xid),
                                      client_ip=layer.ciaddr, offered_ip=layer.yiaddr)
            result["info"] = f"DHCP {options.get('message-type', 'BOOTP')}"

    for name, callback in [("Ethernet", ethernet), ("802.1Q", vlan), ("Network", network),
                           ("Transport", transport), ("Application", application)]:
        extract(name, callback)
    ips = local_ips or set()
    macs = {str(value).lower() for value in (local_macs or set())}
    source_local = result["src_ip"] in ips or str(result["src_mac"]).lower() in macs
    destination_local = result["dst_ip"] in ips or str(result["dst_mac"]).lower() in macs
    if source_local and destination_local:
        result["direction"] = "loopback"
    elif source_local:
        result["direction"] = "outgoing"
    elif destination_local:
        result["direction"] = "incoming"
    if errors:
        layers["Parse warnings"] = {"warnings": errors}
    return result
