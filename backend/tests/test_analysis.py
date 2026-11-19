"""Synthetic protocol fixtures are unit inputs, never dashboard telemetry."""
from __future__ import annotations

import json

import pytest
from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, Dot1Q, Ether, ICMP, IP, IPv6, Raw, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest

from backend.app.services.packet_parser import parse_packet
from backend.app.services.flow_tracker import FlowTracker, track_flows
from backend.app.services import traffic_analyzer as analytics


def dissect(packet, timestamp=100.0):
    # Serialize/reparse so Scapy computes real wire length/checksum fields.
    packet = packet.__class__(bytes(packet))
    packet.time = timestamp
    return parse_packet(packet)


def test_tcp_headers_and_unknown_direction():
    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
        src="192.0.2.1", dst="192.0.2.2", ttl=32, id=7, flags="DF") / TCP(
        sport=4444, dport=2222, seq=123, ack=42, flags="PA", window=1024) / Raw(b"secret")
    parsed = dissect(packet)
    assert parsed["protocol"] == "TCP"
    assert parsed["src_ip"] == "192.0.2.1"
    assert parsed["layers"]["IPv4"]["header_length"] == 20
    assert parsed["layers"]["IPv4"]["id"] == 7
    assert parsed["layers"]["IPv4"]["flags"] == "DF"
    assert parsed["layers"]["TCP"]["sequence"] == 123
    assert parsed["layers"]["TCP"]["payload_length"] == 6
    assert parsed["length"] == len(bytes(packet))
    assert parsed["direction"] == "unknown"
    assert "secret" not in json.dumps(parsed)


@pytest.mark.parametrize("packet,protocol", [
    (IP() / TCP(sport=40000, dport=80), "HTTP"),
    (IP() / TCP(sport=40000, dport=443), "HTTPS/TLS"),
    (IP() / UDP(sport=40000, dport=9999), "UDP"),
    (IP() / ICMP(type=8, code=0), "ICMP"),
    (IPv6(src="2001:db8::1", dst="2001:db8::2") / Raw(b"opaque"), "IPv6"),
    (IPv6(src="::1", dst="::1") / ICMPv6EchoRequest(), "ICMPv6"),
    (Ether() / ARP(psrc="192.0.2.1", pdst="192.0.2.2"), "ARP"),
    (IP() / UDP(sport=68, dport=67) / BOOTP() / DHCP(options=[("message-type", "discover"), "end"]), "DHCP"),
])
def test_protocol_identification(packet, protocol):
    assert dissect(packet)["protocol"] == protocol


def test_dns_question_and_answer():
    packet = IP() / UDP(sport=53, dport=12345) / DNS(
        id=77, qr=1, qd=DNSQR(qname="example.test", qtype="A"),
        an=DNSRR(rrname="example.test", type="A", rdata="192.0.2.4", ttl=30))
    parsed = dissect(packet)
    assert parsed["protocol"] == "DNS"
    assert parsed["transport_protocol"] == "UDP"
    dns = parsed["layers"]["DNS"]
    assert dns["query_name"] == "example.test."
    assert dns["answers"][0]["data"] == "192.0.2.4"
    assert dns["is_response"] is True
    assert dns["response_code"] == 0


def test_vlan_extracts_priority_dei_and_stacked_tags():
    packet = Ether() / Dot1Q(vlan=100, prio=2) / Dot1Q(vlan=20, prio=5, dei=1) / IP() / UDP()
    parsed = dissect(packet)
    assert parsed["vlan_id"] == 20
    vlan = parsed["layers"]["802.1Q"]
    assert vlan["pcp"] == 5
    assert vlan["dei"] == 1
    assert vlan["ethertype"] == 0x800
    assert [tag["vlan_id"] for tag in vlan["tags"]] == [100, 20]


def test_direction_requires_observed_local_addresses():
    packet = IP(src="192.0.2.1", dst="192.0.2.2") / UDP()
    assert parse_packet(packet, local_ips={"192.0.2.1"})["direction"] == "outgoing"
    assert parse_packet(packet, local_ips={"192.0.2.2"})["direction"] == "incoming"
    assert parse_packet(packet, local_ips={"192.0.2.1", "192.0.2.2"})["direction"] == "loopback"


def test_tls_is_not_plaintext():
    packet = IP() / TCP(dport=443) / Raw(b"password=must-not-appear")
    parsed = dissect(packet)
    assert parsed["layers"]["TLS"]["encrypted"] is True
    assert "Port-based" in parsed["layers"]["TLS"]["identification"]
    assert "password" not in json.dumps(parsed)


def test_unsupported_and_malformed_packets_are_safe():
    parsed = parse_packet(Raw(b"\x00\x01"))
    assert parsed["protocol"] == "OTHER"
    assert parsed["src_port"] is None
    json.dumps(parsed, allow_nan=False)
    truncated = parse_packet(IP(b"E\x00\x00\x28" + b"\x00" * 16))
    assert truncated["protocol"] == "IPv4"
    invalid_time = Raw(b"x")
    invalid_time.time = float("nan")
    assert "Parse warnings" in parse_packet(invalid_time)["layers"]


def sample_packets():
    outgoing = dissect(IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=4000, dport=9000, flags="PA", seq=10) / Raw(b"hello"), 100)
    incoming = dissect(IP(src="192.0.2.2", dst="192.0.2.1") / TCP(sport=9000, dport=4000, flags="A", ack=15), 102)
    outgoing["direction"] = "outgoing"
    incoming["direction"] = "incoming"
    return [outgoing, incoming]


def test_flow_combines_directions_and_counts_payload_retransmission():
    packets = sample_packets()
    retransmission = {**packets[0], "timestamp": 103}
    tracked = track_flows([*packets, retransmission])
    assert len(tracked) == 1
    flow = tracked[0]
    assert flow["packets"] == 3
    assert flow["duration"] == 3
    assert flow["retransmissions"] == 1
    assert flow["retransmitted_bytes"] == 5
    assert set(flow["tcp_flags"]) == {"P", "A"}
    assert flow["bytes"] == sum(p["length"] for p in [*packets, retransmission])


def test_zero_payload_ack_not_retransmission_and_state_closes():
    packets = sample_packets()
    finish = dissect(IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=4000, dport=9000, flags="FA"), 104)
    tracked = track_flows([*packets, packets[1], finish])
    assert tracked[0]["retransmissions"] == 0
    assert tracked[0]["state"] == "closed"
    assert analytics.overview([*packets, finish])["active_flows"] == 0


def test_flow_application_classification_does_not_split_transport():
    packets = sample_packets()
    packets[1]["protocol"] = "HTTP"
    assert len(track_flows(packets)) == 1
    assert set(track_flows(packets)[0]["application_protocols"]) == {"TCP", "HTTP"}


def test_retransmission_memory_is_bounded():
    tracker = FlowTracker(max_seen_segments=2)
    for sequence in range(4):
        tracker.add(dissect(IP() / TCP(seq=sequence) / Raw(b"x")))
    assert len(tracker._seen) == 2


def test_analytics_actual_counts_bytes_rates_and_bins():
    packets = sample_packets()
    summary = analytics.overview(packets, {"source": "import"})
    expected_bytes = sum(p["length"] for p in packets)
    assert summary["total_packets"] == 2
    assert summary["total_bytes"] == expected_bytes
    assert summary["average_size"] == expected_bytes / 2
    assert summary["packets_per_second"] == 1
    assert summary["incoming"] == summary["outgoing"] == 1
    assert analytics.protocols(packets) == [{"protocol": "TCP", "count": 2, "bytes": expected_bytes, "percentage": 100}]
    assert sum(row["count"] for row in analytics.sizes(packets)) == 2
    series = analytics.bandwidth(packets)
    assert len(series) == 3
    assert series[1]["packets"] == 0
    assert sum(row["bytes"] for row in series) == expected_bytes
    assert sum(row["packets"] for row in analytics.vlans(packets)) == 2
    devices = analytics.devices(packets)
    assert len(devices) == 2
    assert all(row["sent_packets"] == row["received_packets"] == 1 for row in devices)


def test_analytics_empty_input_and_long_capture_are_bounded():
    assert analytics.overview([])["total_packets"] == 0
    assert analytics.protocols([]) == analytics.bandwidth([]) == analytics.devices([]) == []
    packets = sample_packets()
    packets[1]["timestamp"] = 10_000_000
    series = analytics.bandwidth(packets)
    assert len(series) <= 600
    assert sum(row["packets"] for row in series) == 2


def test_loopback_device_not_double_counted():
    packet = dissect(IP(src="127.0.0.1", dst="127.0.0.1") / UDP())
    device = analytics.devices([packet])[0]
    assert device["packets"] == 1
    assert device["sent_packets"] == device["received_packets"] == 1


def test_arp_is_not_a_transport_flow():
    assert track_flows([dissect(Ether() / ARP())]) == []


def test_icmp_quoted_packet_does_not_change_outer_protocol():
    packet = IP(src="192.0.2.1", dst="192.0.2.2") / ICMP(type=3, code=3) / IP() / UDP() / DNS(qd=DNSQR(qname="example.test"))
    parsed = dissect(packet)
    assert parsed["protocol"] == "ICMP"
    assert parsed["src_port"] is None
    assert "DNS" not in parsed["layers"]


def test_tunneled_inner_ipv4_does_not_replace_outer_ipv6():
    packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / IP(src="192.0.2.1", dst="192.0.2.2") / TCP()
    parsed = dissect(packet)
    assert parsed["protocol"] == "IPv6"
    assert parsed["src_ip"] == "2001:db8::1"
    assert parsed["src_port"] is None
