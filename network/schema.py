"""Shared validation for the HTTP adapter and privileged lab agent.

Keep this module stdlib-only: Ubuntu's system Python supplies Mininet.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

DEFAULT_VLANS = [
    {"id": 10, "name": "Engineering", "subnet": "192.168.10.0/24"},
    {"id": 20, "name": "Finance", "subnet": "192.168.20.0/24"},
    {"id": 30, "name": "Administration", "subnet": "192.168.30.0/24"},
]
HOSTS = {
    "eng1": {"vlan_id": 10, "ip": "192.168.10.11", "mac": "02:00:00:10:00:11", "port": "ns-sw-eth1"},
    "eng2": {"vlan_id": 10, "ip": "192.168.10.12", "mac": "02:00:00:10:00:12", "port": "ns-sw-eth2"},
    "fin1": {"vlan_id": 20, "ip": "192.168.20.11", "mac": "02:00:00:20:00:11", "port": "ns-sw-eth3"},
    "fin2": {"vlan_id": 20, "ip": "192.168.20.12", "mac": "02:00:00:20:00:12", "port": "ns-sw-eth4"},
    "adm1": {"vlan_id": 30, "ip": "192.168.30.11", "mac": "02:00:00:30:00:11", "port": "ns-sw-eth5"},
    "adm2": {"vlan_id": 30, "ip": "192.168.30.12", "mac": "02:00:00:30:00:12", "port": "ns-sw-eth6"},
}
TRUNK = "ns-sw-eth7"
ROUTER_INTERFACE = "ns-r1-eth0"


def integer(value: Any, low: int, high: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{field} must be an integer from {low} to {high}")
    return value


def validate_vlan(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("VLAN must be an object")
    vlan_id = integer(data.get("id"), 1, 4094, "VLAN ID")
    name = data.get("name", "")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,47}", name):
        raise ValueError("VLAN name must contain 1–48 letters, digits, spaces, underscores or hyphens")
    subnet = ipaddress.ip_network(data.get("subnet", ""), strict=True)
    if subnet.version != 4 or not 16 <= subnet.prefixlen <= 29:
        raise ValueError("Lab subnet must be an IPv4 network with prefix /16 through /29")
    if not subnet.is_private or subnet.is_loopback or subnet.is_link_local or subnet.is_multicast:
        raise ValueError("Use a private, non-loopback IPv4 lab subnet")
    return {"id": vlan_id, "name": name, "subnet": str(subnet), "gateway": str(subnet.network_address + 1)}


def validate_vlans(items: list) -> list[dict]:
    if not isinstance(items, list) or not 1 <= len(items) <= 32:
        raise ValueError("Configure 1–32 VLANs")
    vlans = [validate_vlan(v) for v in items]
    for i, vlan in enumerate(vlans):
        for other in vlans[:i]:
            if vlan["id"] == other["id"]:
                raise ValueError("Duplicate VLAN ID")
            if ipaddress.ip_network(vlan["subnet"]).overlaps(ipaddress.ip_network(other["subnet"])):
                raise ValueError("VLAN subnets must not overlap")
    for default in DEFAULT_VLANS:
        matching = next((v for v in vlans if v["id"] == default["id"]), None)
        if matching is None or matching["subnet"] != default["subnet"]:
            raise ValueError("Keep example VLANs 10, 20 and 30 and their subnets; they own the fixed lab hosts")
    return vlans


def validate_rule(data: dict, vlan_ids: set[int] | None = None) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Rule must be an object")
    src = integer(data.get("source_vlan"), 1, 4094, "Source VLAN")
    dst = integer(data.get("destination_vlan"), 1, 4094, "Destination VLAN")
    if src == dst:
        raise ValueError("Router ACL rules must refer to different VLANs")
    if vlan_ids is not None and (src not in vlan_ids or dst not in vlan_ids):
        raise ValueError("Rule refers to an unconfigured VLAN")
    protocol = data.get("protocol", "any")
    action = data.get("action", "deny")
    if protocol not in {"any", "icmp", "tcp", "udp"} or action not in {"allow", "deny"}:
        raise ValueError("Invalid rule protocol or action")
    port = data.get("destination_port")
    if port is not None:
        integer(port, 1, 65535, "Destination port")
        if protocol not in {"tcp", "udp"}:
            raise ValueError("Destination ports require TCP or UDP")
    enabled = data.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean")
    description = data.get("description", "")
    if not isinstance(description, str) or len(description) > 200:
        raise ValueError("Description must be at most 200 characters")
    ident = data.get("id", "")
    if ident and (not isinstance(ident, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", ident)):
        raise ValueError("Invalid rule ID")
    return {"id": ident, "source_vlan": src, "destination_vlan": dst,
            "protocol": protocol, "destination_port": port, "action": action,
            "enabled": enabled, "description": description}


def validate_rules(items: list, vlans: list) -> list[dict]:
    if not isinstance(items, list) or len(items) > 128:
        raise ValueError("At most 128 rules are supported")
    rules = [validate_rule(x, {v["id"] for v in vlans}) for x in items]
    if len({r["id"] for r in rules}) != len(rules):
        raise ValueError("Rule IDs must be unique")
    return rules


def validate_test(data: dict) -> dict:
    source, destination = data.get("source"), data.get("destination")
    if source not in HOSTS or destination not in HOSTS:
        raise ValueError("Select an existing lab host: " + ", ".join(HOSTS))
    if source == destination:
        raise ValueError("Select two different hosts")
    count = integer(data.get("count", 3), 1, 5, "Ping count")
    return {"source": source, "destination": destination, "count": count}


def nft_ruleset(vlans: list, rules: list, *, existing: bool = False) -> str:
    """Compile strictly validated values to a router-namespace-only nft transaction.

    Reply traffic is stateful; rules constrain new inter-VLAN conversations.
    With enabled rules, the implicit policy is DROP. Without rules it is ACCEPT.
    """
    vlans = validate_vlans(vlans)
    rules = validate_rules(rules, vlans)
    networks = {v["id"]: v["subnet"] for v in vlans}
    enabled = [r for r in rules if r["enabled"]]
    lines = (["delete table inet netscope"] if existing else []) + [
        "table inet netscope {",
        "  chain forward {",
        f"    type filter hook forward priority 0; policy {'drop' if enabled else 'accept'};",
        "    ct state invalid drop",
        "    ct state established,related accept",
    ]
    for rule in sorted(enabled, key=lambda r: r["action"] != "deny"):
        fragment = f"    ip saddr {networks[rule['source_vlan']]} ip daddr {networks[rule['destination_vlan']]}"
        protocol = rule["protocol"]
        if protocol != "any":
            fragment += f" ip protocol {protocol}"
        if rule["destination_port"] is not None:
            fragment += f" {protocol} dport {rule['destination_port']}"
        fragment += " counter " + ("accept" if rule["action"] == "allow" else "drop")
        lines.append(fragment)
    lines.extend(["  }", "}"])
    return "\n".join(lines) + "\n"
