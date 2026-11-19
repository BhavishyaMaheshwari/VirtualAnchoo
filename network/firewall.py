"""Manage only the lab router's nftables table through the local agent."""
import argparse
import json
import uuid
from .client import request
from . import store
from .schema import validate_rule, validate_rules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    subs.add_parser("list")
    add = subs.add_parser("add")
    add.add_argument("--source-vlan", type=int, required=True)
    add.add_argument("--destination-vlan", type=int, required=True)
    add.add_argument("--protocol", choices=["any", "icmp", "tcp", "udp"], default="any")
    add.add_argument("--destination-port", type=int)
    add.add_argument("--verdict", choices=["allow", "deny"], required=True)
    for name in ["remove", "enable", "disable"]:
        subs.add_parser(name).add_argument("id")
    args = parser.parse_args()
    state = request("inspect")
    rules = state["rules"]
    if args.action == "add":
        rules.append(validate_rule({"id": uuid.uuid4().hex, "source_vlan": args.source_vlan,
                                    "destination_vlan": args.destination_vlan, "protocol": args.protocol,
                                    "destination_port": args.destination_port, "action": args.verdict},
                                   {v["id"] for v in state["vlans"]}))
    elif args.action != "list":
        match = next((r for r in rules if r["id"] == args.id), None)
        if match is None:
            parser.error("Rule ID was not found")
        if args.action == "remove":
            rules = [r for r in rules if r["id"] != args.id]
        else:
            match["enabled"] = args.action == "enable"
    if args.action != "list":
        state = request("configure", {"vlans": state["vlans"], "rules": validate_rules(rules, state["vlans"])})
        store.save_rules(state["rules"])
    print(json.dumps({"rules": state["rules"], "firewall": state["firewall"]}, indent=2))

if __name__ == "__main__":
    main()
