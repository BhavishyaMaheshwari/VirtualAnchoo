"""Inspect actual OVS VLAN state or add an extra, initially hostless VLAN."""
import argparse
import json
from .client import request
from . import store
from .schema import validate_vlan, validate_vlans


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--add", type=int, metavar="VLAN_ID")
    parser.add_argument("--name")
    parser.add_argument("--subnet")
    args = parser.parse_args()
    state = request("inspect")
    if args.add is not None:
        new = validate_vlan({"id": args.add, "name": args.name, "subnet": args.subnet})
        existing = next((v for v in state["vlans"] if v["id"] == new["id"]), None)
        if existing and existing != new:
            parser.error("The VLAN exists with different settings; in-place subnet changes are unsupported")
        if not existing:
            vlans = validate_vlans(state["vlans"] + [new])
            state = request("configure", {"vlans": vlans, "rules": state["rules"]})
            if not any(v["id"] == new["id"] for v in store.get_vlans()):
                store.save_vlan(new)
    print(json.dumps(state, indent=2))

if __name__ == "__main__":
    main()
