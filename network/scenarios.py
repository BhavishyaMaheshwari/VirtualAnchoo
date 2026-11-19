"""Run real ping experiments, record output, then restore the original policy.

This command changes only the opted-in lab. Expected outcomes are assertions,
not observations; actual results always come from ping's exit code and output.
"""
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
from .client import request
from .schema import validate_rule


def run() -> dict:
    before = request("inspect")
    records = []
    def observe(name, source, destination, expected):
        result = request("test", {"source": source, "destination": destination, "count": 3})
        records.append({"scenario": name, "expected_reachable": expected, "actual": result,
                        "matches_expectation": result["success"] == expected})
    try:
        request("routing", {"enabled": False})
        request("configure", {"vlans": before["vlans"], "rules": []})
        observe("Same VLAN connectivity", "eng1", "eng2", True)
        observe("Inter-VLAN isolation without routing", "eng1", "adm1", False)
        request("routing", {"enabled": True})
        observe("Inter-VLAN routing", "eng1", "adm1", True)
        rules = [validate_rule({"id": "experiment-eng-admin", "source_vlan": 10, "destination_vlan": 30, "action": "allow"}),
                 validate_rule({"id": "experiment-fin-eng", "source_vlan": 20, "destination_vlan": 10, "action": "deny"}),
                 validate_rule({"id": "experiment-admin-fin", "source_vlan": 30, "destination_vlan": 20, "action": "allow"})]
        request("configure", {"vlans": before["vlans"], "rules": rules})
        observe("ACL permits Engineering to Administration", "eng1", "adm1", True)
        observe("ACL denies Finance to Engineering", "fin1", "eng1", False)
        observe("ACL permits Administration to Finance", "adm1", "fin1", True)
        # A fresh ping process uses a fresh echo identifier; established ICMP replies
        # are stateful, while this new conversation is denied by the specific rule.
        rules.append(validate_rule({"id": "experiment-icmp-deny", "source_vlan": 10, "destination_vlan": 30,
                                    "protocol": "icmp", "action": "deny"}))
        request("configure", {"vlans": before["vlans"], "rules": rules})
        observe("Independent ICMP control", "eng2", "adm2", False)
        state = request("inspect")
    finally:
        request("routing", {"enabled": False})
        request("configure", {"vlans": before["vlans"], "rules": before["rules"]})
        request("routing", {"enabled": before["routing_enabled"]})
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "provenance": "Actual Mininet host ping commands",
            "all_matched": all(r["matches_expectation"] for r in records), "results": records,
            "observed_ovs_ports": state["ovs_ports"], "observed_firewall": state["firewall"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="data/experiments/network-results.json")
    args = parser.parse_args()
    report = run()
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["all_matched"] else 1)

if __name__ == "__main__":
    main()
