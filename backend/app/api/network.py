"""Unprivileged HTTP adapter for the explicit local VLAN lab agent."""
from __future__ import annotations
from pathlib import Path
import sys
import threading
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

# Support both `uvicorn backend.app.main:app` and execution from backend/.
_PROJECT = str(Path(__file__).resolve().parents[3])
if _PROJECT not in sys.path:
    sys.path.insert(0, _PROJECT)
from network import client, store
from network.schema import HOSTS, TRUNK, validate_vlan, validate_vlans, validate_rule, validate_rules, validate_test

router = APIRouter(prefix="/api", tags=["VLAN laboratory"])
_MUTATION = threading.RLock()


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

class VlanInput(Input):
    id: int = Field(ge=1, le=4094)
    name: str = Field(min_length=1, max_length=48)
    subnet: str

class RuleInput(Input):
    source_vlan: int = Field(ge=1, le=4094)
    destination_vlan: int = Field(ge=1, le=4094)
    protocol: str = "any"
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    action: str = "deny"
    enabled: bool = True
    description: str = Field(default="", max_length=200)

class EnableInput(Input):
    enabled: bool

class TestInput(Input):
    source: str
    destination: str
    count: int = Field(default=3, ge=1, le=5)


def _invoke(operation, payload=None):
    try:
        return client.request(operation, payload)
    except client.LabUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except client.LabError as exc:
        raise HTTPException(502, str(exc)) from exc


def _status():
    try:
        return client.request("inspect")
    except (client.LabUnavailable, client.LabError) as exc:
        return {"available": False, "running": False, "routing_enabled": False,
                "message": str(exc), "vlans": [], "rules": []}


def _validated(function, *args):
    try:
        return function(*args)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc


def _vlans(status):
    active = {v["id"] for v in status.get("vlans", [])} if status.get("running") else set()
    result = []
    planned = {v["id"]: v for v in store.get_vlans()}
    for live in status.get("vlans", []):
        planned[live["id"]] = live
    for vlan in sorted(planned.values(), key=lambda v: v["id"]):
        hosts = [{"name": name, **values} for name, values in HOSTS.items() if values["vlan_id"] == vlan["id"]]
        result.append({**vlan, "hosts": hosts, "ports": [h["port"] for h in hosts],
                       "status": "active" if vlan["id"] in active else "planned", "mode": "access", "trunk": TRUNK})
    return result


def _rules(status):
    applied = {r["id"]: r for r in status.get("rules", [])} if status.get("running") else {}
    desired = {r["id"]: r for r in store.get_rules()}
    # Include observed agent rules even when an independent operator changed the lab.
    for ident, rule in applied.items():
        desired.setdefault(ident, rule)
    return [{**r, "applied": applied.get(r["id"]) == r} for r in desired.values()]


def _apply_if_online(vlans, rules):
    try:
        client.request("inspect")
    except client.LabUnavailable:
        return False
    except client.LabError as exc:
        raise HTTPException(502, str(exc)) from exc
    _invoke("configure", {"vlans": vlans, "rules": rules})
    return True


@router.get("/vlans")
def list_vlans():
    return _vlans(_status())


@router.post("/vlans", status_code=201)
def create_vlan(body: VlanInput):
    vlan = _validated(validate_vlan, body.model_dump())
    with _MUTATION:
        old = store.get_vlans()
        if any(v["id"] == vlan["id"] for v in old):
            raise HTTPException(409, "This VLAN ID is already configured")
        all_vlans = _validated(validate_vlans, old + [vlan])
        applied = _apply_if_online(all_vlans, store.get_rules())
        store.save_vlan(vlan)
    return {**vlan, "hosts": [], "ports": [], "mode": "access", "trunk": TRUNK,
            "status": "active" if applied else "planned"}


@router.get("/topology")
def topology():
    status = _status()
    vlans = _vlans(status)
    nodes = [
        {"id": "router", "type": "router", "label": "Inter-VLAN gateway", "ip": None, "vlan_id": None,
         "position": {"x": 440, "y": 0}, "details": {"name": "ns-r1", "routing_enabled": status["routing_enabled"], "interfaces": status.get("router_interfaces", [])}},
        {"id": "switch", "type": "switch", "label": "Open vSwitch", "ip": None, "vlan_id": None,
         "position": {"x": 440, "y": 150}, "details": {"name": "ns-sw", "trunk": TRUNK, "tagging": "802.1Q", "ports": status.get("ovs_ports")}},
    ]
    edges = [{"id": "trunk", "source": "router", "target": "switch", "label": "802.1Q trunk · " + ", ".join(str(v["id"]) for v in vlans)}]
    for index, (name, host) in enumerate(HOSTS.items()):
        nodes.append({"id": name, "type": "host", "label": name, "ip": host["ip"], "vlan_id": host["vlan_id"],
                      "position": {"x": (index // 2) * 360 + (index % 2) * 170, "y": 340},
                      "details": {**host, "name": "ns-" + name, "status": "active" if status["running"] else "planned"}})
        edges.append({"id": "link-" + name, "source": "switch", "target": name, "label": f"Access · VLAN {host['vlan_id']}"})
    return {**status, "status": "active" if status["running"] else "offline", "nodes": nodes, "edges": edges, "vlans": vlans,
            "acl_policy": "Stateful: no enabled rules permits routed traffic; enabled rules activate default deny. Deny rules take priority for new connections. Established replies are accepted."}


@router.post("/topology/routing")
def routing(body: EnableInput):
    with _MUTATION:
        # Applying the operator's saved policy before enabling forwarding prevents a permissive gap.
        if body.enabled:
            _invoke("configure", {"vlans": store.get_vlans(), "rules": store.get_rules()})
        return _invoke("routing", body.model_dump())


@router.get("/segmentation/rules")
def list_rules():
    return _rules(_status())


@router.post("/segmentation/rules", status_code=201)
def create_rule(body: RuleInput):
    with _MUTATION:
        vlans = store.get_vlans()
        rule = _validated(validate_rule, {**body.model_dump(), "id": uuid.uuid4().hex}, {v["id"] for v in vlans})
        rules = _validated(validate_rules, store.get_rules() + [rule], vlans)
        applied = _apply_if_online(vlans, rules)
        store.save_rules(rules)
        return {**rule, "applied": applied}


@router.patch("/segmentation/rules/{rule_id}")
def toggle_rule(rule_id: str, body: EnableInput):
    with _MUTATION:
        rules = store.get_rules()
        match = next((r for r in rules if r["id"] == rule_id), None)
        if not match:
            raise HTTPException(404, "Rule not found")
        match["enabled"] = body.enabled
        applied = _apply_if_online(store.get_vlans(), rules)
        store.save_rules(rules)
        return {**match, "applied": applied}


@router.delete("/segmentation/rules/{rule_id}")
def delete_rule(rule_id: str):
    with _MUTATION:
        previous = store.get_rules()
        rules = [r for r in previous if r["id"] != rule_id]
        if len(previous) == len(rules):
            raise HTTPException(404, "Rule not found")
        applied = _apply_if_online(store.get_vlans(), rules)
        store.save_rules(rules)
        return {"deleted": rule_id, "applied": applied}


@router.post("/segmentation/apply")
def apply_rules():
    with _MUTATION:
        return _invoke("configure", {"vlans": store.get_vlans(), "rules": store.get_rules()})


@router.post("/segmentation/test")
def test_connectivity(body: TestInput):
    data = _validated(validate_test, body.model_dump())
    result = _invoke("test", data)
    store.save_test(result)
    return result


@router.get("/segmentation/tests")
def connectivity_history():
    return store.get_tests()
