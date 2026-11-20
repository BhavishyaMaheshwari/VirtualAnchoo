"""Privileged, opt-in Mininet agent. It creates only the isolated ns-* lab.

Run from the repository on Ubuntu:
  sudo /usr/bin/python3 -m network.topology --owner-uid "$(id -u)"
Do not run the FastAPI server as root. No uplink connects this lab to the host LAN.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import fcntl
import json
import logging
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import threading
import uuid

from .client import DEFAULT_SOCKET, MAX_MESSAGE
from .schema import (DEFAULT_VLANS, HOSTS, TRUNK, ROUTER_INTERFACE, validate_vlans,
                     validate_rules, validate_test, nft_ruleset)

LOG = logging.getLogger("virtualanchoo.lab")


def execute(argv: list[str], *, node=None, stdin: str | None = None, timeout: float = 10,
            check: bool = True) -> tuple[int, str]:
    """Argument vectors only; node.popen enters the owned Mininet namespace."""
    options = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE,
               "stderr": subprocess.STDOUT, "text": True}
    proc = node.popen(argv, **options) if node is not None else subprocess.Popen(argv, **options)
    try:
        output, _ = proc.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise RuntimeError(f"Command timed out: {argv[0]}")
    if check and proc.returncode:
        raise RuntimeError(f"{argv[0]} failed ({proc.returncode}): {output[-2000:]}")
    return proc.returncode, output


class Lab:
    def __init__(self):
        self.net = None
        self.router = None
        self.hosts = {}
        self.vlans = validate_vlans(DEFAULT_VLANS)
        self.rules = []
        self.routing = False
        self.firewall_created = False
        self.stop_event = threading.Event()

    def start(self):
        if os.geteuid() != 0:
            raise RuntimeError("The Mininet agent requires root; the web application must remain unprivileged")
        missing = [x for x in ["ovs-vsctl", "ip", "nft", "ping", "sysctl", "mnexec"] if not shutil.which(x)]
        if missing:
            raise RuntimeError("Missing Linux lab dependencies: " + ", ".join(missing))
        try:
            from mininet.net import Mininet
            from mininet.node import OVSSwitch, Host
        except ImportError as exc:
            raise RuntimeError("Mininet is unavailable. Use Ubuntu's /usr/bin/python3 and install mininet") from exc
        execute(["ovs-vsctl", "--timeout=5", "show"])
        exists, _ = execute(["ovs-vsctl", "--timeout=5", "br-exists", "ns-sw"], check=False)
        if exists == 0:
            raise RuntimeError("Bridge ns-sw already exists; stop the previous lab before creating another")
        _, links = execute(["ip", "-j", "link", "show"])
        if any(item.get("ifname", "").startswith("ns-") for item in json.loads(links)):
            raise RuntimeError("An ns-* interface already exists; inspect and clean up the previous lab first")
        self.net = Mininet(controller=None, switch=OVSSwitch, host=Host,
                           build=False, autoSetMacs=False, autoStaticArp=False)
        switch = self.net.addSwitch("ns-sw", failMode="standalone")
        self.router = self.net.addHost("ns-r1", ip=None)
        for index, (name, info) in enumerate(HOSTS.items(), start=1):
            host = self.net.addHost("ns-" + name, ip=info["ip"] + "/24", mac=info["mac"])
            self.hosts[name] = host
            self.net.addLink(switch, host, port1=index)
        self.net.addLink(switch, self.router, port1=7, port2=0)
        try:
            self.net.build()
            self.net.start()
            # All configuration is confined to ns-sw and the router namespace.
            for host in HOSTS.values():
                execute(["ovs-vsctl", "set", "port", host["port"], "vlan_mode=access", f"tag={host['vlan_id']}"])
            execute(["ip", "addr", "flush", "dev", ROUTER_INTERFACE], node=self.router)
            execute(["ip", "link", "set", ROUTER_INTERFACE, "up"], node=self.router)
            # Disable routing explicitly before assigning gateway interfaces.
            self.set_routing(False)
            self.configure(self.vlans, [])
            for name, host in self.hosts.items():
                gateway = next(v["gateway"] for v in self.vlans if v["id"] == HOSTS[name]["vlan_id"])
                execute(["ip", "route", "replace", "default", "via", gateway], node=host)
        except Exception:
            self.stop()
            raise

    def configure(self, vlans: list, rules: list) -> dict:
        vlans = validate_vlans(vlans)
        rules = validate_rules(rules, vlans)
        if {v['id'] for v in self.vlans} - {v['id'] for v in vlans}:
            raise ValueError("Deleting live VLANs is unsupported; restart the lab to reset")
        for previous in self.vlans:
            updated = next(v for v in vlans if v['id'] == previous['id'])
            if previous['subnet'] != updated['subnet']:
                raise ValueError("In-place VLAN subnet changes are unsupported; restart with a new configuration")
        was_routing = self.routing
        self.set_routing(False)
        try:
            for vlan in vlans:
                iface = f"{ROUTER_INTERFACE}.{vlan['id']}"
                exists, _ = execute(["ip", "link", "show", "dev", iface], node=self.router, check=False)
                if exists:
                    execute(["ip", "link", "add", "link", ROUTER_INTERFACE, "name", iface,
                             "type", "vlan", "id", str(vlan["id"])], node=self.router)
                prefix = vlan["subnet"].split("/")[1]
                execute(["ip", "address", "replace", vlan["gateway"] + "/" + prefix, "dev", iface], node=self.router)
                execute(["ip", "link", "set", iface, "up"], node=self.router)
            execute(["ovs-vsctl", "set", "port", TRUNK, "vlan_mode=trunk",
                     "trunks=" + ",".join(str(v["id"]) for v in vlans)])
            # nft applies the whole replacement atomically inside the router namespace.
            config = nft_ruleset(vlans, rules, existing=self.firewall_created)
            execute(["nft", "-c", "-f", "-"], node=self.router, stdin=config)
            execute(["nft", "-f", "-"], node=self.router, stdin=config)
            self.vlans = vlans
            self.rules = rules
            self.firewall_created = True
        except Exception:
            # Leave forwarding disabled if any configuration step fails. The
            # caller receives the error and inspect exposes the resulting state.
            self.set_routing(False)
            raise
        self.set_routing(was_routing)
        return self.inspect()

    def set_routing(self, enabled: bool) -> dict:
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be a boolean")
        execute(["sysctl", "-w", f"net.ipv4.ip_forward={int(enabled)}"], node=self.router)
        self.routing = enabled
        return {"routing_enabled": enabled}

    def inspect(self) -> dict:
        _, ovs = execute(["ovs-vsctl", "--format=json", "--columns=name,tag,trunks,vlan_mode", "list", "port"])
        ovs_data = json.loads(ovs)
        # Never expose unrelated OVS ports from the host's other bridges.
        name_index = ovs_data["headings"].index("name")
        ovs_data["data"] = [row for row in ovs_data["data"] if str(row[name_index]).startswith("ns-sw")]
        _, router_addresses = execute(["ip", "-j", "address", "show"], node=self.router)
        _, forwarding = execute(["sysctl", "-n", "net.ipv4.ip_forward"], node=self.router)
        _, firewall = execute(["nft", "list", "table", "inet", "virtualanchoo"], node=self.router)
        return {"running": True, "available": True, "routing_enabled": forwarding.strip() == "1",
                "vlans": self.vlans, "rules": self.rules, "hosts": HOSTS,
                "switch": "ns-sw", "trunk": TRUNK, "ovs_ports": ovs_data,
                "router_interfaces": json.loads(router_addresses), "firewall": firewall,
                "message": "Isolated Mininet lab is running. State was inspected from OVS and the router namespace."}

    def test(self, payload: dict) -> dict:
        data = validate_test(payload)
        destination = HOSTS[data["destination"]]["ip"]
        command = ["ping", "-n", "-c", str(data["count"]), "-W", "1", destination]
        status, output = execute(command, node=self.hosts[data["source"]], timeout=12, check=False)
        match = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received,.*?([\d.]+)% packet loss", output)
        rtt = re.search(r"(?:rtt|round-trip).*?=\s*[\d.]+/([\d.]+)/", output)
        return {"id": uuid.uuid4().hex, "source": data["source"], "destination": data["destination"],
                "success": status == 0, "transmitted": int(match[1]) if match else None,
                "received": int(match[2]) if match else None, "packet_loss": float(match[3]) if match else None,
                "rtt_ms": float(rtt[1]) if rtt else None, "output": output[-12000:], "command": command,
                "exit_code": status, "executed_at": datetime.now(timezone.utc).isoformat(),
                "error": None if status in (0, 1) else "Ping failed to execute successfully",
                "observation": "Reachable" if status == 0 else "Unreachable; a ping failure alone does not identify the cause"}

    def dispatch(self, operation: str, payload: dict) -> dict:
        if operation == "inspect":
            return self.inspect()
        if operation == "configure":
            return self.configure(payload.get("vlans", self.vlans), payload.get("rules", self.rules))
        if operation == "routing":
            return self.set_routing(payload.get("enabled"))
        if operation == "test":
            return self.test(payload)
        if operation == "shutdown":
            self.stop_event.set()
            return {"stopping": True}
        raise ValueError("Unknown lab operation")

    def stop(self):
        if self.net is not None:
            self.net.stop()
            self.net = None
        self.router = None
        self.hosts = {}


class AgentServer(socketserver.UnixStreamServer):
    allow_reuse_address = False
    timeout = 0.5

    def __init__(self, path, lab: Lab, owner_uid: int):
        self.lab = lab
        self.owner_uid = owner_uid
        super().__init__(path, AgentHandler)


class AgentHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        _, uid, _ = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != self.server.owner_uid:
            self.wfile.write(b'{"ok":false,"error":"Unauthorized local UID"}\n')
            return
        try:
            raw = self.rfile.readline(MAX_MESSAGE + 1)
            if not raw.endswith(b"\n") or len(raw) > MAX_MESSAGE:
                raise ValueError("Invalid or oversized request")
            request = json.loads(raw)
            if not isinstance(request, dict) or set(request) != {"operation", "payload"}:
                raise ValueError("Invalid request object")
            if not isinstance(request["operation"], str) or not isinstance(request["payload"], dict):
                raise ValueError("Invalid operation or payload")
            result = self.server.lab.dispatch(request["operation"], request["payload"])
            response = {"ok": True, "data": result}
        except Exception as exc:
            LOG.warning("Lab request failed: %s", exc)
            response = {"ok": False, "error": str(exc)[:4000]}
        self.wfile.write(json.dumps(response).encode() + b"\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner-uid", type=int, default=int(os.getenv("SUDO_UID", "0")),
                        help="Only this non-root local user may control the lab")
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    if os.geteuid() != 0:
        parser.error("Run this lab agent with sudo on a supported Linux host")
    if args.owner_uid <= 0:
        parser.error("Supply --owner-uid for the non-root user running the dashboard")
    account = pwd.getpwuid(args.owner_uid)
    path = Path(args.socket)
    if not path.is_absolute():
        parser.error("The socket path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    parent_stat = path.parent.stat()
    if parent_stat.st_uid != 0 or stat.S_IMODE(parent_stat.st_mode) & 0o022:
        parser.error("Socket directory must be root-owned and not group/world writable")
    lock_fd = os.open(str(path.parent / "agent.lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error("Another VirtualAnchoo lab agent is already running")
    if path.exists():
        if not stat.S_ISSOCK(path.lstat().st_mode):
            parser.error("Refusing to replace a non-socket path")
        path.unlink()
    lab = Lab()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda _sig, _frame: lab.stop_event.set())
    try:
        lab.start()
        with AgentServer(str(path), lab, args.owner_uid) as server:
            os.chown(path, account.pw_uid, account.pw_gid)
            os.chmod(path, 0o600)
            LOG.info("Isolated lab ready at %s for UID %d", path, account.pw_uid)
            while not lab.stop_event.is_set():
                server.handle_request()
    finally:
        lab.stop()
        if path.exists() and stat.S_ISSOCK(path.lstat().st_mode):
            path.unlink()
        os.close(lock_fd)


if __name__ == "__main__":
    main()
