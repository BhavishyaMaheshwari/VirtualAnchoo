"""Bounded local Unix socket protocol; never sends commands or shell fragments."""
from __future__ import annotations
import json
import os
import socket

MAX_MESSAGE = 256 * 1024
DEFAULT_SOCKET = "/run/virtualanchoo/lab.sock"

class LabUnavailable(RuntimeError):
    pass

class LabError(RuntimeError):
    pass


def request(operation: str, payload: dict | None = None, *, socket_path: str | None = None) -> dict:
    path = socket_path or os.getenv("VIRTUALANCHOO_LAB_SOCKET", DEFAULT_SOCKET)
    message = json.dumps({"operation": operation, "payload": payload or {}}).encode() + b"\n"
    if len(message) > MAX_MESSAGE:
        raise LabError("Lab request is too large")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(25)
            sock.connect(path)
            sock.sendall(message)
            chunks = bytearray()
            while b"\n" not in chunks:
                chunk = sock.recv(16384)
                if not chunk:
                    raise LabUnavailable("Lab agent closed the connection")
                chunks.extend(chunk)
                if len(chunks) > MAX_MESSAGE:
                    raise LabError("Lab response exceeded the size limit")
    except (FileNotFoundError, ConnectionRefusedError, PermissionError, TimeoutError, socket.timeout, OSError) as exc:
        raise LabUnavailable(
            "Privileged VLAN lab is offline or inaccessible. On an authorized Ubuntu host, run "
            "sudo /usr/bin/python3 -m network.topology --owner-uid $(id -u). "
            "Requires Mininet, Open vSwitch, nftables and network administration privileges."
        ) from exc
    try:
        response = json.loads(chunks.split(b"\n", 1)[0])
    except (ValueError, TypeError) as exc:
        raise LabError("Malformed lab response") from exc
    if not response.get("ok"):
        raise LabError(response.get("error", "Lab operation failed"))
    return response["data"]
