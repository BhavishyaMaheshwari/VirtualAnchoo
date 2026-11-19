"""Opt-in integration against the operator's loopback interface.

No external traffic is generated. Skipped unless explicitly enabled and the
process has Linux raw-socket capability; these skips are not passing lab tests.
"""
import os
import socket
import sys
import time
import pytest
from fastapi.testclient import TestClient
from backend.app.main import create_app

@pytest.mark.integration
def test_real_loopback_capture_lifecycle_and_websocket(tmp_path,monkeypatch):
    if os.environ.get("NETSCOPE_RUN_LIVE_TESTS") != "1":
        pytest.skip("Set NETSCOPE_RUN_LIVE_TESTS=1 to authorize the real loopback capture integration")
    if sys.platform != "linux" or not hasattr(socket,"AF_PACKET"):
        pytest.skip("Linux AF_PACKET capture is required")
    try:
        probe = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
        probe.close()
    except PermissionError:
        pytest.skip("CAP_NET_RAW is unavailable in this environment")
    monkeypatch.setenv("NETSCOPE_LIVE_CAPTURE","1")
    with TestClient(create_app(tmp_path/"live")) as client:
        with client.websocket_connect("/ws") as ws:
            assert ws.receive_json()["type"] == "capture_status"
            start = client.post("/api/capture/start",json={"interface":"lo","authorized":True,"packet_limit":100})
            assert start.status_code == 200,start.text
            sid = start.json()["session_id"]
            assert ws.receive_json()["type"] == "capture_status"
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
                receiver.bind(("127.0.0.1",0))
                receiver.settimeout(2)
                destination = receiver.getsockname()
                sender.sendto(b"NetScope authorized loopback integration",destination)
                assert receiver.recvfrom(256)[0].startswith(b"NetScope")
            event = ws.receive_json()
            assert event["type"] == "packet"
            assert event["data"]["session_id"] == sid
            stop = client.post("/api/capture/stop")
            assert stop.status_code == 200 and not stop.json()["running"]
            packets = client.get("/api/packets",params={"session_id":sid}).json()
            assert packets["total"] >= 1
            assert any(p["src_ip"] == "127.0.0.1" for p in packets["items"])
            assert client.get(f"/api/capture/{sid}/export").status_code == 200
