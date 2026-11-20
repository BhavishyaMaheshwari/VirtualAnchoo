"""ASGI and persistence integration with explicitly constructed packet fixtures.

These are offline tests; privileged live capture is tested separately/skipped.
"""
from pathlib import Path
from concurrent.futures import CancelledError as FutureCancelledError
from contextlib import suppress
import time
from fastapi.testclient import TestClient
import pytest
from scapy.all import ARP, DNS, DNSQR, Dot1Q, Ether, IP, TCP, UDP, wrpcap
from backend.app.main import create_app
from backend.app.services import capture_engine

@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.delenv("VIRTUALANCHOO_LIVE_CAPTURE",raising=False)
    with TestClient(create_app(tmp_path/"data")) as client:
        yield client

@pytest.fixture
def pcap(tmp_path):
    path = tmp_path/"unit-fixture.pcap"
    packets = [Ether()/IP(src="10.0.0.1",dst="10.0.0.2")/TCP(sport=4000,dport=443,flags="S"),
               Ether()/IP(src="10.0.0.2",dst="10.0.0.1")/TCP(sport=443,dport=4000,flags="SA"),
               Ether()/Dot1Q(vlan=10)/IP(src="10.0.0.1",dst="10.0.0.53")/UDP(sport=5300,dport=53)/DNS(qd=DNSQR(qname="example.test")),
               Ether()/ARP(psrc="10.0.0.1",pdst="10.0.0.2")]
    for i,packet in enumerate(packets):
        packet.time = 1700000000+i
    wrpcap(str(path),packets)
    return path


def upload(client,pcap):
    with pcap.open("rb") as handle:
        response = client.post("/api/capture/import",files={"file":(pcap.name,handle,"application/vnd.tcpdump.pcap")})
    assert response.status_code == 200,response.text
    return response.json()


def test_empty_start_state(client):
    assert client.get("/api/health").json()["mode"] == "offline"
    assert client.get("/api/packets").json()["total"] == 0
    assert client.get("/api/analytics/overview").json()["total_packets"] == 0
    assert client.get("/api/analytics/protocols").json() == []
    assert client.get("/api/sessions").json() == []
    assert isinstance(client.get("/api/interfaces").json(),list)


def test_import_analytics_filter_inspection_and_export(client,pcap):
    session = upload(client,pcap)
    assert session["source"] == "import" and session["packet_count"] == 4
    assert "pcap_path" not in session
    assert len(client.get("/api/sessions").json()) == 1
    overview = client.get("/api/analytics/overview").json()
    assert overview["total_packets"] == 4
    assert overview["total_bytes"] == session["byte_count"]
    assert sum(item["count"] for item in client.get("/api/analytics/protocols").json()) == 4
    assert sum(item["packets"] for item in client.get("/api/analytics/bandwidth").json()) == 4
    assert sum(item["count"] for item in client.get("/api/analytics/sizes").json()) == 4
    assert len(client.get("/api/analytics/devices").json()) >= 3
    flows = client.get("/api/analytics/flows").json()
    assert any(flow["packets"] == 2 for flow in flows)
    result = client.get("/api/packets",params={"vlan_id":10,"protocol":"DNS","src_ip":"10.0.0.1","src_port":5300,"min_size":40}).json()
    assert result["total"] == 1
    detail = client.get(f'/api/packets/{result["items"][0]["id"]}').json()
    assert detail["layers"]["802.1Q"]["vlan_id"] == 10
    assert client.get("/api/packets",params={"start_time":1700000002,"end_time":1700000002}).json()["total"] == 1
    assert client.get("/api/packets",params={"dst_port":443}).json()["total"] == 1
    assert client.get("/api/packets",params={"max_size":1}).json()["total"] == 0
    assert client.get("/api/packets",params={"search":"10.0.0.53"}).json()["total"] == 1
    assert len(client.get("/api/packets",params={"page_size":2,"page":2}).json()["items"]) == 2
    exported = client.get(f'/api/capture/{session["id"]}/export')
    assert exported.status_code == 200
    assert exported.content == pcap.read_bytes()


def test_persistence_across_restart(tmp_path,pcap):
    directory = tmp_path/"persistent"
    with TestClient(create_app(directory)) as first:
        session = upload(first,pcap)
    with TestClient(create_app(directory)) as second:
        assert second.get("/api/analytics/overview",params={"session_id":session["id"]}).json()["total_packets"] == 4
        assert second.delete(f'/api/sessions/{session["id"]}').status_code == 200
        assert second.get("/api/packets").json()["total"] == 0
        assert second.get(f'/api/capture/{session["id"]}/export').status_code == 404


def test_session_isolation(client,pcap):
    first,second = upload(client,pcap),upload(client,pcap)
    assert first["id"] != second["id"]
    assert client.get("/api/packets").json()["total"] == 4
    assert client.get("/api/packets",params={"session_id":first["id"]}).json()["total"] == 4
    assert client.get("/api/packets",params={"session_id":"missing"}).status_code == 404


@pytest.mark.parametrize("params",[{"src_ip":"invalid"},{"dst_port":65536},{"vlan_id":4095},{"page":0},{"page_size":9999},{"min_size":10,"max_size":5},{"start_time":5,"end_time":4}])
def test_filter_validation(client,params):
    assert client.get("/api/packets",params=params).status_code == 422


def test_bad_imports_and_missing_packets(client):
    assert client.post("/api/capture/import",files={"file":("bad.pcap",b"not a capture")}).status_code == 400
    assert client.post("/api/capture/import",files={"file":("empty.pcap",b"")}).status_code == 400
    assert client.get("/api/packets/999").status_code == 404


def test_capture_requires_operator_opt_in(client):
    assert client.post("/api/capture/start",json={"interface":"lo","authorized":False}).status_code == 422
    result = client.post("/api/capture/start",json={"interface":"lo","authorized":True})
    assert result.status_code == 409
    assert "disabled" in result.json()["detail"]
    assert client.post("/api/capture/stop").json()["running"] is False


def test_permission_error_is_visible(client,monkeypatch):
    monkeypatch.setenv("VIRTUALANCHOO_LIVE_CAPTURE","1")
    monkeypatch.setattr(capture_engine,"interfaces",lambda:[{"name":"test0","addresses":[],"mac":None}])
    def denied(**kwargs):
        raise PermissionError("Operation not permitted")
    monkeypatch.setattr(capture_engine.conf,"L2listen",denied)
    result = client.post("/api/capture/start",json={"interface":"test0","authorized":True})
    assert result.status_code == 409
    assert "permission denied" in result.json()["detail"]
    assert client.get("/api/capture/status").json()["running"] is False
    assert "permission denied" in client.get("/api/capture/status").json()["error"]


def test_local_origin_and_host_guards(client):
    assert client.post("/api/capture/stop",headers={"Origin":"https://evil.invalid"}).status_code == 403
    assert client.get("/api/interfaces",headers={"Host":"evil.invalid"}).status_code == 400


def test_websocket_packet_and_status_delivery(client,pcap):
    # Starlette's TestClient may cancel its portal future on Python 3.14 when
    # closing an otherwise completed WebSocket context.
    with suppress(FutureCancelledError):
        with client.websocket_connect("/ws",headers={"origin":"http://localhost:5173"}) as ws:
            assert ws.receive_json()["type"] == "capture_status"
            session = upload(client,pcap)
            assert ws.receive_json()["type"] == "capture_status"
            # Replay genuine parsed fixture metadata through the same fanout used
            # by the capture callback; this verifies delivery, not raw-socket access.
            packet = client.get("/api/packets").json()["items"][0]
            client.app.state.hub.publish("packet",packet)
            event = ws.receive_json()
            assert event["type"] == "packet"
            assert event["data"]["session_id"] == session["id"]
            ws.close()
            for _ in range(100):
                if not client.app.state.hub.clients:
                    break
                time.sleep(0.01)
    assert not client.app.state.hub.clients
