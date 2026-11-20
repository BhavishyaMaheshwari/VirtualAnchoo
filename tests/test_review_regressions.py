"""Independent integration regressions. Fixtures are synthetic test inputs only.

These tests do not exercise privileged networking or produce dashboard demo data.
"""
from pathlib import Path

from fastapi.testclient import TestClient
from scapy.all import Ether, IP, UDP, PcapNgWriter, PcapReader, wrpcap

from backend.app.main import create_app
from backend.app.models.database import Database


def test_mixed_linktype_pcapng_export_preserves_packets(tmp_path):
    """A valid multi-interface capture must not be flattened into wrong frames."""
    source = tmp_path / "mixed.pcapng"
    ethernet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
        src="192.0.2.1", dst="192.0.2.2") / UDP(sport=1234, dport=9999)
    ethernet.sniffed_on = "ethernet"
    raw_ip = IP(src="198.51.100.1", dst="198.51.100.2") / UDP(sport=1234, dport=9999)
    raw_ip.sniffed_on = "rawip"
    with PcapNgWriter(str(source)) as writer:
        writer.write(ethernet)
        writer.write(raw_ip)
    with TestClient(create_app(data_dir=tmp_path / "app")) as client:
        response = client.post("/api/capture/import", files={"file": (source.name, source.read_bytes())})
        assert response.status_code == 200, response.text
        session = response.json()
        assert session["source"] == "import"
        assert session["packet_count"] == 2
        exported = client.get(f"/api/capture/{session['id']}/export")
        assert exported.status_code == 200
        output = tmp_path / "exported.pcapng"
        output.write_bytes(exported.content)
        with PcapReader(str(output)) as reader:
            packets = list(reader)
        assert len(packets) == 2
        assert packets[0].haslayer(Ether)
        assert not packets[1].haslayer(Ether)
        assert packets[1][IP].src == "198.51.100.1"
        assert packets[1][UDP].dport == 9999


def test_historical_sessions_remain_separate_and_survive_restart(tmp_path):
    first, second = tmp_path / "first.pcap", tmp_path / "second.pcap"
    wrpcap(str(first), [IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=1, dport=2)])
    wrpcap(str(second), [IP(src="198.51.100.1", dst="198.51.100.2") / UDP(sport=3, dport=4)] * 3)
    data = tmp_path / "app"
    with TestClient(create_app(data_dir=data)) as client:
        ids = []
        for source in (first, second):
            imported = client.post("/api/capture/import", files={"file": (source.name, source.read_bytes())})
            assert imported.status_code == 200, imported.text
            ids.append(imported.json()["id"])
        one = client.get("/api/analytics/overview", params={"session_id": ids[0]}).json()
        two = client.get("/api/analytics/overview", params={"session_id": ids[1]}).json()
        assert one["total_packets"] == 1
        assert two["total_packets"] == 3
        assert client.get("/api/packets", params={"session_id": ids[0], "src_ip": "198.51.100.1"}).json()["total"] == 0
    with TestClient(create_app(data_dir=data)) as client:
        sessions = client.get("/api/sessions").json()
        assert {session["id"] for session in sessions} == set(ids)
        assert client.get("/api/analytics/overview", params={"session_id": ids[0]}).json()["total_packets"] == 1
        assert client.get(f"/api/capture/{ids[1]}/export").status_code == 200
        assert client.delete(f"/api/sessions/{ids[0]}").status_code == 200
        assert client.get("/api/packets", params={"session_id": ids[0]}).status_code == 404
        assert client.get("/api/analytics/overview", params={"session_id": ids[1]}).json()["total_packets"] == 3


def test_browser_origin_cannot_mutate_local_service(tmp_path):
    with TestClient(create_app(data_dir=tmp_path)) as client:
        denied = client.post("/api/capture/stop", headers={"Origin": "https://untrusted.example"})
        assert denied.status_code == 403
        assert client.post("/api/capture/stop", headers={"Origin": "http://127.0.0.1:8765"}).status_code == 200


def test_existing_database_survives_project_rename(tmp_path):
    database = Database(tmp_path)
    session = database.create_session("import", "existing capture", "")
    database.conn.close()
    (tmp_path / "virtualanchoo.sqlite3").rename(tmp_path / "netscope.sqlite3")

    reopened = Database(tmp_path)
    try:
        assert reopened.session(session["id"])["name"] == "existing capture"
        assert not (tmp_path / "virtualanchoo.sqlite3").exists()
    finally:
        reopened.conn.close()
