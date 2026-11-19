"""Download Wireshark's published DHCP capture for explicitly labelled offline analysis.

This retrieves actual captured traffic; it does not generate packet records. The
file is never imported automatically. Import it using the dashboard or API.
"""
import hashlib
from pathlib import Path
from urllib.request import urlopen

URL = "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dhcp.pcap"
target = Path(__file__).resolve().parents[1] / "data" / "examples" / "wireshark-dhcp.pcap"
target.parent.mkdir(parents=True, exist_ok=True)
with urlopen(URL, timeout=30) as response:
    capture = response.read(2_000_001)
if len(capture) > 2_000_000 or capture[:4] not in (bytes.fromhex("d4c3b2a1"), bytes.fromhex("a1b2c3d4")):
    raise SystemExit("Download is not the expected bounded PCAP file; no file saved.")
target.write_bytes(capture)
print(f"Source: {URL}\nSaved: {target}\nSHA256: {hashlib.sha256(capture).hexdigest()}")
print("Import this file as offline traffic. Capture timestamps are historical, not live.")
