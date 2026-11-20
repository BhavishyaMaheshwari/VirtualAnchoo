# Validation record

This file distinguishes implementation, automated verification, and observations from a real network. It must not be read as a claim that privileged lab scenarios passed in an environment that cannot run them.

## Build environment

The implementation environment has Python 3.12 and Node.js 24. Its process capability bounding set is empty, and it has no `sudo`, Mininet, Open vSwitch, or nftables executables. Raw packet capture and privileged VLAN experiments cannot run in this environment. The appropriate outcome for those integration tests is an explicit skip, with prerequisites described in the test and setup documentation.

## Validation categories

| Category | Meaning |
| --- | --- |
| Parser fixtures | Constructed Scapy packets verify protocol fields, malformed/missing-layer handling, VLAN extraction, and identification. These are algorithm tests, not observed network traffic. |
| PCAP/API integration | Imports actual capture files or clearly identified test fixtures, checks persistence, filters, analytics, exports, and event delivery. Fixture provenance must remain explicit. |
| Live capture lifecycle | Tests state transitions and error handling; an actual raw-socket test only passes if packets were captured from generated local traffic on an authorized interface. |
| Network configuration unit tests | Validate VLAN/rule schema and command/ruleset construction. They do not prove OVS or firewall behavior. |
| Privileged network integration | Creates a real lab, inspects OVS/tagged interfaces, and measures host reachability before/after routing and ACL changes. Requires explicit opt-in on supported Linux. |
| Frontend build | TypeScript and Vite build check static integration. Browser verification separately checks rendering and interaction. |

## Actual results

Latest local verification (2026-11-20, macOS, Python 3.14.0): `./scripts/test.sh` passed **65 Python tests and 8 frontend interaction tests**, with 6 privileged tests skipped; the TypeScript check and Vite production build passed. The added Python test verifies that existing database files remain accessible after the rename. The frontend interaction suite does not establish visual layout. Live capture and the Linux VLAN lab still require the documented authorized host and privileges.

The following detailed checks were recorded in the original delivery environment; its browser and privileged limits remain separate from the latest local run:

| Check | Observed result | What this establishes |
| --- | --- | --- |
| `.venv/bin/python -m pytest -q -ra` | **64 passed, 6 skipped** | Parsing, fields/protocols, VLAN tags, flow/analytics/filter calculations, API/persistence/import/export/WebSocket behavior, schema and lab adapter/failure handling. |
| `npm --prefix frontend test` | **7 passed at original delivery; 8 passed locally on 2026-11-17** | UUID session selection, packet inspection, display filters, file import success/error, authorization/permission feedback, six-page navigation, and now confirmed session deletion. Uses synthetic fixtures and stubs chart/topology rendering because jsdom lacks a layout engine. |
| `npm --prefix frontend run build` | **Passed** | TypeScript checks and Vite build of actual chart/topology modules; no bundle-size warning after chunk separation. |
| Production HTTP/WS smoke check | **Passed** | HTML, interfaces, network APIs, API docs and a real WebSocket status connection responded successfully. |
| Actual capture permission attempt | **HTTP 409 with permission-denied instructions** | Explicit opt-in reaches the OS raw-socket check, and missing privileges are reported. It does not establish successful capture. |
| Explicit live-test opt-in | **Skipped: CAP_NET_RAW unavailable** | The actual integration test recognizes the environment limitation. |
| Local traffic helper | **TCP, UDP, DNS exchanges completed** | Actual local sockets transferred messages; no capture was possible. |
| Managed browser preview | **Unverified** | `sites-preview start` failed: relay could not open browser port 4173, timeout waiting for relay readiness. No screenshot or visual/browser-flow pass is claimed. |

The Python run emitted one dependency deprecation notice from the installed FastAPI/Starlette TestClient HTTPX adapter. Assertions passed; no application failure resulted.

### Real historical capture verification

These captures came from Wireshark's published SampleCaptures collection, not a packet generator:

| Capture source | Imported packet observations | Packet bytes | Export verification |
| --- | ---: | ---: | --- |
| [DHCP](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dhcp.pcap) | 4 | 1,312 | Byte-identical original export; Scapy reread matched counts and lengths. |
| [DNS](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap) | 38 | 3,706 | Byte-identical original export; Scapy reread matched counts and lengths. |

Both had `source: import` and explicitly historical filenames. Overview, protocol, bandwidth, device, flow, size and VLAN endpoints returned successful responses derived from these records. DHCP produced two bidirectional UDP tuples; DNS produced eight. Imported direction remained unknown. These are historical trace observations; the capture timestamps are not the import time. The supplied download helper retrieves the DHCP trace on demand and prints its URL/hash; runtime traces are excluded from the delivery ZIP.

### Environment-dependent verification still required

One live loopback integration test and five real Mininet tests are skipped by default. The Mininet tests cover actual OVS access/trunk settings and router VLAN interfaces, same-VLAN ping, cross-VLAN isolation, routed reachability, and ACL/ICMP outcomes. All require explicit opt-in and the documented environment. Unit tests with constructed packets or mocked agent failures do not prove those network behaviors.

The nine experiments in [experiments.md](experiments.md) remain **NOT RUN on a privileged lab host**. Their expected outcomes must be compared with real output and recorded before a report claims they passed. Live behavior, browser rendering and throughput limits remain material verification boundaries.
