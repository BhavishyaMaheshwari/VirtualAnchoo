# VirtualAnchoo

**Network Traffic Analysis, Packet Sniffing and VLAN-Based Network Segmentation**

VirtualAnchoo is a local Computer Networks project with a Python/FastAPI packet-analysis backend, a React dashboard, and an optional Mininet/Open vSwitch lab. Traffic statistics come from captured packets or explicitly labelled imported capture files. The application starts in offline mode; it does not generate demonstration traffic or create a privileged network automatically.

## Run locally

Prerequisites: Python 3.11+, Node.js 20.19+ or 22.12+, npm, and a POSIX shell. The VLAN lab additionally requires a compatible Linux host or Ubuntu VM.

```bash
cd VirtualAnchoo
./scripts/setup.sh
./scripts/start.sh
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173). The API runs at [http://127.0.0.1:8765](http://127.0.0.1:8765), with interactive API documentation at [http://127.0.0.1:8765/docs](http://127.0.0.1:8765/docs).

An optional public historical capture can be downloaded with `.venv/bin/python scripts/fetch_example_pcap.py`, then imported from `data/examples/wireshark-dhcp.pcap`. The helper prints its source URL and SHA-256; it never preloads traffic.

Import an existing authorized `.pcap` or `.pcapng` file to begin analysis without capture privileges. No sample traffic is preloaded. Select a session in the dashboard to review its packets, charts, devices, and flows. Imported sessions retain their provenance.
Use the download button beside the session selector to export a finished capture, or the trash button to delete the selected session and its locally stored packet data.

```bash
./scripts/stop.sh
./scripts/start.sh --production
```

Production mode serves the built frontend and API together at [http://127.0.0.1:8765](http://127.0.0.1:8765). Here “production” selects built assets; it does not turn this local single-operator application into a hardened public server.

For authorized live capture, start with `./scripts/start.sh --live`, select the interface, acknowledge authorization in the dashboard, and start capture. This switch enables the feature but does **not** grant operating-system privileges. See [setup](docs/setup.md) for Linux capture capabilities and the optional lab.

## Features

- Scapy capture with interface selection, BPF filters, explicit start/stop, permission reporting, and per-session resource limits.
- Ethernet, IPv4/IPv6, TCP, UDP, ICMP, DNS, ARP, DHCP, and 802.1Q fields when present. HTTP/TLS identification is heuristic; encrypted application payloads are not shown as decrypted content.
- PCAP/PCAPNG import, capture export, persisted session history, structured packet inspection, and packet filtering/pagination.
- Packet/byte totals, size distribution, protocol percentages and volume, direction where observable, time-series traffic, endpoint activity, MAC/IP observations, and bidirectional transport flows.
- Six dashboard sections: overview, packet analyzer, traffic analytics, network topology, VLAN management, and segmentation/access control.
- A real optional Linux lab with two hosts per department, VLANs 10/20/30, Open vSwitch access/trunk ports, router subinterfaces, inter-VLAN forwarding, and scoped firewall rules.
- Validated lab controls and actual connectivity-test results. The interface distinguishes planned configuration from an active lab.
- Unit/API tests plus explicit environment-dependent tests for raw capture and privileged networking.

## Architecture and stack

| Component | Technology and responsibility |
| --- | --- |
| Backend | Python 3.11+, FastAPI, Pydantic, Scapy, SQLite, REST and WebSockets |
| Frontend | React, TypeScript, Vite, Tailwind CSS, Recharts, React Flow, Lucide |
| Capture | Background capture worker, packet metadata, bounded sessions, capture files |
| Lab | Mininet, Open vSwitch, Linux namespaces, 802.1Q, routing and firewall tools |
| Persistence | SQLite for sessions/metadata and lab history; separate PCAP files for export |

TShark is an optional independent capture/dissection aid; VirtualAnchoo does not require PyShark or a TShark subprocess for its primary parsing path.

```text
backend/       FastAPI APIs, capture/parser/analytics services, storage, tests
frontend/      React application and Vite build
network/       Real Linux VLAN lab, constrained controls, scenarios, tests
scripts/       Setup, process lifecycle, verification, and lab cleanup helpers
docs/          Architecture, setup, API, experiments, concepts, and validation
data/          Runtime database and captures (ignored by source control)
```

See the [architecture and topology diagrams](docs/architecture.md) for the data path and privilege boundary.

## Tests and demonstrations

```bash
./scripts/test.sh
```

The unprivileged suite exercises parsing, protocol classification, VLAN extraction, flows, analytics, filters, APIs, capture lifecycle behavior, and PCAP/WebSocket integration as supported by the fixtures. Test-generated packet fixtures verify algorithms; they are not measurements of a real network and are never loaded into the dashboard as real traffic.

Tests needing raw-socket capabilities or the Mininet lab are skipped when their prerequisites or explicit opt-in are absent. A skipped test is not a passed networking experiment. [Validation](docs/validation.md) records the actual checks performed in the build environment. [Experiments](docs/experiments.md) provides nine reproducible demonstrations with explicit result-recording guidance.

## Documentation

- [Installation, live capture, lab setup, and troubleshooting](docs/setup.md)
- [Architecture and network topology](docs/architecture.md)
- [REST and WebSocket API](docs/API.md)
- [Nine experiments and evidence templates](docs/experiments.md)
- [Computer Networks viva notes](docs/viva.md)
- [Implemented versus verified behavior](docs/validation.md)

## Important limits

This application is intended for a trusted local operator. Keep the API bound to loopback. Only capture interfaces and networks you own or are authorized to monitor. The frontend cannot elevate privileges, and importing a capture file does not enable live sniffing or create a network.

Flow tracking groups bidirectional endpoint/transport tuples within a capture session, without a full TCP state machine, inactivity expiration, stream reassembly, or decryption. Repeated TCP payload sequence/length observations are only retransmission estimates. Endpoint reuse and duplicate capture observations can affect flow interpretation. See [API semantics](docs/API.md) for rate and counter definitions.

Per-session limits bound work, but this is not a high-throughput production collector. Retained sessions consume disk until deleted. The Mininet lab is Linux-specific; macOS and Windows users need a Linux VM. A topology diagram and a saved ACL are not evidence of actual network isolation: run the documented connectivity tests on the supported lab.

## Verification delivered with this source

The integrated checks currently pass **64 Python tests and 8 frontend interaction tests**, with **6 privileged integration tests skipped**. TypeScript checking and the Vite production build pass. Public historical Wireshark DHCP (4 packets / 1,312 packet bytes) and DNS (38 packets / 3,706 packet bytes) captures were imported, analyzed and exported with matching counts and lengths. Browser QA could not run because the managed preview relay failed; live capture and Mininet behavior need verification on the documented Linux host. See [validation.md](docs/validation.md) for precise scope.
