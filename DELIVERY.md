# VirtualAnchoo delivery

This archive contains the full Python and TypeScript source, a prebuilt React dashboard, Mininet/OVS lab scripts, tests, setup/run scripts and documentation. It excludes installed dependencies, private runtime data and captures. The application begins with empty history.

## First run

Extract the ZIP, open a terminal in its `VirtualAnchoo` folder, then:

```bash
bash scripts/setup.sh
bash scripts/start.sh --production
```

Visit **http://127.0.0.1:8765**. Import a PCAP/PCAPNG file to analyze real traffic. The optional public Wireshark download helper is documented in README.md. To stop, run `bash scripts/stop.sh` in another terminal.

For development use `bash scripts/start.sh` and visit http://127.0.0.1:5173. Use Python 3.11+, a supported Node.js/npm release, and a POSIX shell. On Windows use an Ubuntu VM/WSL2 for the application; the VLAN lab specifically needs a Linux environment with the documented kernel/network capabilities. A dedicated Ubuntu VM is the recommended full-project environment.

## What was checked

- 65 Python tests and 8 frontend interaction tests pass.
- Six privileged integration tests are explicitly skipped in the build environment.
- TypeScript and the Vite production build pass.
- Historical public Wireshark DHCP/DNS captures pass real API import, analytics and byte-identical export checks.
- Production HTML, API routes and WebSocket status delivery were checked over local connections.
- Actual local TCP/UDP/DNS socket exchanges completed. Live packet capture permission is unavailable; its explicit error was verified.
- Full browser visual QA is unverified: the managed preview relay could not start.

See `docs/validation.md` for evidence and limits. Live capture, Mininet VLAN behavior, routing and firewall reachability require the explicitly authorized Linux setup; they have not been demonstrated on this build machine.

## Guides

- `README.md`: features, architecture, quick start and limits.
- `docs/setup.md`: installation, capabilities, VM/lab operation and troubleshooting.
- `docs/API.md`: REST, WebSocket and statistic semantics.
- `docs/architecture.md`: application and network diagrams.
- `docs/experiments.md`: nine experiments with expected/actual result fields.
- `docs/viva.md`: underlying Computer Networks concepts.

Run `bash scripts/test.sh` for automated verification. Build assets are included for convenience; setup rebuilds them. `MANIFEST.sha256` records all archived file hashes; the adjacent ZIP checksum verifies the download. `python3 scripts/package.py` can recreate the ZIP after checks/build.
