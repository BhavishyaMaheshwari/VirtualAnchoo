# Installation and operation

## 1. Local prerequisites

- Python 3.11 or newer with `venv` and pip.
- Node.js 20.19+ or 22.12+ and npm.
- A POSIX shell for the included lifecycle scripts.
- For live capture, a supported Scapy interface and raw-socket privileges. BPF compilation may need libpcap.
- For VLAN experiments, a dedicated Ubuntu 22.04/24.04 VM or compatible Linux machine with Mininet, Open vSwitch, `iproute2`, and firewall tooling.

The dashboard and PCAP import do not need Mininet or elevated privileges. Mininet/OVS do not run natively on macOS or Windows; use an Ubuntu VM with a Linux kernel rather than expecting the host OS to provide Linux namespaces. A typical unprivileged container may have Linux but still lack the capabilities and kernel networking support needed by the lab.

## 2. Install the application

From the repository root:

```bash
./scripts/setup.sh
```

This creates `.venv`, installs `backend/requirements.txt`, installs frontend dependencies from the lockfile, and builds the React application. It does not configure host networking or start the VLAN lab.

Equivalent manual application setup:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
cd frontend
npm ci
npm run build
cd ..
```

On Ubuntu, install missing Python support with `sudo apt install python3-venv python3-pip`. Install a supported Node.js release through your preferred trusted package source if the OS package is too old.

## 3. Start and stop

```bash
./scripts/start.sh
./scripts/stop.sh
```

Development mode starts the backend on `127.0.0.1:8765` and Vite on `127.0.0.1:5173`. Vite proxies `/api` and `/ws` to the backend. The start script tracks its processes so the stop script can stop those processes without a broad `pkill`.

For a single service using built frontend assets:

```bash
./scripts/start.sh --production
```

Then visit [http://127.0.0.1:8765](http://127.0.0.1:8765). Manual backend start, from the repository root:

```bash
.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8765
```

Manual frontend start, in a separate terminal:

```bash
cd frontend
npm run dev
```

## 4. Offline analysis

Import a capture through the dashboard or REST API:

```bash
curl -f -F 'file=@/absolute/path/to/authorized-capture.pcap' \
  http://127.0.0.1:8765/api/capture/import
```

Use a capture obtained from a network you are authorized to inspect. Files may contain sensitive payloads even though the dashboard primarily presents metadata. A session returned by this endpoint is labelled `source: import`; its timestamps describe the capture, not the current wall clock.

Export a session using the returned session ID:

```bash
curl -f http://127.0.0.1:8765/api/capture/SESSION_ID/export -o session.pcap
```

Do not substitute generated test packets for measured traffic in reports. Unit tests intentionally construct packets to verify fields; their results establish parser behavior only.

## 5. Authorized live capture

```bash
./scripts/start.sh --live
```

On macOS, start with `./scripts/start.sh --production --live` in a normal Terminal. Scapy uses macOS BPF devices; the account running VirtualAnchoo must be able to open `/dev/bpf*`. Check with `id -Gn` and `ls -l /dev/bpf0`. A coding sandbox may deny BPF and local port binding even when the same account can use them from Terminal. Do not run the entire web application with `sudo` just to access BPF. If capture permission is unavailable, use `tcpdump` as an authorized operator to create a PCAP and import it through the dashboard.

Live capture additionally requires `VIRTUALANCHOO_LIVE_CAPTURE=1`, a valid accessible interface, OS capture privileges, and `authorized: true` in the capture request. The dashboard asks the operator to acknowledge authorization before starting. This is an operator assertion, not automatic permission discovery.

Check interfaces with `GET /api/interfaces`. Use a narrow filter and a reasonable packet limit, for example `icmp` for an owned lab interface. Invalid BPF filters, unknown interfaces, and unavailable permissions are reported as errors. A capture that starts but encounters an asynchronous error reports it in capture status.

On Linux, Scapy's raw socket capture generally requires `CAP_NET_RAW`; some capture operations also need `CAP_NET_ADMIN`. Prefer a dedicated VM and a capability-scoped service configured by its administrator. Do not add capabilities to a shared system Python binary or expose a privileged API on all interfaces.

An administrator can run the backend with scoped capabilities using systemd on a dedicated Linux lab machine. Stop an already-running backend first. This example grants the process capture capabilities while retaining the current user's identity:

```bash
sudo systemd-run --unit=virtualanchoo-capture --collect \
  --uid="$(id -u)" --gid="$(id -g)" \
  --working-directory="$PWD" \
  --property=AmbientCapabilities='CAP_NET_RAW CAP_NET_ADMIN' \
  --property=CapabilityBoundingSet='CAP_NET_RAW CAP_NET_ADMIN' \
  --setenv=VIRTUALANCHOO_LIVE_CAPTURE=1 \
  "$PWD/.venv/bin/python" -m uvicorn backend.app.main:app \
  --host 127.0.0.1 --port 8765
```

Inspect with `journalctl -u virtualanchoo-capture`; stop with `sudo systemctl stop virtualanchoo-capture`. This is a Linux operator setup example, not a command executed by the application. It is unavailable in containers without systemd or a sufficient capability bounding set.

## 6. Ubuntu VLAN lab prerequisites

Run these administrative installation steps inside the intended lab VM:

```bash
sudo apt update
sudo apt install mininet openvswitch-switch iproute2 iputils-ping \
  nftables tcpdump libpcap0.8 python3-venv python3-pip
sudo systemctl enable --now openvswitch-switch
sudo ovs-vsctl show
```

Distribution Mininet packages are commonly installed for `/usr/bin/python3`. Use that interpreter for lab commands unless Mininet is also installed and importable in another interpreter. The API/Scapy environment and privileged Mininet interpreter are intentionally separate.

The lab's command reference is in [experiments](experiments.md). Its privileged process is started explicitly by the operator and binds a restricted Unix socket. Starting the ordinary app does not start Mininet, change the host firewall, or enable host IP forwarding.

## 7. Start the lab explicitly

From the repository root, on the authorized Ubuntu VM:

```bash
sudo /usr/bin/python3 -m network.topology --owner-uid "$(id -u)"
```

Keep that terminal open. In a second terminal as the ordinary application user:

```bash
.venv/bin/python -m network.vlan_config
.venv/bin/python -m network.routing status
```

The API then reports active observed state. Saved custom VLANs/ACLs can be applied with the Access Control page's **Apply saved rules** button. Routing remains disabled until enabled explicitly. The fixed six hosts cannot be reassigned through the dashboard; extra VLANs initially have no hosts. In-place subnet changes and deleting live VLANs are unsupported.

To stop the owned lab, run `.venv/bin/python -m network.cleanup` or Ctrl+C in the agent terminal. Agent operations never accept arbitrary shell commands. `VIRTUALANCHOO_LAB_SOCKET` changes the client path; an explicit agent `--socket` must match and its parent must be root-owned and not writable by other users.

For privileged pytest, use a separate `python3 -m venv --system-site-packages .venv-lab`, install the backend requirements there, and run its interpreter under the documented opt-in. This makes Ubuntu's Mininet module visible without requiring it in the ordinary application venv.

## 8. Storage and retention

`VIRTUALANCHOO_DATA_DIR` selects the backend data directory; the default is the repository's `data/` directory. Keep it private. The packet database is `virtualanchoo.sqlite3`, and captured packet files are under `captures/`. Existing installations with a `netscope.sqlite3` database continue to use it until the file is migrated manually.

The backend limits a session to 100,000 packets, an uploaded file to 64 MiB, and a live capture file to 128 MiB, with a 1 GiB storage guard. These are application limits, not a substitute for filesystem quotas or backups. Stop capture before deleting a session. `DELETE /api/sessions/{session_id}` is the explicit history-removal operation. No automatic retention deletion is performed.

## Troubleshooting

| Symptom | Check and remedy |
| --- | --- |
| Dashboard reports backend offline | Start the backend; check port 8765 and process logs. Confirm the frontend proxy uses the same port. |
| No packets or charts | Import a valid authorized capture or start capture on the relevant interface. Empty counters are expected without data. |
| Live mode disabled | Restart with `--live` or `VIRTUALANCHOO_LIVE_CAPTURE=1`; this still requires OS privileges. |
| Operation not permitted | Check raw-socket capabilities, container capability bounding set, and interface access. Use offline import when privileges are unavailable. |
| BPF filter error | Check filter syntax and libpcap availability. Start with a simple filter such as `icmp`. |
| Traffic appears twice on loopback | Some capture paths expose duplicate observations. Counters describe captured observations; retransmission estimates can include duplicates. |
| No VLAN tag shown | Capture on the trunk rather than an access host. Physical NIC offload may remove tags before the capture hook. |
| Lab unavailable | Check the lab process, socket path/permissions, Linux dependencies, OVS service, and namespace capabilities. Saved topology is not an active network. |
| `import mininet` fails | Run lab commands with the distribution Python that owns the Mininet installation. |
| Cross-VLAN ping fails | Check lab state, subnet/gateway addresses, router forwarding, and firewall policy; a failure does not uniquely prove an ACL block. |
| PCAP upload fails | Confirm format, non-corruption, supported link type, packet limit, and upload/storage limits. |
| WebSocket reconnects | REST history remains available; verify origin/port and proxy configuration. |
| TLS payload unreadable | Expected: VirtualAnchoo does not decrypt TLS. Endpoint and timing metadata may still be visible. |

Do not use a broad Mininet cleanup command on a machine hosting unrelated labs. Use the project's scoped cleanup procedure after stopping its lab process.

## Port overrides

`./scripts/start.sh --backend-port 8766 --frontend-port 5174` configures the proxy and exact local browser origins for those ports. For manual starts, set `VIRTUALANCHOO_API_TARGET=http://127.0.0.1:8766` for Vite and `VIRTUALANCHOO_ALLOWED_ORIGINS=http://127.0.0.1:5174,http://localhost:5174` for FastAPI. Keep bindings on loopback. `VIRTUALANCHOO_NETWORK_DB` selects the lab configuration database independently from the packet data directory. Run CLI and API with the same value when overriding it.
