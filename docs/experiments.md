# Reproducible experiments and report evidence

Run these on networks and interfaces you are authorized to monitor. Live capture and Mininet require the Linux setup in [setup.md](setup.md). Offline analysis is available on any supported application host.

## Evidence and status

The implementation environment cannot open raw sockets or create a Mininet lab. **The live experiments below are NOT RUN here.** Expected results are hypotheses, not measured outcomes. Two public historical Wireshark captures were imported and exported successfully; those observations appear in [validation.md](validation.md). They do not establish that the local VLAN lab ran.

For each real execution, record the command, OS/tool versions, timestamp, selected capture interface, session ID, packet filter, observed packet counts, ping exit codes, OVS output, firewall counters, and relevant packet IDs. Export the PCAP and retain the JSON scenario report. Do not label a ping failure as an ACL drop unless forwarding and counters corroborate that cause.

## Prepare the authorized Linux lab

From the extracted repository, in a dedicated Ubuntu VM:

```bash
sudo apt install mininet openvswitch-switch nftables iproute2 iputils-ping tcpdump libpcap0.8
sudo systemctl start openvswitch-switch
sudo /usr/bin/python3 -m network.topology --owner-uid "$(id -u)"
```

Keep that terminal open. The lab creates `ns-sw`, six isolated hosts, and `ns-r1`. There is no physical uplink. The controlling Unix socket is `/run/netscope/lab.sock`, restricted to the specified user. In another terminal, as that user:

```bash
.venv/bin/python -m network.vlan_config
.venv/bin/python -m network.routing status
```

Start the application with `./scripts/start.sh --live` using the capture capability setup in [setup.md](setup.md), or capture with a separate authorized tool and import its file. The lab agent and the API are separate processes; enabling the lab does not grant capture privileges to the API.

Host inventory:

| Department | VLAN/subnet | Hosts | Access ports |
| --- | --- | --- | --- |
| Engineering | 10 / 192.168.10.0/24 | eng1 .11, eng2 .12 | ns-sw-eth1, ns-sw-eth2 |
| Finance | 20 / 192.168.20.0/24 | fin1 .11, fin2 .12 | ns-sw-eth3, ns-sw-eth4 |
| Administration | 30 / 192.168.30.0/24 | adm1 .11, adm2 .12 | ns-sw-eth5, ns-sw-eth6 |

`ns-sw-eth7` is the router trunk; gateways are `.1` in each subnet. IPv4 routing starts disabled. Use the Access Control page to manage rules. With no enabled rules, routed traffic is permitted; any enabled rule activates default deny for new conversations. Explicit denies precede allows; established replies are accepted. Disable existing saved ACLs before experiments expecting unrestricted routing.

## Experiment 1 — Capture TCP, UDP, ICMP, DNS, and ARP

**Objective:** identify protocol fields from actual exchanges.

**Configuration:** authorized loopback capture for TCP/UDP/DNS; active VLAN lab for ICMP and ARP. Loopback has no Ethernet ARP, so ARP must be observed on the lab Ethernet links.

**Commands and procedure:**

1. Start a capture on `lo` with filter `tcp or udp`, then run:
   ```bash
   .venv/bin/python scripts/generate_local_traffic.py
   ```
   This performs real TCP and UDP echo exchanges and a DNS query/answer over loopback UDP 5353. It does not create packet records. If a DNS service owns port 5353, the helper reports that conflict.
2. Stop and export the loopback capture. Inspect TCP flags/ports and DNS questions/answers. Scapy recognizes DNS on the mDNS port 5353.
3. Start a lab access-port capture on `ns-sw-eth1` with `arp or icmp`; then:
   ```bash
   curl -f -H 'Content-Type: application/json' -d '{"source":"eng1","destination":"eng2","count":3}' \
     http://127.0.0.1:8765/api/segmentation/test
   ```

**Expected:** TCP handshake/data/close observations, UDP datagrams, DNS query/response, ARP resolution when the neighbor cache is cold, and ICMP echo request/reply. Cached ARP entries can make a later run contain no ARP exchange. Loopback can expose duplicate observations.

**Actual result:** NOT RUN with capture here. The socket helper itself completed actual TCP/UDP/DNS loopback exchanges, but no packets were captured because capture permission is unavailable.

**Packet observations to record:** selected packet IDs, timestamps, source/destination, TCP flags, DNS name/type, ARP operation, and ICMP type/code. HTTPS/TLS metadata is observable; encrypted payload is not decrypted.

## Experiment 2 — Compare protocol statistics

**Objective:** validate protocol percentages, packet totals, and byte volumes.

**Configuration:** the real session from experiment 1, or an explicitly labelled imported trace.

**Commands:**

```bash
curl -f http://127.0.0.1:8765/api/analytics/overview
curl -f http://127.0.0.1:8765/api/analytics/protocols
curl -f http://127.0.0.1:8765/api/analytics/sizes
```

Use `?session_id=UUID` to pin a historical session. Select the same session in Traffic Analytics.

**Expected:** protocol counts sum to total packets; byte volumes sum to total bytes; size-bin counts sum to total packets. Application labels partition packets (for example DNS occupies DNS, rather than also occupying UDP). Bandwidth buckets include `interval_seconds`; the UI divides bucket totals by that width to display rates.

**Actual result:** live experiment NOT RUN. Separate historical DHCP/DNS import validations passed; see validation record.

**Packet observations:** compare individual packet lengths with summed protocol volume. Captured length excludes overhead absent from the capture, such as typical Ethernet FCS/preamble.

## Experiment 3 — Analyze communication between hosts

**Objective:** relate endpoint statistics and bidirectional flows to actual host exchanges.

**Configuration:** active lab, same-VLAN eng1/eng2; capture `ns-sw-eth1`.

**Commands:** run the experiment 1 ICMP curl request; then:

```bash
curl -f http://127.0.0.1:8765/api/analytics/devices
curl -f http://127.0.0.1:8765/api/analytics/flows
```

**Expected:** eng1/eng2 IPs appear; reverse traffic joins the same transport tuple. ARP produces device observations but is excluded from IP flows. ICMP has no TCP/UDP ports. Source/destination device counters describe roles; summing all device volumes double-counts packets observed at both endpoints.

**Actual result:** NOT RUN on the lab here.

**Packet observations:** note request/reply direction, MAC/IP associations, flow start/end timestamps, and number of observations. Flow grouping does not implement idle expiry or stream reassembly; repeated TCP payload sequence/length pairs are retransmission estimates.

## Experiment 4 — Create VLANs and inspect assignments

**Objective:** verify actual OVS access ports, trunk tags, and Linux router subinterfaces.

**Configuration:** explicitly started topology, VLANs 10/20/30 with two hosts each.

**Commands:**

```bash
.venv/bin/python -m network.vlan_config
sudo ovs-vsctl --columns=name,tag,trunks,vlan_mode list port
curl -f http://127.0.0.1:8765/api/topology
```

The API filters observations to the lab. Optional hostless VLAN addition:

```bash
.venv/bin/python -m network.vlan_config --add 40 --name Operations --subnet 192.168.40.0/24
```

**Expected:** access port tags match the inventory; the router port has trunk mode and VLANs 10,20,30 (plus optional 40); router interfaces end `.10`, `.20`, `.30`. New VLANs initially have no assigned hosts. Fixed host reassignment and deletion of live VLANs are intentionally unsupported. Restart to reset the live lab; stored desired extra VLANs can be reapplied explicitly.

**Actual result:** NOT RUN here; OVS/Mininet are unavailable. Dashboard planned definitions are not active VLAN evidence.

**Packet observations:** access traffic is normally untagged; trunk traffic carries the VLAN ID.

## Experiment 5 — Verify same-VLAN communication

**Objective:** demonstrate Layer 2 communication within one broadcast domain.

**Configuration:** lab running; routing disabled.

```bash
.venv/bin/python -m network.routing disable
curl -f -H 'Content-Type: application/json' -d '{"source":"eng1","destination":"eng2","count":3}' \
  http://127.0.0.1:8765/api/segmentation/test
```

**Expected:** three successful probes after address resolution, using switching without inter-VLAN forwarding. ACLs on the router's forward chain do not mediate same-VLAN traffic.

**Actual result:** NOT RUN here.

**Packet observations:** peer ARP and ICMP; record raw ping output and selected capture session.

## Experiment 6 — Verify isolation without routing

**Objective:** test that separated VLANs cannot communicate through a disabled gateway.

**Configuration:** same lab, IPv4 forwarding disabled.

```bash
.venv/bin/python -m network.routing disable
curl -f -H 'Content-Type: application/json' -d '{"source":"eng1","destination":"adm1","count":3}' \
  http://127.0.0.1:8765/api/segmentation/test
```

**Expected:** no reply, ping exit code 1, router forwarding observed as disabled. Same-VLAN communication should remain available as a control.

**Actual result:** NOT RUN here.

**Packet observations:** distinguish gateway ARP from end-to-end delivery. A timeout alone cannot identify the cause of packet loss.

## Experiment 7 — Enable inter-VLAN routing

**Objective:** verify Layer 3 communication through VLAN gateway interfaces.

**Configuration:** no enabled ACLs; routing on.

```bash
.venv/bin/python -m network.routing enable
curl -f -H 'Content-Type: application/json' -d '{"source":"eng1","destination":"adm1","count":3}' \
  http://127.0.0.1:8765/api/segmentation/test
.venv/bin/python -m network.routing status
```

**Expected:** replies from Administration. The routed packet changes Ethernet endpoints and VLAN tag at the gateway, and IPv4 TTL decreases on forwarding.

**Actual result:** NOT RUN here.

**Packet observations:** compare both VLAN sides of the trunk and inspect IP TTL, Ethernet addresses, and VLAN IDs.

## Experiment 8 — Apply ACLs and compare outcomes

**Objective:** independently verify allowed, denied, and ICMP-specific policy behavior.

**Configuration:** active lab. The scenario runner temporarily changes only the lab and restores its initial policy/routing in `finally`.

```bash
.venv/bin/python -m network.scenarios --output data/experiments/network-results.json
```

The runner checks same-VLAN communication, isolation, routing, Engineering→Administration allow, Finance→Engineering deny, Administration→Finance allow, and a specific Engineering→Administration ICMP deny using a fresh host pair. It saves actual ping output, exit codes, expectations, match results, inspected OVS state, and firewall counters. It exits nonzero on mismatches.

For interactive rule operations:

```bash
.venv/bin/python -m network.firewall add --source-vlan 10 --destination-vlan 30 --verdict allow
.venv/bin/python -m network.firewall list
# Substitute the returned identifier:
.venv/bin/python -m network.firewall disable RULE_ID
.venv/bin/python -m network.firewall enable RULE_ID
.venv/bin/python -m network.firewall remove RULE_ID
```

**Expected:** results match the stated policy; independent ICMP deny precedes the broader allow for new conversations. Existing tracked conversations can continue because established replies are stateful.

**Actual result:** NOT RUN here. Inspect the saved report; do not replace it with anticipated values. CLI mutation commands persist desired configuration for the dashboard when invoked by the same local user/data settings.

**Packet observations:** correlate denied probes with router firewall counters, and allowed probes with replies. Preserve raw test output and PCAP evidence.

## Experiment 9 — Capture 802.1Q tags on the trunk

**Objective:** inspect real VLAN IDs, PCP, DEI, and encapsulated EtherType.

**Configuration:** lab active; capture root-namespace trunk interface `ns-sw-eth7`. Enable routing for the cross-VLAN probe and disable conflicting ACLs.

```bash
sudo tcpdump -i ns-sw-eth7 -nn -s 0 -w /tmp/netscope-trunk.pcap 'vlan'
```

In another terminal, trigger the real eng1→adm1 connectivity request from experiment 7. Stop tcpdump with Ctrl+C, then import `/tmp/netscope-trunk.pcap` into NetScope. Alternatively use NetScope live capture with the same interface/filter and appropriate privileges.

**Expected:** trunk frames include 802.1Q; Engineering traffic uses VLAN 10 and Administration uses VLAN 30. The inspector exposes tags, PCP, DEI, and EtherType. Do not infer tags from the topology diagram. Physical NIC offloads and capture position can affect whether tags are visible; virtual trunk observation must still be verified.

**Actual result:** NOT RUN here. Constructed parser fixtures verify extraction only.

**Packet observations:** record selected tagged packet IDs/fields and compare Wireshark or `tcpdump -nn -e -r /tmp/netscope-trunk.pcap`.

## Automated privileged checks and cleanup

Application parser/API tests run without special privileges:

```bash
./scripts/test.sh
```

Authorized live loopback integration (run in the configured capture-capable service/interpreter environment):

```bash
NETSCOPE_RUN_LIVE_TESTS=1 .venv/bin/python -m pytest backend/tests/test_live_capture.py -v -ra
```

To let pytest create and destroy its own lab, first stop any manually started lab. Use a virtual environment made with `--system-site-packages` so Ubuntu's Mininet package is visible, or install Mininet for the chosen interpreter:

```bash
sudo env NETSCOPE_RUN_NETWORK_TESTS=1 .venv/bin/python -m pytest network/tests/test_privileged.py -v -ra
```

Stop the manually started lab gracefully using Ctrl+C in its terminal or:

```bash
.venv/bin/python -m network.cleanup
./scripts/stop.sh
```

Cleanup is scoped to the agent's lab. An unavailable agent does not authorize deleting arbitrary host interfaces; inspect any orphaned `ns-*` resources manually. Avoid global `mn -c` on hosts running unrelated labs.
