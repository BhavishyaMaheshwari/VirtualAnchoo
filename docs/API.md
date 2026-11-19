# API reference

Development API base: `http://127.0.0.1:8765`. The Vite dashboard proxies `/api` and `/ws`. OpenAPI at `/docs` is the authoritative schema for the running version.

The service is a trusted, local, single-operator tool. It is not an authenticated public API. Bind to loopback. Input validation and browser-origin restrictions reduce accidental misuse but do not replace authentication or deployment hardening.

## Capture and history

| Method and path | Purpose |
| --- | --- |
| `GET /api/interfaces` | Enumerate local capture interfaces and observable addresses/status. |
| `POST /api/capture/start` | Start one authorized live capture. Requires live mode and OS permissions. |
| `POST /api/capture/stop` | Stop capture and finalize the session. |
| `GET /api/capture/status` | Capture state, selected interface/filter, session, counts, and errors. |
| `POST /api/capture/import` | Import multipart field `file`; accepts supported PCAP/PCAPNG capture data. |
| `GET /api/capture/{session_id}/export` | Download a stopped session's capture file. |
| `GET /api/sessions` | List up to 100 recent persisted sessions, newest first. |
| `DELETE /api/sessions/{session_id}` | Delete a stopped session, its metadata, and its capture file. |

Start request:

```json
{
  "interface": "lo",
  "bpf_filter": "icmp",
  "packet_limit": 1000,
  "authorized": true
}
```

`authorized` must be `true`, `packet_limit` must be 1–100000, and the interface must exist. Authorization is the operator's assertion that they may monitor this interface. A nonempty BPF filter needs a working filter compiler. The API does not silently retry an invalid filter as unfiltered capture.

Sessions include `id`, `source` (`live` or `import`), `name`, `interface`, `bpf_filter`, `started_at`, `ended_at`, `status`, `packet_count`, `byte_count`, and `error`. Session start/end are workflow wall-clock times; each packet has its own capture timestamp. Imported historical packet times can precede the session's import time by years.

Limits: 64 MiB upload, 100000 packets per session, 128 MiB live capture file, and a 1 GiB storage guard. Capture errors remain observable; a partial/error session must not be reported as a complete successful capture. Stop a live session before exporting or deleting it.

## Packets

`GET /api/packets` returns `{items, total, page, page_size}` ordered newest stored packet first. `GET /api/packets/{packet_id}` returns one structured record.

| Query | Meaning |
| --- | --- |
| `session_id` | Selected capture session; defaults to the newest session. |
| `page`, `page_size` | One-based page; page size 1–500 (default 100). |
| `protocol` | Exact displayed protocol label. |
| `src_ip`, `dst_ip` | Validated exact IPv4/IPv6 address. |
| `src_port`, `dst_port` | Exact port, 0–65535. |
| `vlan_id` | Observed tag ID, 0–4094; 0 is a priority-tagged frame. |
| `min_size`, `max_size` | Inclusive captured-length limits in bytes. |
| `start_time`, `end_time` | Inclusive Unix timestamp limits, in seconds. |
| `search` | Substring search through endpoint/protocol/metadata text, up to 200 characters. |

Packet fields include `id`, `session_id`, `timestamp`, `length`, `protocol`, `transport_protocol`, `src_ip`, `dst_ip`, `src_mac`, `dst_mac`, `src_port`, `dst_port`, `vlan_id`, `direction`, `interface`, `info`, and `layers`. Unavailable values are absent or null. `layers` is an object keyed by decoded protocol layer; individual packet shapes vary because not every frame contains every layer.

```bash
curl -f 'http://127.0.0.1:8765/api/packets?protocol=DNS&page_size=25'
curl -f 'http://127.0.0.1:8765/api/packets?src_ip=192.168.10.11&vlan_id=10'
```

## Analytics

All analytics endpoints accept optional `session_id`. Empty sessions produce zero/empty aggregates. Results may be cached briefly during live capture; the cache is bounded and refreshed as packet counts change.

| Path under `/api/analytics` | Result |
| --- | --- |
| `/overview` | Total packets/bytes, average/min/max size, session-average rates, observed/active flows, directions, session provenance. |
| `/protocols` | Array of protocol, packet count (`count`), bytes, and percentage. |
| `/bandwidth` | Array of timestamp, packets, bytes, and `interval_seconds`. |
| `/devices` | Array of IP, observed MACs, total packets/bytes, sent/received packets/bytes. |
| `/flows` | Bidirectional transport flow aggregates, endpoints, times, packet/byte counts, flags, state, retransmission estimates. |
| `/sizes` | Array of `{range, count}` captured-length histogram bins. |
| `/vlans` | Array of `{vlan_id, packets, bytes}`; a null ID means no observed VLAN tag. |

### Interpretation

- `length` counts captured bytes, not Ethernet wire-time overhead. Preamble, inter-frame gap, and truncated bytes are not included.
- Overview packets/second and bytes/second divide by the span between first and last observed packet, with a minimum denominator of one second. They are **session-average rates**, not a present-moment interface meter.
- Bandwidth uses at most 600 time bins, including idle intervals. Divide a bin's bytes or packets by its `interval_seconds` to obtain a per-second rate. For bits/second multiply bytes/second by eight.
- Protocol percentages divide by the session's packet count. An application label such as DNS/HTTPS is not additional traffic on top of its TCP/UDP carrier.
- Device totals count observations touching each IP. A packet between two different devices contributes to each device's activity; summing device totals therefore double-counts those packet bytes. MAC/IP associations are observations, not authenticated identity.
- Direction is relative to addresses observable on the selected live interface. Imported captures generally lack enough local interface context and remain `unknown`; loopback observations can be separate from incoming/outgoing.
- A flow canonicalizes endpoint IP/port pairs plus transport protocol across the entire session. It does not expire on idle timeout or split reused tuples into connection instances. There is no full TCP stream reassembly.
- TCP FIN/RST can mark a flow closed; other observed flows are considered active for this limited counter. This is not proof of an established or currently transmitting connection. UDP/ICMP do not have a TCP connection lifecycle.
- Retransmission estimates count repeated TCP payload sequence/length observations per direction with bounded recent-segment memory. Duplicate capture, overlap, reordering, missing packets, and sequence wraparound limit accuracy. They are not authoritative loss measurements.
- VLAN is not currently part of the canonical flow key. Captures containing overlapping IP/port spaces in multiple VLANs can merge flows; keep those captures/session analyses separate.
- TLS labels use available dissection/port hints. No endpoint decrypts HTTPS payloads.

## Live WebSocket events

Connect to `ws://127.0.0.1:8765/ws`, or use the dashboard's same-origin `/ws` proxy. Event envelopes are:

```json
{"type": "packet", "data": {"id": 42, "session_id": "...", "protocol": "DNS"}}
```

The shown packet object is abbreviated; actual events carry parsed packet metadata. Other event types include `capture_status` and `analytics`. Consumers must check `type`, scope packet events to the selected session, and refresh REST state after reconnecting.

Each connected client has a bounded notification queue. Slow consumers may lose notifications rather than blocking capture; persisted packet history remains the recovery source. This stream is not a guaranteed-delivery message log.

## VLAN topology and segmentation

| Method and path | Purpose |
| --- | --- |
| `GET /api/vlans` | Desired VLAN configuration and live availability/application state. |
| `POST /api/vlans` | Validate and save a VLAN configuration; apply it when supported and the lab is available. |
| `GET /api/topology` | Hosts, switch/router, connections, VLAN groups, and truthful lab status. |
| `POST /api/topology/routing` | Set router-namespace forwarding with `{enabled: true/false}`. |
| `GET /api/segmentation/rules` | Saved access rules and application status. |
| `POST /api/segmentation/rules` | Add an allow/deny rule. |
| `PATCH /api/segmentation/rules/{rule_id}` | Enable or disable a saved rule. |
| `DELETE /api/segmentation/rules/{rule_id}` | Remove a rule. |
| `POST /api/segmentation/test` | Run bounded ICMP connectivity testing between two fixed lab hosts. |

VLAN definition example:

```json
{"id": 40, "name": "Research", "subnet": "192.168.40.0/24"}
```

The example lab reserves VLANs 10, 20, and 30 and their subnets for its six fixed hosts. Additional VLANs do not automatically create new hosts or assign arbitrary host interfaces. VLAN IDs are 1–4094; subnets must be validated private IPv4 networks in the supported prefix range and must not overlap.

Rule example:

```json
{
  "source_vlan": 10,
  "destination_vlan": 30,
  "protocol": "icmp",
  "destination_port": null,
  "action": "allow",
  "enabled": true,
  "description": "Engineering can ping Administration"
}
```

Supported protocols are `any`, `icmp`, `tcp`, and `udp`; a destination port is valid only for TCP/UDP. Rules refer to configured VLAN IDs. They affect new inter-VLAN forwarded traffic in the router namespace. Established/related return traffic is accepted; enabled denies take precedence over allows. With enabled rules, unmatched forwarded traffic is dropped. With no enabled rules, forwarding policy is accept, while the routing switch still controls whether IP forwarding is enabled.

Connectivity request:

```json
{"source": "eng1", "destination": "adm1", "count": 3}
```

Sources/destinations must be one of `eng1`, `eng2`, `fin1`, `fin2`, `adm1`, or `adm2`; count is 1–5. Results include the executed argument list, exit code, timestamp, raw ping output, packet counts/loss when parsed, and success. A failure is labelled unreachable, not automatically “blocked by firewall.” No arbitrary command or address is accepted for a connectivity test.

## Errors

FastAPI error bodies include `detail`; validation can return structured field errors. Common statuses are `422` for invalid inputs, `404` for missing sessions/packets, `409` for incompatible capture lifecycle operations, `400` for invalid capture imports, and `413` for oversized uploads. Lab-dependent operations report unavailable/error state if the agent or prerequisites cannot be reached. Inspect the returned message instead of treating an HTTP failure as a connectivity experiment.

## Import/export coverage

Imports preserve the original PCAP or PCAPNG bytes, including mixed-interface link types. Exports use the matching extension. The analysis is bounded to the first 100,000 packets or the per-session byte ceiling; a `limited` session/error message reports this explicitly. The exported original file can contain packets beyond the analyzed prefix. Partial malformed-file errors are surfaced rather than reported as complete imports. No imported traffic is labelled live.
