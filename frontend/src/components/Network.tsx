import { useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  MarkerType,
  Handle,
  Position,
} from "@xyflow/react";
import type { NodeProps, Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Network,
  Router,
  Monitor,
  Server,
  Plus,
  ArrowRight,
  ShieldCheck,
  Trash2,
  Play,
  Terminal,
  Info,
  X,
  ToggleLeft,
  ToggleRight,
} from "lucide-react";
import type { AppData } from "../hooks/useData";
import type { Connectivity, Dict, Rule } from "../types";
import { api } from "../services/api";
import { Panel, Empty } from "./Charts";
import { time } from "../utils/format";
const vlanColor = (id: number | undefined) =>
  id === 10
    ? "#608f35"
    : id === 20
      ? "#8271b2"
      : id === 30
        ? "#bc8b3d"
        : "#6489bc";
function NetworkNode({
  data,
}: NodeProps<
  Node<{ label: string; kind: string; ip?: string; vlan_id?: number }>
>) {
  const Icon =
    data.kind === "router" ? Router : data.kind === "switch" ? Server : Monitor;
  return (
    <div
      className={`network-node ${data.kind}`}
      style={{ "--node-color": vlanColor(data.vlan_id) } as React.CSSProperties}
    >
      <Handle type="target" position={Position.Top} />
      <span className="node-icon">
        <Icon size={20} />
      </span>
      <div>
        <strong>{data.label}</strong>
        <small>
          {data.ip ||
            (data.kind === "switch" ? "Open vSwitch" : "802.1Q gateway")}
        </small>
      </div>
      {data.vlan_id && <span className="node-vlan">{data.vlan_id}</span>}
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}
const nodeTypes = { device: NetworkNode };
type Props = {
  data: AppData;
  notify: (message: string) => void;
  run: (fn: () => Promise<unknown>, success?: string) => Promise<void>;
  busy: boolean;
};
export function TopologyPage({ data, run, busy }: Props) {
  const [selected, setSelected] = useState<Dict | null>(null);
  const topology = data.topology;
  const nodes = useMemo(
    () =>
      (topology?.nodes || []).map((n) => ({
        id: n.id,
        type: "device",
        position: n.position,
        data: { ...n, kind: n.type },
      })),
    [topology],
  );
  const edges = useMemo(
    () =>
      (topology?.edges || []).map((e) => ({
        ...e,
        type: "smoothstep",
        style: { stroke: "#a8bca0", strokeWidth: 1.5 },
        labelStyle: { fill: "#546b58", fontSize: 11 },
        labelBgStyle: { fill: "#ffffff" },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: "#a8bca0",
          width: 10,
          height: 10,
        },
      })),
    [topology],
  );
  return (
    <>
      <div className={`notice ${topology?.running ? "success" : ""}`}>
        <Info size={17} />
        <span>
          {topology?.message || "Loading the virtual network configuration…"}{" "}
          {!topology?.running &&
            "Diagram shows configured topology, not observed live connectivity."}
        </span>
      </div>
      <section className="panel topology-panel">
        <div className="panel-heading">
          <div>
            <h2>Enterprise network</h2>
            <p>Department segmentation · IEEE 802.1Q</p>
          </div>
          <span className={`badge ${topology?.running ? "green" : ""}`}>
            <span className="status-orb" />
            {topology?.running ? "Lab active" : "Planned topology"}
          </span>
        </div>
        <div className="topology-canvas">
          {nodes.length ? (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{ padding: 0.2 }}
              nodesDraggable={false}
              nodesConnectable={false}
              elementsSelectable
              onNodeClick={(_, node) => setSelected(node.data)}
              colorMode="light"
              minZoom={0.25}
              maxZoom={1.8}
            >
              <Background color="#dce9d5" gap={24} size={1} />
              <Controls showInteractive={false} />
              <MiniMap
                nodeColor={(n) => vlanColor(n.data.vlan_id as number)}
                maskColor="#f8faf5aa"
              />
            </ReactFlow>
          ) : (
            <Empty
              title="Topology unavailable"
              text="Start the backend to inspect the network configuration."
            />
          )}
        </div>
        <div className="topology-footer">
          <div className="legend-inline">
            {data.vlans.map((v) => (
              <span key={v.id}>
                <i style={{ background: vlanColor(v.id) }} />
                {v.name} · VLAN {v.id}
              </span>
            ))}
          </div>
          <span>Click a device to inspect</span>
        </div>
      </section>
      <div className="grid-two">
        <Panel title="Inter-VLAN routing" eyebrow="LAYER 3">
          <div className="routing-panel">
            <div>
              <strong>
                {topology?.routing_enabled
                  ? "Routing enabled"
                  : "Routing disabled"}
              </strong>
              <p>
                Routing changes are applied inside the lab router namespace.
              </p>
            </div>
            <button
              className="button"
              disabled={busy || !topology?.running}
              onClick={() =>
                void run(
                  () =>
                    api("/topology/routing", {
                      method: "POST",
                      body: JSON.stringify({
                        enabled: !topology?.routing_enabled,
                      }),
                    }),
                  "Routing updated",
                )
              }
            >
              {topology?.routing_enabled ? (
                <ToggleRight size={20} />
              ) : (
                <ToggleLeft size={20} />
              )}{" "}
              {topology?.routing_enabled ? "Disable" : "Enable"}
            </button>
          </div>
        </Panel>
        <Panel title="Network inventory" eyebrow="CONFIGURATION">
          <div className="inventory">
            <div>
              <strong>
                {nodes.filter((n) => n.data.kind === "host").length}
              </strong>
              <span>Hosts</span>
            </div>
            <div>
              <strong>
                {nodes.filter((n) => n.data.kind === "switch").length}
              </strong>
              <span>Switches</span>
            </div>
            <div>
              <strong>
                {nodes.filter((n) => n.data.kind === "router").length}
              </strong>
              <span>Routers</span>
            </div>
            <div>
              <strong>{data.vlans.length}</strong>
              <span>VLANs</span>
            </div>
          </div>
        </Panel>
      </div>
      {selected && (
        <div className="modal-backdrop" onClick={() => setSelected(null)}>
          <section
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="node-title"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-heading">
              <h2 id="node-title">{String(selected.label)}</h2>
              <button
                className="icon-button"
                aria-label="Close node details"
                onClick={() => setSelected(null)}
              >
                <X size={18} />
              </button>
            </div>
            <dl className="node-details">
              {Object.entries(selected)
                .filter(([k]) => !["position", "label"].includes(k))
                .map(([k, v]) => (
                  <div key={k}>
                    <dt>{k}</dt>
                    <dd>
                      {typeof v === "object"
                        ? JSON.stringify(v, null, 2)
                        : String(v ?? "—")}
                    </dd>
                  </div>
                ))}
            </dl>
          </section>
        </div>
      )}
    </>
  );
}
export function VlanPage({ data, run, busy }: Props) {
  const [show, setShow] = useState(false);
  const [form, setForm] = useState({ id: "", name: "", subnet: "" });
  return (
    <>
      <div className="section-heading">
        <p className="muted">
          Isolated broadcast domains for your virtual enterprise network.
        </p>
        <button className="button primary" onClick={() => setShow(true)}>
          <Plus size={15} />
          Add VLAN
        </button>
      </div>
      <div className="vlan-grid">
        {data.vlans.map((v) => (
          <section
            className="panel vlan-card"
            key={v.id}
            style={{ "--vlan-color": vlanColor(v.id) } as React.CSSProperties}
          >
            <div className="vlan-card-head">
              <span className="vlan-icon">
                <Network size={21} />
              </span>
              <span className={`badge ${v.status === "active" ? "green" : ""}`}>
                {v.status === "active" ? "Active" : "Planned"}
              </span>
            </div>
            <div className="eyebrow">VLAN {v.id}</div>
            <h2>{v.name}</h2>
            <p className="mono">{v.subnet}</p>
            <dl>
              <div>
                <dt>Gateway</dt>
                <dd>{v.gateway || "—"}</dd>
              </div>
              <div>
                <dt>Connected hosts</dt>
                <dd>
                  {v.hosts?.length || 0}
                  {v.status !== "active" ? " configured" : ""}
                </dd>
              </div>
              <div>
                <dt>Port mode</dt>
                <dd>{v.mode || "access"}</dd>
              </div>
              <div>
                <dt>Trunk interface</dt>
                <dd>{v.trunk || "—"}</dd>
              </div>
            </dl>
            <div className="vlan-hosts">
              {v.hosts?.map((h) => (
                <span key={h.name}>
                  <Monitor size={12} />
                  {h.name}
                  <small>{h.ip}</small>
                </span>
              ))}
            </div>
          </section>
        ))}
      </div>
      <Panel title="Switch port configuration" eyebrow="OPEN VSWITCH">
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>VLAN</th>
                <th>DEPARTMENT</th>
                <th>ACCESS PORTS</th>
                <th>TRUNK</th>
                <th>STATUS</th>
              </tr>
            </thead>
            <tbody>
              {data.vlans.map((v) => (
                <tr key={v.id}>
                  <td>
                    <span
                      className="vlan-chip"
                      style={{ color: vlanColor(v.id) }}
                    >
                      {v.id}
                    </span>
                  </td>
                  <td>{v.name}</td>
                  <td className="mono">
                    {v.ports?.join(", ") || "No ports assigned"}
                  </td>
                  <td className="mono">{v.trunk || "—"}</td>
                  <td>
                    <span
                      className={`badge ${v.status === "active" ? "green" : ""}`}
                    >
                      {v.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!data.vlans.length && (
          <Empty small title="No VLAN configurations available" />
        )}
      </Panel>
      <div className="notice">
        <Info size={16} />
        <span>
          VLAN definitions persist locally. Live changes require the explicitly
          started Mininet lab; planned configuration does not establish
          isolation by itself.
        </span>
      </div>
      {show && (
        <div className="modal-backdrop">
          <form
            role="dialog"
            aria-modal="true"
            aria-label="Network configuration"
            className="modal"
            onSubmit={(e) => {
              e.preventDefault();
              void run(async () => {
                await api("/vlans", {
                  method: "POST",
                  body: JSON.stringify({ ...form, id: Number(form.id) }),
                });
                setShow(false);
                setForm({ id: "", name: "", subnet: "" });
              }, "VLAN configuration saved");
            }}
          >
            <div className="modal-heading">
              <h2>Add VLAN</h2>
              <button
                className="icon-button"
                type="button"
                aria-label="Close VLAN form"
                onClick={() => setShow(false)}
              >
                <X size={18} />
              </button>
            </div>
            <p className="muted">
              Create a department network. The backend validates subnet and VLAN
              ID conflicts.
            </p>
            <label>
              VLAN ID
              <input
                required
                type="number"
                min="1"
                max="4094"
                value={form.id}
                onChange={(e) => setForm({ ...form, id: e.target.value })}
                placeholder="40"
              />
            </label>
            <label>
              Name
              <input
                required
                maxLength={64}
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Operations"
              />
            </label>
            <label>
              IPv4 subnet
              <input
                required
                value={form.subnet}
                onChange={(e) => setForm({ ...form, subnet: e.target.value })}
                placeholder="192.168.40.0/24"
              />
            </label>
            <button className="button primary full" disabled={busy}>
              Save VLAN
            </button>
          </form>
        </div>
      )}
    </>
  );
}
export function SegmentationPage({ data, run, busy, notify }: Props) {
  const [show, setShow] = useState(false),
    [form, setForm] = useState({
      source_vlan: "10",
      destination_vlan: "30",
      protocol: "any",
      destination_port: "",
      action: "allow",
      description: "",
      enabled: true,
    });
  const hosts = data.vlans.flatMap((v) => v.hosts || []);
  const [source, setSource] = useState("eng1"),
    [destination, setDestination] = useState("eng2"),
    [test, setTest] = useState<Connectivity | null>(null),
    [testing, setTesting] = useState(false);
  const route = data.topology?.routing_enabled;
  const testNetwork = async () => {
    setTesting(true);
    try {
      setTest(
        await api<Connectivity>("/segmentation/test", {
          method: "POST",
          body: JSON.stringify({ source, destination, count: 3 }),
        }),
      );
    } catch (e) {
      setTest(null);
      notify(e instanceof Error ? e.message : "Connectivity test failed");
    } finally {
      setTesting(false);
    }
  };
  const change = (r: Rule) =>
    void run(
      () =>
        api(`/segmentation/rules/${r.id}`, {
          method: "PATCH",
          body: JSON.stringify({ enabled: !r.enabled }),
        }),
      "Rule updated",
    );
  return (
    <>
      <div className="policy-banner">
        <span className="policy-icon">
          <ShieldCheck size={25} />
        </span>
        <div>
          <strong>
            {route
              ? "Inter-VLAN routing is enabled"
              : "Inter-VLAN routing is disabled"}
          </strong>
          <p>
            {data.rules.some((r) => r.enabled)
              ? "Enabled ACLs use default-deny forwarding, with established replies allowed."
              : "With no enabled ACLs, enabling routing permits communication between VLANs."}
          </p>
        </div>
        <span className={`badge ${data.topology?.running ? "green" : ""}`}>
          {data.topology?.running ? "Lab active" : "Lab offline"}
        </span>
      </div>
      <Panel
        title="Access control rules"
        eyebrow="NETWORK POLICIES"
        action={
          <div className="toolbar-actions">
            <button
              className="button compact"
              disabled={busy || !data.topology?.running}
              onClick={() =>
                void run(
                  () => api("/segmentation/apply", { method: "POST" }),
                  "Saved rules applied",
                )
              }
            >
              Apply saved rules
            </button>
            <button
              className="button primary compact"
              onClick={() => setShow(true)}
            >
              <Plus size={14} />
              Add rule
            </button>
          </div>
        }
      >
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>STATUS</th>
                <th>SOURCE</th>
                <th></th>
                <th>DESTINATION</th>
                <th>PROTOCOL</th>
                <th>PORT</th>
                <th>ACTION</th>
                <th>APPLICATION</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data.rules.map((r) => (
                <tr key={r.id}>
                  <td>
                    <button
                      className={`toggle ${r.enabled ? "on" : ""}`}
                      aria-label={`${r.enabled ? "Disable" : "Enable"} rule ${r.id}`}
                      disabled={busy}
                      onClick={() => change(r)}
                    >
                      {r.enabled ? (
                        <ToggleRight size={24} />
                      ) : (
                        <ToggleLeft size={24} />
                      )}
                    </button>
                  </td>
                  <td>
                    <strong className="normal">VLAN {r.source_vlan}</strong>
                    <small className="sub-cell">
                      {data.vlans.find((v) => v.id === r.source_vlan)?.name}
                    </small>
                  </td>
                  <td>
                    <ArrowRight size={14} className="muted" />
                  </td>
                  <td>
                    <strong className="normal">
                      VLAN {r.destination_vlan}
                    </strong>
                    <small className="sub-cell">
                      {
                        data.vlans.find((v) => v.id === r.destination_vlan)
                          ?.name
                      }
                    </small>
                  </td>
                  <td className="mono">{r.protocol.toUpperCase()}</td>
                  <td className="mono">{r.destination_port ?? "Any"}</td>
                  <td>
                    <span
                      className={`badge ${r.action === "allow" ? "green" : "red"}`}
                    >
                      {r.action}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${r.applied ? "green" : ""}`}>
                      {r.applied ? "Applied" : "Saved"}
                    </span>
                  </td>
                  <td>
                    <button
                      className="icon-button danger"
                      disabled={busy}
                      aria-label={`Delete rule ${r.id}`}
                      onClick={() =>
                        void run(
                          () =>
                            api(`/segmentation/rules/${r.id}`, {
                              method: "DELETE",
                            }),
                          "Rule removed",
                        )
                      }
                    >
                      <Trash2 size={15} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!data.rules.length && (
          <Empty
            small
            title="No access rules configured"
            text="Add policies to control traffic between departments. No rule is treated as applied until the lab confirms it."
          />
        )}
      </Panel>
      <div className="grid-two">
        <Panel
          title="Test connectivity"
          eyebrow="VERIFY ON THE NETWORK"
          action={<Terminal size={17} className="muted" />}
        >
          <div className="test-form">
            <div className="test-hosts">
              <label>
                Source host
                <select
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                >
                  {hosts.map((h) => (
                    <option key={h.name} value={h.name}>
                      {h.name} · {h.ip}
                    </option>
                  ))}
                </select>
              </label>
              <ArrowRight size={17} />
              <label>
                Destination host
                <select
                  value={destination}
                  onChange={(e) => setDestination(e.target.value)}
                >
                  {hosts.map((h) => (
                    <option key={h.name} value={h.name}>
                      {h.name} · {h.ip}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <p className="muted">
              Runs three actual ICMP probes from the selected host namespace.
            </p>
            <button
              className="button primary"
              disabled={testing || !data.topology?.running || !hosts.length}
              onClick={() => void testNetwork()}
            >
              <Play size={14} />
              {testing ? "Testing…" : "Run connectivity test"}
            </button>
            {!data.topology?.running && (
              <small className="muted">
                Start the Mininet lab to run this test.
              </small>
            )}
          </div>
        </Panel>
        <Panel title="Test result" eyebrow="OBSERVED EVIDENCE">
          {test ? (
            <div className="test-result">
              <div className="test-result-head">
                <span className={`badge ${test.success ? "green" : "red"}`}>
                  {test.success ? "Reachable" : "No reply"}
                </span>
                <span className="muted">{time(test.executed_at, true)}</span>
              </div>
              <div className="test-metrics">
                <span>
                  <b>
                    {test.received}/{test.transmitted}
                  </b>{" "}
                  packets received
                </span>
                <span>
                  <b>{test.packet_loss}%</b> loss
                </span>
                <span>
                  <b>{test.rtt_ms ?? "—"}</b> ms RTT
                </span>
              </div>
              <pre>{test.output || test.error}</pre>
              <p className="muted">
                A failed probe alone does not prove an ACL blocked traffic.
                Check routing, host state, and firewall counters.
              </p>
            </div>
          ) : (
            <Empty
              small
              title="No test run yet"
              text="Results come from actual Linux network probes."
            />
          )}
        </Panel>
      </div>
      {show && (
        <div className="modal-backdrop">
          <form
            role="dialog"
            aria-modal="true"
            aria-label="Network configuration"
            className="modal"
            onSubmit={(e) => {
              e.preventDefault();
              void run(async () => {
                await api("/segmentation/rules", {
                  method: "POST",
                  body: JSON.stringify({
                    ...form,
                    source_vlan: Number(form.source_vlan),
                    destination_vlan: Number(form.destination_vlan),
                    destination_port: form.destination_port
                      ? Number(form.destination_port)
                      : null,
                  }),
                });
                setShow(false);
              }, "Access rule saved");
            }}
          >
            <div className="modal-heading">
              <h2>Add access rule</h2>
              <button
                className="icon-button"
                type="button"
                aria-label="Close access rule form"
                onClick={() => setShow(false)}
              >
                <X size={18} />
              </button>
            </div>
            <div className="form-grid">
              {(["source_vlan", "destination_vlan"] as const).map((k) => (
                <label key={k}>
                  {k === "source_vlan" ? "Source VLAN" : "Destination VLAN"}
                  <select
                    value={form[k]}
                    onChange={(e) => setForm({ ...form, [k]: e.target.value })}
                  >
                    {data.vlans.map((v) => (
                      <option key={v.id} value={v.id}>
                        {v.id} · {v.name}
                      </option>
                    ))}
                  </select>
                </label>
              ))}
              <label>
                Protocol
                <select
                  value={form.protocol}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      protocol: e.target.value,
                      destination_port: "",
                    })
                  }
                >
                  {["any", "icmp", "tcp", "udp"].map((p) => (
                    <option key={p}>{p}</option>
                  ))}
                </select>
              </label>
              <label>
                Destination port
                <input
                  type="number"
                  min={1}
                  max={65535}
                  disabled={!["tcp", "udp"].includes(form.protocol)}
                  value={form.destination_port}
                  placeholder="Any"
                  onChange={(e) =>
                    setForm({ ...form, destination_port: e.target.value })
                  }
                />
              </label>
            </div>
            <label>
              Action
              <select
                value={form.action}
                onChange={(e) => setForm({ ...form, action: e.target.value })}
              >
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
              </select>
            </label>
            <label>
              Description
              <input
                maxLength={200}
                value={form.description}
                onChange={(e) =>
                  setForm({ ...form, description: e.target.value })
                }
                placeholder="Engineering access to Administration"
              />
            </label>
            <div className="notice">
              Enabled rules activate default-deny forwarding. Replies to
              established allowed connections are permitted.
            </div>
            <button className="button primary full" disabled={busy}>
              Save rule
            </button>
          </form>
        </div>
      )}
    </>
  );
}
