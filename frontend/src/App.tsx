import { useEffect, useRef, useState } from "react";
import {
  Activity,
  LayoutDashboard,
  ScanLine,
  ChartNoAxesCombined,
  Network,
  Layers,
  ShieldCheck,
  ChevronRight,
  ChevronDown,
  Upload,
  Download,
  Play,
  Square,
  Radio,
  ArrowUpRight,
  ArrowDownLeft,
  Cable,
  GitBranch,
  RefreshCw,
  X,
  Menu,
  Terminal,
  FileInput,
  LoaderCircle,
  CheckCircle2,
  AlertTriangle,
  Command,
  Trash2,
  FileSearch,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useData } from "./hooks/useData";
import { api } from "./services/api";
import { bytes, number, time } from "./utils/format";
import type { Session } from "./types";
import {
  Panel,
  Empty,
  TrafficChart,
  ProtocolChart,
  DeviceTable,
  SizeChart,
  Stat,
  Health,
  SectionLink,
  ChartLabel,
} from "./components/Charts";
import { PacketAnalyzer } from "./components/PacketAnalyzer";
import { TopologyPage, VlanPage, SegmentationPage } from "./components/Network";
const nav: { id: string; label: string; icon: LucideIcon; caption: string }[] =
  [
    {
      id: "overview",
      label: "Overview",
      icon: LayoutDashboard,
      caption: "Your network, in focus.",
    },
    {
      id: "packets",
      label: "Packet Analyzer",
      icon: ScanLine,
      caption: "Every packet. A clearer picture.",
    },
    {
      id: "analytics",
      label: "Traffic Analytics",
      icon: ChartNoAxesCombined,
      caption: "Understand how your network communicates.",
    },
    {
      id: "topology",
      label: "Network Topology",
      icon: Network,
      caption: "A connected view of your virtual network.",
    },
    {
      id: "vlans",
      label: "VLAN Management",
      icon: Layers,
      caption: "Organize your network into secure segments.",
    },
    {
      id: "segmentation",
      label: "Access Control",
      icon: ShieldCheck,
      caption: "Define boundaries. Verify communication.",
    },
  ];
export default function App() {
  const [page, setPage] = useState(() => {
      const p = location.hash.slice(1);
      return nav.some((n) => n.id === p) ? p : "overview";
    }),
    [sessionId, setSessionId] = useState<string | undefined>(undefined),
    [sidebar, setSidebar] = useState(false),
    [captureDialog, setCaptureDialog] = useState(false),
    [deleteDialog, setDeleteDialog] = useState(false),
    [busy, setBusy] = useState(false),
    [toast, setToast] = useState(""),
    [toastError, setToastError] = useState(false),
    [captureForm, setCaptureForm] = useState({
      interface: "",
      bpf_filter: "",
      packet_limit: "10000",
      authorized: false,
    });
  const data = useData(sessionId),
    fileRef = useRef<HTMLInputElement>(null),
    toastTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const active = nav.find((n) => n.id === page) || nav[0],
    overview = data.overview;
  const session =
    data.sessions.find((s) => s.id === sessionId) ||
    (!sessionId ? data.sessions[0] : undefined) ||
    overview.session;
  const isImport = session?.source === "import";
  const notify = (message: string, error = false) => {
    setToast(message);
    setToastError(error);
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(""), 6500);
  };
  const run = async (fn: () => Promise<unknown>, success?: string) => {
    setBusy(true);
    try {
      await fn();
      if (success) notify(success);
      await data.refresh();
    } catch (e) {
      notify(
        e instanceof Error ? e.message : "An unexpected error occurred",
        true,
      );
    } finally {
      setBusy(false);
    }
  };
  const navigate = (id: string) => {
    setPage(id);
    location.hash = id;
    setSidebar(false);
  };
  useEffect(() => {
    const change = () => {
      const p = location.hash.slice(1);
      if (nav.some((n) => n.id === p)) setPage(p);
    };
    window.addEventListener("hashchange", change);
    return () => window.removeEventListener("hashchange", change);
  }, []);
  useEffect(() => {
    if (!captureForm.interface && data.interfaces.length)
      setCaptureForm((f) => ({ ...f, interface: data.interfaces[0].name }));
  }, [data.interfaces, captureForm.interface]);
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setCaptureDialog(false);
        setDeleteDialog(false);
        setSidebar(false);
      }
      if (
        e.key === "/" &&
        !["INPUT", "TEXTAREA", "SELECT"].includes(
          (e.target as HTMLElement)?.tagName,
        )
      ) {
        e.preventDefault();
        navigate("packets");
        setTimeout(
          () =>
            document
              .querySelector<HTMLInputElement>('[aria-label="Search packets"]')
              ?.focus(),
          50,
        );
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);
  const importFile = (file: File) =>
    void run(async () => {
      const form = new FormData();
      form.append("file", file);
      const result = await api<
        Session & { session_id?: string; session?: Session }
      >("/capture/import", { method: "POST", body: form });
      setSessionId(result.id || result.session_id || result.session?.id);
      navigate("packets");
    }, "PCAP imported. Analysis is ready.");
  const start = () =>
    void run(async () => {
      await api("/capture/start", {
        method: "POST",
        body: JSON.stringify({
          ...captureForm,
          packet_limit: Number(captureForm.packet_limit),
        }),
      });
      setSessionId(undefined);
      setCaptureDialog(false);
      navigate("packets");
    }, "Live capture started");
  const networkProps = {
    data,
    run,
    busy,
    notify: (s: string) => notify(s, true),
  };
  const removeSession = () => {
    if (!session) return;
    void run(async () => {
      await api(`/sessions/${session.id}`, { method: "DELETE" });
      setSessionId(undefined);
      setDeleteDialog(false);
    }, "Capture session deleted");
  };
  return (
    <div className="app-shell">
      <input
        ref={fileRef}
        type="file"
        accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap,application/octet-stream"
        className="hidden"
        aria-label="Import PCAP file"
        onChange={(e) => {
          if (e.target.files?.[0]) importFile(e.target.files[0]);
          e.target.value = "";
        }}
      />
      {sidebar && (
        <div className="sidebar-shade" onClick={() => setSidebar(false)} />
      )}
      <aside className={`sidebar ${sidebar ? "open" : ""}`}>
        <a
          className="brand"
          href="#overview"
          onClick={() => navigate("overview")}
        >
          <div className="brand-mark">
            <Activity size={24} strokeWidth={2.4} />
          </div>
          <span>
            VirtualAnchoo<span className="brand-dot">.</span>
          </span>
        </a>
        <div className="workspace-card">
          <span className="workspace-icon">
            <Network size={18} />
          </span>
          <div>
            <strong>Local workspace</strong>
            <small>Network operations</small>
          </div>
          <ChevronDown size={14} />
        </div>
        <span className="nav-label">MONITOR</span>
        <nav>
          {nav.slice(0, 3).map(({ id, label, icon: Icon }) => (
            <button
              className={page === id ? "active" : ""}
              key={id}
              onClick={() => navigate(id)}
            >
              <Icon size={18} />
              <span>{label}</span>
              {page === id && <span className="nav-indicator" />}
            </button>
          ))}
          <span className="nav-label">NETWORK</span>
          {nav.slice(3).map(({ id, label, icon: Icon }) => (
            <button
              className={page === id ? "active" : ""}
              key={id}
              onClick={() => navigate(id)}
            >
              <Icon size={18} />
              <span>{label}</span>
              {page === id && <span className="nav-indicator" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-status">
            <span className={`status-orb ${data.online ? "green" : ""}`} />
            <span>
              {data.checking ? "Connecting to backend" : data.online ? "Backend connected" : "Backend disconnected"}
            </span>
            <span>v1.0</span>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-menu"
              onClick={() => setSidebar(!sidebar)}
              aria-label="Open navigation"
            >
              <Menu size={20} />
            </button>
            <span>Workspace</span>
            <ChevronRight size={13} />
            <strong>{active.label}</strong>
          </div>
          <div className="topbar-right">
            <span className="local-badge">
              <span className={`status-orb ${data.online ? "green" : ""}`} />
              LOCAL ENVIRONMENT
            </span>
            <div className="topbar-divider" />
            <span className="profile">NS</span>
          </div>
        </header>
        <main>
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                <span className="heading-line" />
                NETWORK INTELLIGENCE
              </div>
              <h1>{active.label}</h1>
              <p>{active.caption}</p>
            </div>
            <div className="heading-actions">
              <button
                className="icon-button refresh-button"
                onClick={() => void data.refresh()}
                aria-label="Refresh dashboard"
              >
                <RefreshCw size={16} />
              </button>
              <button
                className="button"
                disabled={busy || !data.online}
                onClick={() => fileRef.current?.click()}
              >
                {busy ? (
                  <LoaderCircle className="spin" size={15} />
                ) : (
                  <Upload size={15} />
                )}
                Import PCAP
              </button>
              <button
                className={`button ${data.capture.running ? "stop" : "primary"}`}
                disabled={busy || !data.online}
                onClick={() =>
                  data.capture.running
                    ? void run(
                        () => api("/capture/stop", { method: "POST" }),
                        "Capture stopped",
                      )
                    : setCaptureDialog(true)
                }
              >
                {data.capture.running ? (
                  <Square size={13} />
                ) : (
                  <Play size={14} />
                )}
                <span>
                  {data.capture.running ? "Stop capture" : "Start capture"}
                </span>
              </button>
            </div>
          </div>
          {!data.online && !data.checking && (
            <div className="notice warning">
              <AlertTriangle size={17} />
              <span>
                Backend unavailable. Start VirtualAnchoo locally to capture traffic
                or import a PCAP. <code>./scripts/start.sh</code>
              </span>
            </div>
          )}
          {data.online && data.error && (
            <div className="notice warning">
              <AlertTriangle size={16} />
              <span>{data.error}</span>
            </div>
          )}
          {data.capture.error && (
            <div className="notice warning">
              <AlertTriangle size={16} />
              <span>Capture: {data.capture.error}</span>
            </div>
          )}
          <section className="capture-strip">
            <div className="capture-state">
              <span
                className={`capture-icon ${data.capture.running ? "capturing" : ""}`}
              >
                <Radio size={17} />
              </span>
              <div>
                <strong>
                  {data.capture.running
                    ? "Capture in progress"
                    : session
                      ? isImport
                        ? "Imported capture"
                        : "Capture complete"
                      : data.capture.live_enabled ? "Ready to capture" : "Ready to analyze"}
                </strong>
                <small>
                  {data.capture.running
                    ? `${data.capture.interface} · ${number(data.capture.packet_count)} packets`
                    : session
                      ? `${session.name || session.interface || "Capture session"} · ${time(session.started_at, true)}`
                      : data.capture.live_enabled ? "Select an interface or import a capture file to begin" : "Import a PCAP file to begin; enable live mode for capture"}
                </small>
              </div>
              {data.capture.running && (
                <span className="badge green live-badge">
                  <span className="status-orb green" />
                  LIVE
                </span>
              )}
            </div>
            <div className="session-controls">
              <span className={`badge ${isImport ? "purple" : ""}`}>
                {session
                  ? isImport
                    ? "PCAP IMPORT"
                    : "LIVE CAPTURE"
                  : "NO SESSION"}
              </span>
              <select
                aria-label="Capture session"
                value={sessionId ?? ""}
                onChange={(e) => setSessionId(e.target.value || undefined)}
              >
                <option value="">Latest capture</option>
                {data.sessions.map((s) => (
                  <option value={s.id} key={s.id}>
                    #{s.id} · {s.name || s.interface || s.source} ·{" "}
                    {time(s.started_at)}
                  </option>
                ))}
              </select>
              <a
                className={`icon-button ${!session ? "disabled" : ""}`}
                aria-label="Export selected capture as PCAP"
                href={session ? `/api/capture/${session.id}/export` : undefined}
                download
              >
                <Download size={16} />
              </a>
              <button
                className="icon-button delete-session"
                aria-label="Delete selected capture session"
                title="Delete selected capture session"
                disabled={!session || busy || (data.capture.running && data.capture.session_id === session.id)}
                onClick={() => setDeleteDialog(true)}
              >
                <Trash2 size={16} />
              </button>
            </div>
          </section>
          {page === "overview" && (
            <>
              {!session && data.online && (
                <section className="getting-started">
                  <div className="getting-started-icon"><FileSearch size={26} /></div>
                  <div className="getting-started-copy">
                    <span className="eyebrow">GET STARTED</span>
                    <h2>See what is happening on your network.</h2>
                    <p>Import a PCAP or PCAPNG file for immediate analysis. Live capture is available when you start VirtualAnchoo with capture permissions.</p>
                  </div>
                  <div className="getting-started-actions">
                    <button className="button primary" onClick={() => fileRef.current?.click()}><Upload size={15} /> Import a capture</button>
                    <button className="button" onClick={() => setCaptureDialog(true)}><Radio size={15} /> Capture live</button>
                  </div>
                </section>
              )}
              <div className="stat-grid">
                <Stat
                  label="Total packets"
                  value={number(overview.total_packets)}
                  icon={<ScanLine size={17} />}
                  foot={
                    session
                      ? "Packets in selected capture"
                      : "Waiting for first capture"
                  }
                />
                <Stat
                  label="Traffic volume"
                  value={bytes(overview.total_bytes)}
                  icon={<ArrowUpRight size={17} />}
                  foot={`${bytes(overview.average_size)} average packet size`}
                />
                <Stat
                  label="Open / observed flows"
                  value={number(overview.active_flows)}
                  icon={<GitBranch size={17} />}
                  foot="TCP not closed + observed datagram flows"
                />
                <Stat
                  label="Average packet rate"
                  value={number(overview.packets_per_second)}
                  unit="pps"
                  icon={<Activity size={17} />}
                  foot={`${bytes(overview.bytes_per_second)}/s average bandwidth`}
                />
              </div>
              <div className="overview-charts">
                <Panel
                  title="Bandwidth over time"
                  eyebrow="TRAFFIC ACTIVITY"
                  action={<ChartLabel />}
                >
                  <div className="chart-summary">
                    <strong>{bytes(overview.total_bytes)}</strong>
                    <span>total in selected capture</span>
                    <span className="chart-key">
                      <i />
                      Bandwidth
                    </span>
                  </div>
                  <TrafficChart data={data} />
                </Panel>
                <Panel
                  title="Protocol distribution"
                  eyebrow="TRAFFIC COMPOSITION"
                  action={
                    <span className="subtle-tag">
                      {data.protocols.length} protocols
                    </span>
                  }
                >
                  <ProtocolChart data={data} />
                </Panel>
              </div>
              <div className="overview-bottom">
                <Panel
                  title="Top communicating devices"
                  eyebrow="NETWORK ENDPOINTS"
                  action={
                    <SectionLink onClick={() => navigate("analytics")}>
                      View analytics
                    </SectionLink>
                  }
                >
                  <DeviceTable data={data} />
                </Panel>
                <Panel title="Network status" eyebrow="SYSTEM HEALTH">
                  <Health data={data} />
                  <div className="health-footer">
                    <span>
                      <Cable size={14} />
                      <b>
                        {
                          data.interfaces.filter((i) => i.is_up !== false)
                            .length
                        }
                      </b>{" "}
                      interfaces available
                    </span>
                    <span>
                      <Layers size={14} />
                      <b>
                        {data.vlans.filter((v) => v.status === "active").length}
                      </b>{" "}
                      active VLANs
                    </span>
                  </div>
                </Panel>
              </div>
              <div className="overview-note">
                <ShieldCheck size={15} />
                <span>
                  Statistics are derived only from captured packets or clearly
                  labeled PCAP imports.
                </span>
                <button
                  className="text-button"
                  onClick={() => navigate("packets")}
                >
                  Open packet analyzer
                  <ArrowUpRight size={14} />
                </button>
              </div>
            </>
          )}
          {page === "packets" && (
            <PacketAnalyzer
              data={data}
              sessionId={sessionId}
              notify={(s) => notify(s)}
            />
          )}
          {page === "analytics" && (
            <>
              <div className="stat-grid">
                <Stat
                  label="Average packet"
                  value={bytes(overview.average_size)}
                  icon={<ScanLine size={17} />}
                  foot={`Min ${bytes(overview.min_size)} · Max ${bytes(overview.max_size)}`}
                />
                <Stat
                  label="Incoming packets"
                  value={number(overview.incoming)}
                  icon={<ArrowDownLeft size={17} />}
                  foot="Where direction is determinable"
                />
                <Stat
                  label="Outgoing packets"
                  value={number(overview.outgoing)}
                  icon={<ArrowUpRight size={17} />}
                  foot="Where direction is determinable"
                />
                <Stat
                  label="Unknown direction"
                  value={number(overview.unknown)}
                  icon={<GitBranch size={17} />}
                  foot="Includes unclassified imported traffic"
                />
              </div>
              <div className="grid-two">
                <Panel title="Bandwidth over time" action={<ChartLabel />}>
                  <TrafficChart data={data} />
                </Panel>
                <Panel title="Packet rate over time" action={<ChartLabel />}>
                  <TrafficChart data={data} metric="packets" />
                </Panel>
              </div>
              <div className="grid-three">
                <Panel title="Protocol distribution">
                  <ProtocolChart data={data} />
                </Panel>
                <Panel title="Packet size distribution">
                  <SizeChart data={data} />
                </Panel>
                <Panel title="Traffic by VLAN">
                  {data.vlanTraffic.length ? (
                    <div className="vlan-volume">
                      {data.vlanTraffic.map((v) => (
                        <div key={v.vlan_id ?? "none"}>
                          <div>
                            <span className="vlan-chip">
                              {v.vlan_id ?? "—"}
                            </span>
                            <span>
                              {v.vlan_id ? `VLAN ${v.vlan_id}` : "Untagged"}
                              <small>{number(v.packets)} packets</small>
                            </span>
                            <strong>{bytes(v.bytes)}</strong>
                          </div>
                          <span className="volume-track">
                            <i
                              style={{
                                width: `${(v.bytes / Math.max(1, ...data.vlanTraffic.map((x) => x.bytes))) * 100}%`,
                              }}
                            />
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <Empty
                      small
                      title="No VLAN traffic observed"
                      text="802.1Q tags are detected from actual frames."
                    />
                  )}
                </Panel>
              </div>
              <div className="grid-two">
                <Panel title="Top source IPs">
                  <DeviceTable data={data} sort="source" />
                </Panel>
                <Panel title="Top destination IPs">
                  <DeviceTable data={data} sort="destination" />
                </Panel>
              </div>
              <Panel
                title="Network flows"
                eyebrow="BIDIRECTIONAL CONVERSATIONS"
                action={
                  <span className="subtle-tag">
                    {number(data.flows.length)} flows
                  </span>
                }
              >
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>SOURCE ENDPOINT</th>
                        <th>DESTINATION ENDPOINT</th>
                        <th>PROTOCOL</th>
                        <th>PACKETS</th>
                        <th>BYTES</th>
                        <th>DURATION</th>
                        <th>TCP FLAGS</th>
                        <th>RETRANSMISSIONS*</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.flows.map((f, i) => (
                        <tr key={f.id || i}>
                          <td className="mono">
                            {f.src_ip || f.source_ip}:{f.src_port ?? "—"}
                          </td>
                          <td className="mono">
                            {f.dst_ip || f.destination_ip}:{f.dst_port ?? "—"}
                          </td>
                          <td>{f.protocol}</td>
                          <td className="mono">{number(f.packets)}</td>
                          <td className="mono">{bytes(f.bytes)}</td>
                          <td className="mono">{number(f.duration)} s</td>
                          <td className="mono">
                            {Array.isArray(f.tcp_flags)
                              ? f.tcp_flags.join(", ")
                              : f.tcp_flags || "—"}
                          </td>
                          <td className="mono">{f.retransmissions ?? 0}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {!data.flows.length && (
                  <Empty small title="No IP flows identified" />
                )}
                <div className="table-footer">
                  * Retransmission detection is heuristic. Flows are grouped by
                  endpoints and transport protocol.
                </div>
              </Panel>
            </>
          )}
          {page === "topology" && <TopologyPage {...networkProps} />}
          {page === "vlans" && <VlanPage {...networkProps} />}
          {page === "segmentation" && <SegmentationPage {...networkProps} />}
          <footer className="main-footer">
            <span>
              VIRTUALANCHOO <span className="footer-slash">/</span> Network
              visibility, packet by packet.
            </span>
            <span>
              <span
                className={`status-orb ${data.wsConnected ? "green" : ""}`}
              />
              {data.wsConnected
                ? "WebSocket connected"
                : "Live connection pending"}
              <span className="footer-slash">/</span>
              <Command size={12} /> / to search
            </span>
          </footer>
        </main>
      </div>
      {captureDialog && (
        <div className="modal-backdrop" onClick={() => setCaptureDialog(false)}>
          <form
            role="dialog"
            aria-modal="true"
            aria-label="Live capture settings"
            className="modal capture-modal"
            onClick={(e) => e.stopPropagation()}
            onSubmit={(e) => {
              e.preventDefault();
              start();
            }}
          >
            <div className="modal-heading">
              <div>
                <div className="eyebrow">LIVE PACKET CAPTURE</div>
                <h2>Start listening</h2>
              </div>
              <button
                className="icon-button"
                type="button"
                aria-label="Close capture settings"
                onClick={() => setCaptureDialog(false)}
              >
                <X size={19} />
              </button>
            </div>
            <p className="muted">
              Capture real traffic from an interface you own or are authorized
              to monitor.
            </p>
            <label>
              Network interface
              <select
                required
                value={captureForm.interface}
                onChange={(e) =>
                  setCaptureForm({ ...captureForm, interface: e.target.value })
                }
              >
                <option value="" disabled>
                  Select an interface
                </option>
                {data.interfaces.map((i) => (
                  <option key={i.name} value={i.name}>
                    {i.name}
                    {i.addresses?.length ? ` · ${i.addresses.join(", ")}` : ""}
                  </option>
                ))}
              </select>
            </label>
            <label>
              BPF capture filter <span className="optional">optional</span>
              <input
                className="mono"
                value={captureForm.bpf_filter}
                onChange={(e) =>
                  setCaptureForm({ ...captureForm, bpf_filter: e.target.value })
                }
                placeholder="tcp or udp port 53"
                maxLength={500}
              />
              <small>Filters packets before storage. Requires libpcap.</small>
            </label>
            <label>
              Packet limit
              <input
                type="number"
                required
                min={1}
                max={100000}
                value={captureForm.packet_limit}
                onChange={(e) =>
                  setCaptureForm({
                    ...captureForm,
                    packet_limit: e.target.value,
                  })
                }
              />
              <small>
                Capture stops automatically when this limit is reached.
              </small>
            </label>
            <label className="checkbox-label">
              <input
                type="checkbox"
                required
                checked={captureForm.authorized}
                onChange={(e) =>
                  setCaptureForm({
                    ...captureForm,
                    authorized: e.target.checked,
                  })
                }
              />
              <span>
                I am authorized to monitor this interface and its traffic.
              </span>
            </label>
            <div className="notice">
              <Terminal size={16} />
              <span>{data.capture.live_enabled
                ? "Live mode is enabled. Packet capture still requires operating-system permission."
                : <>Live mode is off. Restart with <code>./scripts/start.sh --live</code> to enable it.</>}
              </span>
            </div>
            <button
              className="button primary full"
              disabled={
                busy || !data.capture.live_enabled || !captureForm.authorized || !captureForm.interface
              }
            >
              {busy ? (
                <LoaderCircle className="spin" size={15} />
              ) : (
                <Play size={14} />
              )}
              Start capture
            </button>
            <button
              className="text-button modal-secondary"
              type="button"
              onClick={() => {
                setCaptureDialog(false);
                fileRef.current?.click();
              }}
            >
              <FileInput size={14} />
              Import a PCAP instead
            </button>
          </form>
        </div>
      )}
      {deleteDialog && session && (
        <div className="modal-backdrop" onClick={() => setDeleteDialog(false)}>
          <div role="dialog" aria-modal="true" aria-label="Delete capture session" className="modal delete-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-heading"><div><div className="eyebrow">SESSION HISTORY</div><h2>Delete this capture?</h2></div><button className="icon-button" aria-label="Close delete dialog" onClick={() => setDeleteDialog(false)}><X size={19} /></button></div>
            <p className="muted">This removes <strong>{session.name || session.filename || session.interface || session.id}</strong>, its packet records, and its stored capture file from this machine.</p>
            <div className="delete-actions"><button className="button" onClick={() => setDeleteDialog(false)}>Keep session</button><button className="button danger" disabled={busy} onClick={removeSession}><Trash2 size={15} /> Delete capture</button></div>
          </div>
        </div>
      )}
      {toast && (
        <div
          className={`toast ${toastError ? "error" : ""}`}
          role={toastError ? "alert" : "status"}
        >
          {toastError ? (
            <AlertTriangle size={18} />
          ) : (
            <CheckCircle2 size={18} />
          )}
          <span>{toast}</span>
          <button
            className="icon-button"
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <X size={16} />
          </button>
        </div>
      )}
    </div>
  );
}
