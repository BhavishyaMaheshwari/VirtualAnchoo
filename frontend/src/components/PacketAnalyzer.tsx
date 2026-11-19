import { useEffect, useState } from "react";
import {
  Search,
  SlidersHorizontal,
  ChevronLeft,
  ChevronRight,
  X,
  Layers,
  ArrowRight,
  Copy,
  Filter,
} from "lucide-react";
import { api, query } from "../services/api";
import type { Packet } from "../types";
import type { AppData } from "../hooks/useData";
import { bytes, number, time, protocolColor } from "../utils/format";
import { Empty } from "./Charts";
const blank = {
  protocol: "",
  src_ip: "",
  dst_ip: "",
  src_port: "",
  dst_port: "",
  vlan_id: "",
  min_size: "",
  max_size: "",
  start_time: "",
  end_time: "",
};
export function PacketAnalyzer({
  data,
  sessionId,
  notify,
}: {
  data: AppData;
  sessionId: string | undefined;
  notify: (s: string) => void;
}) {
  const [items, setItems] = useState<Packet[]>([]),
    [total, setTotal] = useState(0),
    [page, setPage] = useState(1),
    [search, setSearch] = useState(""),
    [filters, setFilters] = useState(blank),
    [applied, setApplied] = useState(blank),
    [expanded, setExpanded] = useState(false),
    [selected, setSelected] = useState<Packet | null>(null),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(false);
  const size = 50;
  useEffect(() => {
    setPage(1);
    setSelected(null);
  }, [sessionId]);
  useEffect(() => {
    let valid = true;
    const t = setTimeout(
      () => {
        setLoading(true);
        const params: Record<string, unknown> = {
          ...applied,
          session_id: sessionId,
          page,
          page_size: size,
          search,
        };
        for (const key of ["start_time", "end_time"])
          if (params[key])
            params[key] = new Date(String(params[key])).getTime() / 1000;
        void api<{ items: Packet[]; total: number }>("/packets" + query(params))
          .then((r) => {
            if (valid) {
              setItems(r.items);
              setTotal(r.total);
              setError("");
            }
          })
          .catch((e) => {
            if (valid) setError(e.message);
          })
          .finally(() => {
            if (valid) setLoading(false);
          });
      },
      search ? 250 : 0,
    );
    return () => {
      valid = false;
      clearTimeout(t);
    };
  }, [sessionId, data.revision, page, search, applied]);
  const select = async (p: Packet) => {
    setSelected(p);
    try {
      setSelected(await api<Packet>(`/packets/${p.id}`));
    } catch (e) {
      notify(e instanceof Error ? e.message : "Packet details unavailable");
    }
  };
  const active = Object.values(applied).filter(Boolean).length;
  return (
    <>
      <section className="panel packet-panel">
        <div className="packet-toolbar">
          <div className="search-box">
            <Search size={15} />
            <input
              aria-label="Search packets"
              placeholder="Search IP, protocol or packet info…"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
            />
            <kbd>/</kbd>
          </div>
          <div className="toolbar-actions">
            <span className="muted mono">{number(total)} packets</span>
            <button
              className={`button compact ${expanded ? "selected" : ""}`}
              onClick={() => setExpanded(!expanded)}
            >
              <SlidersHorizontal size={14} />
              Filters{active > 0 && <span className="count">{active}</span>}
            </button>
          </div>
        </div>
        {expanded && (
          <form
            className="filter-panel"
            onSubmit={(e) => {
              e.preventDefault();
              setApplied({ ...filters });
              setPage(1);
            }}
          >
            <div className="filter-fields">
              <label>
                Protocol
                <select
                  value={filters.protocol}
                  onChange={(e) =>
                    setFilters({ ...filters, protocol: e.target.value })
                  }
                >
                  <option value="">All protocols</option>
                  {[
                    "TCP",
                    "UDP",
                    "ICMP",
                    "ICMPv6",
                    "DNS",
                    "HTTP",
                    "HTTPS/TLS",
                    "ARP",
                    "DHCP",
                    "IPv6",
                  ].map((p) => (
                    <option key={p}>{p}</option>
                  ))}
                </select>
              </label>
              {[
                ["src_ip", "Source IP"],
                ["dst_ip", "Destination IP"],
                ["src_port", "Source port"],
                ["dst_port", "Destination port"],
                ["vlan_id", "VLAN ID"],
                ["min_size", "Min bytes"],
                ["max_size", "Max bytes"],
                ["start_time", "From time"],
                ["end_time", "To time"],
              ].map(([key, label]) => (
                <label key={key}>
                  {label}
                  <input
                    value={filters[key as keyof typeof blank]}
                    onChange={(e) =>
                      setFilters({ ...filters, [key]: e.target.value })
                    }
                    type={
                      key.includes("time")
                        ? "datetime-local"
                        : key.includes("port") ||
                            key.includes("size") ||
                            key === "vlan_id"
                          ? "number"
                          : "text"
                    }
                    min={key === "vlan_id" ? 1 : 0}
                    max={
                      key.includes("port")
                        ? 65535
                        : key === "vlan_id"
                          ? 4094
                          : undefined
                    }
                    placeholder={key.includes("ip") ? "192.168.1.1" : "Any"}
                  />
                </label>
              ))}
            </div>
            <div className="filter-actions">
              <span className="muted">
                Display filters apply to the selected capture.
              </span>
              <button
                className="text-button"
                type="button"
                onClick={() => {
                  setFilters(blank);
                  setApplied(blank);
                  setPage(1);
                }}
              >
                Reset filters
              </button>
              <button className="button primary compact">
                <Filter size={13} />
                Apply filters
              </button>
            </div>
          </form>
        )}
        {error && <div className="inline-error">{error}</div>}
        <div className="table-scroll packet-scroll">
          <table className="packet-table">
            <thead>
              <tr>
                <th>#</th>
                <th>TIMESTAMP</th>
                <th>SOURCE</th>
                <th>DESTINATION</th>
                <th>PROTOCOL</th>
                <th>LENGTH</th>
                <th>SRC PORT</th>
                <th>DST PORT</th>
                <th>VLAN</th>
                <th>INFO</th>
              </tr>
            </thead>
            <tbody>
              {items.map((p) => (
                <tr
                  key={p.id}
                  onClick={() => void select(p)}
                  className={selected?.id === p.id ? "row-selected" : ""}
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void select(p);
                  }}
                  aria-label={`Inspect packet ${p.id}`}
                >
                  <td className="muted">{p.id}</td>
                  <td className="mono">{time(p.timestamp)}</td>
                  <td className="mono">{p.src_ip || p.src_mac || "—"}</td>
                  <td className="mono">{p.dst_ip || p.dst_mac || "—"}</td>
                  <td>
                    <span
                      className="protocol-pill"
                      style={{
                        color: protocolColor(p.protocol),
                        background: `${protocolColor(p.protocol)}16`,
                      }}
                    >
                      {p.protocol}
                    </span>
                  </td>
                  <td className="mono">{p.length}</td>
                  <td className="mono muted">{p.src_port ?? "—"}</td>
                  <td className="mono muted">{p.dst_port ?? "—"}</td>
                  <td className="mono">{p.vlan_id ?? "—"}</td>
                  <td className="packet-info" title={p.info}>
                    {p.info || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!items.length && (
          <Empty
            title={
              search || active
                ? "No packets match your filters"
                : "Ready for your first packet"
            }
            text={
              search || active
                ? "Try a different search or clear the display filters."
                : "Choose an authorized interface to capture, or import a PCAP for offline analysis."
            }
          />
        )}
        <div className="table-footer">
          <span>
            {loading
              ? "Updating…"
              : total
                ? `Showing ${number((page - 1) * size + 1)}–${number(Math.min(page * size, total))} of ${number(total)} packets`
                : "No packets in this capture"}{" "}
            · 50 per page
          </span>
          <div>
            <button
              aria-label="Previous packet page"
              className="icon-button"
              disabled={page === 1}
              onClick={() => setPage((p) => p - 1)}
            >
              <ChevronLeft size={16} />
            </button>
            <span>
              Page {page} of {Math.max(1, Math.ceil(total / size))}
            </span>
            <button
              aria-label="Next packet page"
              className="icon-button"
              disabled={page * size >= total}
              onClick={() => setPage((p) => p + 1)}
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </section>
      <div className="hint-row">
        <span>
          <Layers size={14} /> Select any packet to inspect its protocol layers.
        </span>
        <span>Encrypted TLS payloads are not decrypted.</span>
      </div>
      {selected && (
        <div className="drawer-backdrop" onClick={() => setSelected(null)}>
          <aside
            className="packet-drawer"
            role="dialog"
            aria-modal="true"
            aria-labelledby="packet-title"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="drawer-head">
              <div>
                <div className="eyebrow">PACKET INSPECTOR</div>
                <h2 id="packet-title">Packet #{selected.id}</h2>
              </div>
              <button
                className="icon-button"
                aria-label="Close packet inspector"
                onClick={() => setSelected(null)}
              >
                <X size={19} />
              </button>
            </div>
            <div className="drawer-summary">
              <span
                className="protocol-pill"
                style={{ color: protocolColor(selected.protocol) }}
              >
                {selected.protocol}
              </span>
              <span>{bytes(selected.length)}</span>
              <span>{time(selected.timestamp, true)}</span>
            </div>
            <div className="packet-route">
              <span>
                {selected.src_ip || selected.src_mac || "Unknown"}
                <small>Source · {selected.src_port ?? "—"}</small>
              </span>
              <ArrowRight size={18} />
              <span>
                {selected.dst_ip || selected.dst_mac || "Unknown"}
                <small>Destination · {selected.dst_port ?? "—"}</small>
              </span>
            </div>
            <p className="packet-description">{selected.info}</p>
            <div className="detail-meta">
              <span>
                Interface <b>{selected.interface || "Imported capture"}</b>
              </span>
              <span>
                Direction <b>{selected.direction || "Unknown"}</b>
              </span>
              <span>
                VLAN <b>{selected.vlan_id ?? "Untagged"}</b>
              </span>
            </div>
            {Object.entries(selected.layers || {}).map(([layer, fields]) => (
              <details className="layer" key={layer} open>
                <summary>
                  <Layers size={14} />
                  {layer}
                </summary>
                <dl>
                  {Object.entries(fields).map(([k, v]) => (
                    <div key={k}>
                      <dt>{k.replaceAll("_", " ")}</dt>
                      <dd>
                        {typeof v === "object"
                          ? JSON.stringify(v)
                          : String(v ?? "—")}
                      </dd>
                    </div>
                  ))}
                </dl>
              </details>
            ))}
            {selected.protocol.includes("TLS") ||
            selected.protocol.includes("HTTPS") ? (
              <div className="notice">
                Encrypted application payload cannot be inspected without
                appropriate decryption access. Only observable metadata is
                shown.
              </div>
            ) : null}
            <button
              className="button full"
              onClick={() =>
                void navigator.clipboard
                  .writeText(JSON.stringify(selected, null, 2))
                  .then(() => notify("Packet metadata copied"))
                  .catch(() => notify("Clipboard unavailable in this browser"))
              }
            >
              <Copy size={14} />
              Copy packet metadata
            </button>
          </aside>
        </div>
      )}
    </>
  );
}
