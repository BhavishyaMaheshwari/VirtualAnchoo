import { Activity, BarChart3, ArrowUpRight, Radio } from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from "recharts";
import type { AppData } from "../hooks/useData";
import { bytes, number, time, colors, protocolColor } from "../utils/format";
import type { ReactNode } from "react";
export function Panel({
  title,
  eyebrow,
  action,
  children,
  className = "",
}: {
  title: string;
  eyebrow?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-heading">
        <div>
          {eyebrow && <div className="eyebrow">{eyebrow}</div>}
          <h2>{title}</h2>
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
export function Empty({
  title = "No traffic to analyze",
  text = "Import a PCAP file or start a capture to see real network activity.",
  small = false,
}: {
  title?: string;
  text?: string;
  small?: boolean;
}) {
  return (
    <div className={`empty ${small ? "small" : ""}`}>
      <span className="empty-icon">
        <Activity size={small ? 21 : 27} />
      </span>
      <strong>{title}</strong>
      <p>{text}</p>
    </div>
  );
}
const tooltipStyle = {
  background: "#ffffff",
  border: "1px solid #dce7d5",
  borderRadius: 8,
  fontSize: 12,
  color: "#2d4031",
  boxShadow: "0 8px 24px #243b1f1a",
};
export function TrafficChart({
  data,
  metric = "bytes",
  height = 220,
}: {
  data: AppData;
  metric?: "bytes" | "packets";
  height?: number;
}) {
  if (!data.bandwidth.length)
    return (
      <div className="empty-chart" style={{ height }}>
        <div className="chart-grid" />
        <Empty
          small
          title="Waiting for packet data"
          text="Actual traffic will appear here."
        />
      </div>
    );
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart
        data={data.bandwidth.map((p) => ({
          ...p,
          bytes: p.bytes / Math.max(1, p.interval_seconds || 1),
          packets: p.packets / Math.max(1, p.interval_seconds || 1),
        }))}
        margin={{ top: 18, right: 12, left: 3, bottom: 0 }}
      >
        <defs>
          <linearGradient id={`gradient-${metric}`} x1="0" y1="0" x2="0" y2="1">
            <stop
              offset="0%"
              stopColor={metric === "bytes" ? "#a7d653" : "#7f9fd2"}
              stopOpacity={0.22}
            />
            <stop offset="100%" stopColor="#a7d653" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid
          stroke="#e8eee2"
          vertical={false}
          strokeDasharray="3 6"
        />
        <XAxis
          dataKey="timestamp"
          tickFormatter={(v) => time(v)}
          minTickGap={50}
          tick={{ fill: "#67796a", fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          tickFormatter={(v) =>
            metric === "bytes" ? `${bytes(v)}/s` : `${number(v)}/s`
          }
          tick={{ fill: "#67796a", fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          width={65}
        />
        <Tooltip
          contentStyle={tooltipStyle}
          labelFormatter={(v) => time(v as number | string, true)}
          formatter={(v) => [
            metric === "bytes"
              ? `${bytes(Number(v))}/s`
              : `${number(Number(v))}/s`,
            metric === "bytes" ? "Bandwidth" : "Packet rate",
          ]}
        />
        <Area
          type="monotone"
          dataKey={metric}
          stroke={metric === "bytes" ? "#82b63d" : "#6f8ebf"}
          strokeWidth={2.5}
          fill={`url(#gradient-${metric})`}
          isAnimationActive={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
export function ProtocolChart({ data }: { data: AppData }) {
  if (!data.protocols.length)
    return (
      <div className="protocol-empty">
        <div className="empty-donut">
          <span>
            0<small>packets</small>
          </span>
        </div>
        <p>Protocol breakdown appears after capture.</p>
      </div>
    );
  return (
    <div className="protocol-chart">
      <div className="donut-wrap">
        <ResponsiveContainer width="100%" height={178}>
          <PieChart>
            <Pie
              data={data.protocols}
              dataKey="packets"
              nameKey="protocol"
              innerRadius={57}
              outerRadius={77}
              paddingAngle={3}
              stroke="none"
              isAnimationActive={false}
            >
              {data.protocols.map((p) => (
                <Cell key={p.protocol} fill={protocolColor(p.protocol)} />
              ))}
            </Pie>
            <Tooltip contentStyle={tooltipStyle} />
          </PieChart>
        </ResponsiveContainer>
        <div className="donut-label">
          <strong>{number(data.protocols.length)}</strong>
          <small>protocols</small>
        </div>
      </div>
      <div className="protocol-legend">
        {data.protocols.map((p) => (
          <div key={p.protocol}>
            <span
              className="legend-dot"
              style={{ background: protocolColor(p.protocol) }}
            />
            <span>{p.protocol}</span>
            <strong>{number(p.percentage)}%</strong>
          </div>
        ))}
      </div>
    </div>
  );
}
export function DeviceTable({
  data,
  sort = "total",
}: {
  data: AppData;
  sort?: "total" | "source" | "destination";
}) {
  const ds = [...data.devices]
    .sort((a, b) =>
      sort === "source"
        ? (b.sent_packets || 0) - (a.sent_packets || 0)
        : sort === "destination"
          ? (b.received_packets || 0) - (a.received_packets || 0)
          : (b.bytes || 0) - (a.bytes || 0),
    )
    .slice(0, 6);
  return ds.length ? (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>DEVICE / IP ADDRESS</th>
            <th>PACKETS</th>
            <th>VOLUME</th>
            <th>ACTIVITY</th>
          </tr>
        </thead>
        <tbody>
          {ds.map((d, i) => (
            <tr key={d.ip || i}>
              <td>
                <span className="device-cell">
                  <span className="device-icon">
                    <Radio size={14} />
                  </span>
                  <span className="mono">
                    {d.ip || d.address}
                    <small className="sub-cell">
                      {d.macs?.join(", ") || d.mac || "MAC not observed"}
                    </small>
                  </span>
                </span>
              </td>
              <td className="mono">
                {number(
                  sort === "source"
                    ? d.sent_packets
                    : sort === "destination"
                      ? d.received_packets
                      : d.packets,
                )}
              </td>
              <td className="mono">{bytes(d.bytes)}</td>
              <td>
                <span className="mini-bar">
                  <i
                    style={{
                      width: `${Math.max(4, ((d.bytes || 0) / Math.max(1, ...ds.map((v) => v.bytes || 0))) * 100)}%`,
                      background: colors[i % colors.length],
                    }}
                  />
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty
      small
      title="No devices observed"
      text="Devices are identified from captured IP and MAC addresses."
    />
  );
}
export function SizeChart({ data }: { data: AppData }) {
  return data.sizes.some((s) => s.count > 0) ? (
    <ResponsiveContainer width="100%" height={215}>
      <BarChart
        data={data.sizes}
        margin={{ top: 18, right: 15, left: 0, bottom: 8 }}
      >
        <CartesianGrid
          stroke="#e8eee2"
          vertical={false}
          strokeDasharray="3 6"
        />
        <XAxis
          dataKey="range"
          tick={{ fill: "#67796a", fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          tick={{ fill: "#67796a", fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          width={42}
        />
        <Tooltip contentStyle={tooltipStyle} />
        <Bar
          dataKey="count"
          name="Packets"
          fill="#a5d353"
          radius={[4, 4, 0, 0]}
          maxBarSize={34}
          isAnimationActive={false}
        />
      </BarChart>
    </ResponsiveContainer>
  ) : (
    <Empty small title="No packet sizes recorded" />
  );
}
export function Stat({
  label,
  value,
  unit,
  icon,
  foot,
}: {
  label: string;
  value: string;
  unit?: string;
  icon: ReactNode;
  foot: string;
}) {
  return (
    <div className="stat">
      <div className="stat-top">
        <span>{label}</span>
        {icon}
      </div>
      <div className="stat-value">
        {value}
        <span>{unit}</span>
      </div>
      <div className="stat-foot">{foot}</div>
    </div>
  );
}
export function Health({ data }: { data: AppData }) {
  return (
    <div className="health-items">
      <div>
        <span className={`status-orb ${data.online ? "green" : ""}`} />
        <span>API connection</span>
        <strong>{data.online ? "Connected" : "Unavailable"}</strong>
      </div>
      <div>
        <span className={`status-orb ${data.wsConnected ? "green" : ""}`} />
        <span>Live updates</span>
        <strong>{data.wsConnected ? "Connected" : "Reconnecting"}</strong>
      </div>
      <div>
        <span className={`status-orb ${data.capture.running ? "green" : ""}`} />
        <span>Capture engine</span>
        <strong>{data.capture.running ? "Capturing" : "Idle"}</strong>
      </div>
      <div>
        <span
          className={`status-orb ${data.topology?.running ? "green" : ""}`}
        />
        <span>Virtual network</span>
        <strong>{data.topology?.running ? "Active" : "Not running"}</strong>
      </div>
    </div>
  );
}
export function SectionLink({
  children,
  onClick,
}: {
  children: ReactNode;
  onClick: () => void;
}) {
  return (
    <button className="text-button" onClick={onClick}>
      {children}
      <ArrowUpRight size={14} />
    </button>
  );
}
export function ChartLabel() {
  return (
    <span className="subtle-tag">
      <BarChart3 size={12} /> Per second
    </span>
  );
}
