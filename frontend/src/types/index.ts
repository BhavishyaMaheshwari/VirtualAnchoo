export type Dict = Record<string, unknown>;
export interface Packet {
  id: number;
  session_id: string;
  timestamp: number | string;
  src_ip: string | null;
  dst_ip: string | null;
  src_mac: string | null;
  dst_mac: string | null;
  protocol: string;
  length: number;
  src_port: number | null;
  dst_port: number | null;
  vlan_id: number | null;
  info: string;
  direction: string;
  interface: string;
  layers: Record<string, Dict | Dict[]>;
}
export interface Session {
  id: string;
  source?: string;
  mode?: string;
  filename?: string;
  name?: string;
  interface?: string;
  started_at?: number | string;
  packet_count?: number;
  status?: string;
}
export interface Interface {
  name: string;
  description?: string;
  addresses?: string[];
  ips?: string[];
  is_up?: boolean;
  mac?: string;
}
export interface Capture {
  running: boolean;
  session_id: string | null;
  live_enabled?: boolean;
  interface?: string;
  bpf_filter?: string;
  packet_count?: number;
  error?: string | null;
}
export interface Overview {
  total_packets: number;
  total_bytes: number;
  average_size: number;
  min_size: number;
  max_size: number;
  packets_per_second: number;
  bytes_per_second: number;
  active_flows: number;
  incoming: number;
  outgoing: number;
  unknown: number;
  session?: Session;
}
export interface Protocol {
  protocol: string;
  packets: number;
  count: number;
  bytes: number;
  percentage: number;
}
export interface Bandwidth {
  timestamp: number | string;
  packets: number;
  bytes: number;
  interval_seconds: number;
}
export interface Device {
  ip?: string;
  address?: string;
  mac?: string;
  macs?: string[];
  packets?: number;
  bytes?: number;
  source_packets?: number;
  destination_packets?: number;
  sent_packets?: number;
  received_packets?: number;
}
export interface Flow {
  id?: string;
  src_ip?: string;
  dst_ip?: string;
  source_ip?: string;
  destination_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  packets?: number;
  bytes?: number;
  duration?: number;
  start_time?: number;
  end_time?: number;
  tcp_flags?: string[] | string;
  retransmissions?: number;
}
export interface Vlan {
  id: number;
  name: string;
  subnet: string;
  gateway?: string;
  hosts: { name: string; ip: string; mac?: string; port?: string }[];
  ports: string[];
  status: string;
  mode?: string;
  trunk?: string;
}
export interface Topology {
  available: boolean;
  running: boolean;
  routing_enabled: boolean;
  status: string;
  message: string;
  nodes: {
    id: string;
    type: string;
    label: string;
    ip?: string;
    vlan_id?: number;
    position: { x: number; y: number };
    details: Dict;
  }[];
  edges: { id: string; source: string; target: string; label?: string }[];
  vlans: Vlan[];
}
export interface Rule {
  id: string;
  source_vlan: number;
  destination_vlan: number;
  protocol: string;
  destination_port: number | null;
  action: string;
  enabled: boolean;
  description: string;
  applied: boolean;
}
export interface Connectivity {
  id: string;
  source: string;
  destination: string;
  success: boolean;
  transmitted: number;
  received: number;
  packet_loss: number;
  rtt_ms: number | null;
  output: string;
  executed_at: string;
  error: string | null;
}
