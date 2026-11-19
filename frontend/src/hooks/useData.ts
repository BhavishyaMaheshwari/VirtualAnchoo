import { useCallback, useEffect, useRef, useState } from "react";
import { api, query } from "../services/api";
import type {
  Bandwidth,
  Capture,
  Device,
  Flow,
  Interface,
  Overview,
  Protocol,
  Session,
  Topology,
  Vlan,
  Rule,
} from "../types";
export const zeroOverview: Overview = {
  total_packets: 0,
  total_bytes: 0,
  average_size: 0,
  min_size: 0,
  max_size: 0,
  packets_per_second: 0,
  bytes_per_second: 0,
  active_flows: 0,
  incoming: 0,
  outgoing: 0,
  unknown: 0,
};
export function useData(sessionId: string | undefined) {
  const [online, setOnline] = useState(false),
    [checking, setChecking] = useState(true),
    [error, setError] = useState(""),
    [wsConnected, setWsConnected] = useState(false),
    [revision, setRevision] = useState(0);
  const [sessions, setSessions] = useState<Session[]>([]),
    [interfaces, setInterfaces] = useState<Interface[]>([]),
    [capture, setCapture] = useState<Capture>({
      running: false,
      session_id: null,
    });
  const [overview, setOverview] = useState<Overview>(zeroOverview),
    [protocols, setProtocols] = useState<Protocol[]>([]),
    [bandwidth, setBandwidth] = useState<Bandwidth[]>([]),
    [devices, setDevices] = useState<Device[]>([]),
    [flows, setFlows] = useState<Flow[]>([]);
  const [sizes, setSizes] = useState<{ range: string; count: number }[]>([]),
    [vlanTraffic, setVlanTraffic] = useState<
      { vlan_id: number; packets: number; bytes: number }[]
    >([]);
  const [vlans, setVlans] = useState<Vlan[]>([]),
    [topology, setTopology] = useState<Topology | null>(null),
    [rules, setRules] = useState<Rule[]>([]);
  const requestVersion = useRef(0);
  const refresh = useCallback(async () => {
    const version = ++requestVersion.current;
    const current = () => version === requestVersion.current;
    const update =
      <T>(setter: (value: T) => void) =>
      (value: T) => {
        if (current()) setter(value);
      };
    const q = query({ session_id: sessionId });
    try {
      const status = await api<Capture>("/capture/status");
      if (!current()) return;
      setCapture(status);
      setOnline(true);
      setChecking(false);
      setError("");
      const results = await Promise.allSettled([
        api<Session[]>("/sessions").then(update(setSessions)),
        api<Interface[]>("/interfaces").then(update(setInterfaces)),
        api<Overview>("/analytics/overview" + q).then(update(setOverview)),
        api<Protocol[]>("/analytics/protocols" + q).then((items) =>
          update(setProtocols)(
            items.map((p) => ({ ...p, packets: p.count ?? p.packets })),
          ),
        ),
        api<Bandwidth[]>("/analytics/bandwidth" + q).then(update(setBandwidth)),
        api<Device[]>("/analytics/devices" + q).then(update(setDevices)),
        api<Flow[]>("/analytics/flows" + q).then(update(setFlows)),
        api<{ range: string; count: number }[]>("/analytics/sizes" + q).then(
          update(setSizes),
        ),
        api<{ vlan_id: number; packets: number; bytes: number }[]>(
          "/analytics/vlans" + q,
        ).then(update(setVlanTraffic)),
        api<Vlan[]>("/vlans").then(update(setVlans)),
        api<Topology>("/topology").then(update(setTopology)),
        api<Rule[]>("/segmentation/rules").then(update(setRules)),
      ]);
      if (!current()) return;
      const fail = results.find((r) => r.status === "rejected");
      if (fail?.status === "rejected")
        setError(
          fail.reason instanceof Error
            ? fail.reason.message
            : "Some data could not be loaded",
        );
      setRevision((x) => x + 1);
    } catch (e) {
      if (!current()) return;
      setOnline(false);
      setChecking(false);
      setError(e instanceof Error ? e.message : "Backend unavailable");
    }
  }, [sessionId]);
  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => clearInterval(timer);
  }, [refresh]);
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;
  useEffect(() => {
    let socket: WebSocket | undefined,
      retry: ReturnType<typeof setTimeout>,
      throttle: ReturnType<typeof setTimeout> | undefined,
      closed = false;
    const connect = () => {
      socket = new WebSocket(
        `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws`,
      );
      socket.onopen = () => setWsConnected(true);
      socket.onmessage = () => {
        if (!throttle)
          throttle = setTimeout(() => {
            throttle = undefined;
            void refreshRef.current();
          }, 700);
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        setWsConnected(false);
        if (!closed) retry = setTimeout(connect, 3000);
      };
    };
    connect();
    return () => {
      closed = true;
      clearTimeout(retry);
      clearTimeout(throttle);
      socket?.close();
    };
  }, []);
  return {
    online,
    checking,
    error,
    wsConnected,
    revision,
    sessions,
    interfaces,
    capture,
    overview,
    protocols,
    bandwidth,
    devices,
    flows,
    sizes,
    vlanTraffic,
    vlans,
    topology,
    rules,
    refresh,
  };
}
export type AppData = ReturnType<typeof useData>;
