/** UI contract regressions using explicitly synthetic fixtures, never runtime seed data.
 * Charts/React Flow are stubbed because jsdom has no layout engine. Their visual
 * appearance is not established by this suite; the production modules build.
 */
import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import App from "../src/App";

vi.mock("recharts", () =>
  Object.fromEntries(
    [
      "ResponsiveContainer",
      "AreaChart",
      "Area",
      "XAxis",
      "YAxis",
      "CartesianGrid",
      "Tooltip",
      "PieChart",
      "Pie",
      "Cell",
      "BarChart",
      "Bar",
    ].map((name) => [name, () => null]),
  ),
);
vi.mock("@xyflow/react", () => ({
  ReactFlow: () => <div>Topology canvas</div>,
  Background: () => null,
  Controls: () => null,
  MiniMap: () => null,
  Handle: () => null,
  Position: { Top: "top", Bottom: "bottom" },
  MarkerType: { ArrowClosed: "closed" },
}));
const uuid = "963e6880-252c-4c3a-8da7-819fb405209a";
const session = {
  id: uuid,
  source: "import",
  name: "Synthetic UI fixture.pcap",
  started_at: 1700000000,
  packet_count: 1,
  status: "completed",
};
const packet = {
  id: 7,
  session_id: uuid,
  timestamp: 1700000000,
  src_ip: "192.0.2.1",
  dst_ip: "192.0.2.2",
  src_mac: null,
  dst_mac: null,
  protocol: "DNS",
  length: 80,
  src_port: 12345,
  dst_port: 53,
  vlan_id: 10,
  info: "DNS query fixture.test.",
  direction: "unknown",
  interface: "pcap",
  layers: { DNS: { query_name: "fixture.test.", query_type: 1 } },
};
const overview = {
  total_packets: 1,
  total_bytes: 80,
  average_size: 80,
  min_size: 80,
  max_size: 80,
  packets_per_second: 1,
  bytes_per_second: 80,
  active_flows: 1,
  incoming: 0,
  outgoing: 0,
  unknown: 1,
  session,
};
let calls: string[], imported: boolean, importError: boolean, deleted: boolean;
class TestSocket {
  onopen: unknown;
  onmessage: unknown;
  onerror: unknown;
  onclose: unknown;
  close() {}
}
beforeEach(() => {
  location.hash = "";
  calls = [];
  imported = false;
  importError = false;
  deleted = false;
  vi.stubGlobal("WebSocket", TestSocket);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push(url);
      const path = url.split("?")[0];
      let body: unknown;
      if (path === "/api/capture/import") {
        if (importError)
          return new Response(
            JSON.stringify({ detail: "Invalid capture fixture" }),
            { status: 400 },
          );
        imported = true;
        body = session;
      } else if (path === "/api/capture/start")
        return new Response(
          JSON.stringify({ detail: "Capture permission denied fixture" }),
          { status: 409 },
        );
      else if (path === "/api/capture/status")
        body = { running: false, session_id: uuid, live_enabled: true };
      else if (path === "/api/sessions") body = deleted ? [] : [session];
      else if (path === `/api/sessions/${uuid}` && init?.method === "DELETE") {
        deleted = true;
        body = { deleted: uuid };
      }
      else if (path === "/api/interfaces")
        body = [{ name: "lo", addresses: ["127.0.0.1"] }];
      else if (path === "/api/analytics/overview") body = overview;
      else if (path === "/api/analytics/protocols")
        body = [{ protocol: "DNS", count: 1, bytes: 80, percentage: 100 }];
      else if (path === "/api/packets")
        body = { items: [packet], total: 1, page: 1, page_size: 50 };
      else if (path === "/api/packets/7") body = packet;
      else if (path === "/api/topology")
        body = {
          running: false,
          available: false,
          routing_enabled: false,
          status: "offline",
          message: "Fixture lab offline",
          nodes: [],
          edges: [],
          vlans: [],
        };
      else if (path === "/api/vlans")
        body = [
          {
            id: 10,
            name: "Engineering",
            subnet: "192.168.10.0/24",
            gateway: "192.168.10.1",
            hosts: [
              { name: "eng1", ip: "192.168.10.11" },
              { name: "eng2", ip: "192.168.10.12" },
            ],
            ports: [],
            status: "planned",
            trunk: "ns-sw-eth7",
          },
        ];
      else body = [];
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
async function ready() {
  render(<App />);
  await screen.findByText("Backend connected");
}

describe("dashboard API contracts", () => {
  it("confirms and removes a stored session", async () => {
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Delete selected capture session" }));
    const dialog = screen.getByRole("dialog", { name: "Delete capture session" });
    expect(within(dialog).getByText(/Synthetic UI fixture/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete capture" }));
    await waitFor(() => expect(deleted).toBe(true));
    await waitFor(() => expect(screen.getByText("Capture session deleted")).toBeTruthy());
  });
  it("keeps UUID session IDs intact when selecting history", async () => {
    await ready();
    fireEvent.change(screen.getByLabelText("Capture session"), {
      target: { value: uuid },
    });
    await waitFor(() =>
      expect(
        calls.some((url) =>
          url.includes("/api/analytics/overview?session_id=" + uuid),
        ),
      ).toBe(true),
    );
    expect(calls.some((url) => url.includes("NaN"))).toBe(false);
  });
  it("opens structured packet details from the real API shape", async () => {
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Packet Analyzer" }));
    fireEvent.click(await screen.findByLabelText("Inspect packet 7"));
    const dialog = await screen.findByRole("dialog", { name: "Packet #7" });
    expect(within(dialog).getByText("fixture.test.")).toBeTruthy();
    fireEvent.click(within(dialog).getByLabelText("Close packet inspector"));
    expect(screen.queryByRole("dialog")).toBeNull();
  });
  it("sends protocol and VLAN display filters", async () => {
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Packet Analyzer" }));
    fireEvent.click(screen.getByRole("button", { name: "Filters" }));
    fireEvent.change(screen.getByLabelText("Protocol"), {
      target: { value: "DNS" },
    });
    fireEvent.change(screen.getByLabelText("VLAN ID"), {
      target: { value: "10" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() =>
      expect(
        calls.some(
          (url) => url.includes("protocol=DNS") && url.includes("vlan_id=10"),
        ),
      ).toBe(true),
    );
  });
  it("imports a file and switches to the returned UUID session", async () => {
    await ready();
    fireEvent.change(screen.getByLabelText("Import PCAP file"), {
      target: { files: [new File(["test fixture"], "fixture.pcap")] },
    });
    await screen.findByText("PCAP imported. Analysis is ready.");
    expect(imported).toBe(true);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(
      "Packet Analyzer",
    );
    await waitFor(() =>
      expect(
        (screen.getByLabelText("Capture session") as HTMLSelectElement).value,
      ).toBe(uuid),
    );
  });
  it("surfaces import errors without reporting success", async () => {
    await ready();
    importError = true;
    fireEvent.change(screen.getByLabelText("Import PCAP file"), {
      target: { files: [new File(["bad"], "bad.pcap")] },
    });
    expect((await screen.findByRole("alert")).textContent).toContain(
      "Invalid capture fixture",
    );
    expect(screen.queryByText("PCAP imported. Analysis is ready.")).toBeNull();
  });
  it("requires consent and displays capture permission failure", async () => {
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Start capture" }));
    const dialog = screen.getByRole("dialog", {
      name: "Live capture settings",
    });
    expect(
      (
        within(dialog).getByRole("button", {
          name: "Start capture",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    fireEvent.click(within(dialog).getByRole("checkbox"));
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Start capture" }),
    );
    expect((await screen.findByRole("alert")).textContent).toContain(
      "Capture permission denied fixture",
    );
  });
  it("shows the six pages and labels offline network state", async () => {
    await ready();
    for (const name of [
      "Traffic Analytics",
      "Network Topology",
      "VLAN Management",
      "Access Control",
    ]) {
      fireEvent.click(screen.getByRole("button", { name }));
      expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(name);
    }
    expect(
      (
        screen.getByRole("button", {
          name: "Run connectivity test",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "VLAN Management" }));
    expect(await screen.findByText("Planned")).toBeTruthy();
  });
});
