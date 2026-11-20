export const number = (value: number | undefined) =>
  new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 }).format(
    value || 0,
  );
export function bytes(value: number | undefined) {
  const n = value || 0;
  if (n < 1024) return `${number(n)} B`;
  if (n < 1048576) return `${number(n / 1024)} KB`;
  if (n < 1073741824) return `${number(n / 1048576)} MB`;
  return `${number(n / 1073741824)} GB`;
}
export function time(value: number | string | undefined, full = false) {
  if (value === undefined) return "—";
  const date = new Date(typeof value === "number" ? value * 1000 : value);
  if (Number.isNaN(date.getTime())) return "—";
  return full
    ? date.toLocaleString()
    : date.toLocaleTimeString("en-GB", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
}
export const colors = [
  "#527d2e",
  "#536fa9",
  "#7963a3",
  "#a66c23",
  "#397e89",
  "#a75670",
  "#65766c",
];
export function protocolColor(p: string) {
  const ps = [
    "TCP",
    "UDP",
    "DNS",
    "HTTP",
    "HTTPS",
    "TLS",
    "ARP",
    "ICMP",
    "DHCP",
    "IPv6",
  ];
  const i = ps.findIndex((x) => p.toUpperCase().includes(x.toUpperCase()));
  return colors[(i < 0 ? 6 : i) % colors.length];
}
