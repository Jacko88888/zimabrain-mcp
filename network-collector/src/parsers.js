import net from "node:net";

export function parseResolver(text) {
  const nameservers = [];
  const search = [];
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.replace(/#.*/, "").trim();
    if (!line) continue;
    const [key, ...values] = line.split(/\s+/);
    if (key === "nameserver" && values[0] && net.isIP(values[0])) nameservers.push(values[0]);
    if (key === "search") search.push(...values.filter(Boolean));
  }
  return { nameservers: [...new Set(nameservers)], search: [...new Set(search)] };
}

export function parsePing(text) {
  const packet = String(text ?? "").match(/(\d+) packets transmitted, (\d+) packets received, ([\d.]+)% packet loss/)
    ?? String(text ?? "").match(/(\d+) packets transmitted, (\d+) received, ([\d.]+)% packet loss/);
  const timing = String(text ?? "").match(/(?:round-trip|rtt) min\/avg\/max(?:\/mdev)? = ([\d.]+)\/([\d.]+)\/([\d.]+)/);
  return {
    transmitted: Number.parseInt(packet?.[1] ?? "0", 10),
    received: Number.parseInt(packet?.[2] ?? "0", 10),
    packetLossPercent: Number.parseFloat(packet?.[3] ?? "100"),
    minimumMs: timing ? Number.parseFloat(timing[1]) : null,
    averageMs: timing ? Number.parseFloat(timing[2]) : null,
    maximumMs: timing ? Number.parseFloat(timing[3]) : null,
  };
}

function splitAddressPort(value) {
  const raw = String(value ?? "");
  if (raw.startsWith("[") && raw.includes("]:")) {
    const close = raw.lastIndexOf("]:");
    return { address: raw.slice(1, close), port: Number.parseInt(raw.slice(close + 2), 10) };
  }
  const separator = raw.lastIndexOf(":");
  if (separator < 0) return { address: raw, port: null };
  return { address: raw.slice(0, separator), port: Number.parseInt(raw.slice(separator + 1), 10) };
}

export function classifyBind(address, interfaceAddresses = {}) {
  const value = String(address ?? "").replace(/^\[|\]$/g, "");
  if (["127.0.0.1", "::1"].includes(value)) return "localhost";
  if (["0.0.0.0", "::", "*"].includes(value)) return "all_interfaces";
  if (value.startsWith("169.254.") || value.toLowerCase().startsWith("fe80:")) return "link_local";
  for (const [name, addresses] of Object.entries(interfaceAddresses)) {
    if (!addresses.includes(value)) continue;
    if (name === "tailscale0" || name.startsWith("zt") || name.startsWith("tun")) return "overlay";
    if (name.startsWith("br-") || name === "docker0" || name === "virbr0") return "container_bridge";
    return "lan";
  }
  return "other";
}

export function parseListeningSockets(text, interfaceAddresses = {}) {
  const rows = [];
  const seen = new Set();
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const fields = line.split(/\s+/);
    if (fields.length < 5) continue;
    const protocol = fields[0].toLowerCase();
    const local = splitAddressPort(fields[4]);
    if (!Number.isInteger(local.port)) continue;
    const processMatch = line.match(/users:\(\(\"([^\"]+)\",pid=(\d+)/);
    const process = processMatch?.[1] ?? null;
    const pid = processMatch ? Number.parseInt(processMatch[2], 10) : null;
    const scope = classifyBind(local.address, interfaceAddresses);
    const key = `${protocol}|${local.address}|${local.port}|${process ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    rows.push({
      protocol,
      address: local.address,
      port: local.port,
      process,
      pid,
      scope,
      locallyReachable: true,
      lanReachable: ["all_interfaces", "lan"].includes(scope),
      internetReachability: "not_verified",
    });
  }
  return rows.sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol));
}

export function firewallChainPresent(saveText, chain, hookChain) {
  const text = String(saveText ?? "");
  return text.includes(`:${chain} `) && text.includes(`-A ${hookChain} -j ${chain}`);
}
