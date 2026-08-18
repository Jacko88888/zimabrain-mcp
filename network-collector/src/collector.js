import { execFile } from "node:child_process";
import { Resolver } from "node:dns/promises";
import { readFile, readdir } from "node:fs/promises";
import { promisify } from "node:util";
import { classifyBind, firewallChainPresent, parseListeningSockets, parsePing, parseResolver } from "./parsers.js";

const execFileAsync = promisify(execFile);
const HOST_PROC = process.env.HOST_PROC ?? "/host/proc";
const RESOLV_CONF = process.env.RESOLV_CONF ?? "/host/etc/resolv.conf";
const ZFW_RULES_PATH = process.env.ZFW_RULES_PATH ?? "/host/zfw/rules.json";
const ALLOWED_DNS = new Set(["github.com", "zimaspace.com", "cloudflare.com"]);

async function command(file, args, timeout = 5000) {
  try {
    const { stdout, stderr } = await execFileAsync(file, args, { timeout, maxBuffer: 4 * 1024 * 1024 });
    return { ok: true, stdout, stderr, exitCode: 0 };
  } catch (error) {
    return {
      ok: false,
      stdout: String(error?.stdout ?? ""),
      stderr: String(error?.stderr ?? error?.message ?? "command failed"),
      exitCode: Number.isInteger(error?.code) ? error.code : null,
    };
  }
}

async function jsonCommand(file, args) {
  const result = await command(file, args);
  if (!result.ok) throw new Error(`${file} failed: ${result.stderr.trim() || "unknown error"}`);
  return JSON.parse(result.stdout || "[]");
}

function cleanAddress(value) {
  return String(value ?? "").split("%")[0];
}

export async function networkInterfaces() {
  const raw = await jsonCommand("ip", ["-j", "address", "show"]);
  const interfaces = raw.map((item) => ({
    name: item.ifname,
    state: item.operstate ?? "UNKNOWN",
    mtu: item.mtu ?? null,
    type: item.link_type ?? null,
    addresses: (item.addr_info ?? []).map((address) => ({
      family: address.family,
      address: cleanAddress(address.local),
      prefixLength: address.prefixlen,
      scope: address.scope,
      dynamic: Boolean(address.dynamic),
    })),
  }));
  const up = interfaces.filter((item) => item.state === "UP" || item.name === "lo").length;
  return { generatedAt: new Date().toISOString(), observedInterfaces: interfaces.length, upInterfaces: up, interfaces };
}

export async function networkRoutes() {
  const [ipv4, ipv6] = await Promise.all([
    jsonCommand("ip", ["-j", "route", "show", "table", "main"]),
    jsonCommand("ip", ["-6", "-j", "route", "show", "table", "main"]).catch(() => []),
  ]);
  const normalize = (route, family) => ({
    family,
    destination: route.dst ?? "default",
    gateway: route.gateway ?? null,
    interface: route.dev ?? null,
    source: route.prefsrc ?? route.src ?? null,
    metric: route.metric ?? null,
    protocol: route.protocol ?? null,
    linkDown: Boolean(route.flags?.includes("linkdown")),
  });
  const routes = [...ipv4.map((route) => normalize(route, "ipv4")), ...ipv6.map((route) => normalize(route, "ipv6"))];
  const defaultRoutes = routes.filter((route) => route.destination === "default");
  return { generatedAt: new Date().toISOString(), observedRoutes: routes.length, defaultRoutes, routes };
}

export async function dnsLookup(domain) {
  const normalized = String(domain ?? "").trim().toLowerCase();
  if (!ALLOWED_DNS.has(normalized)) throw new Error("DNS name is not in the fixed allow-list");
  const resolver = parseResolver(await readFile(RESOLV_CONF, "utf8"));
  const lookup = new Resolver();
  if (resolver.nameservers.length) lookup.setServers(resolver.nameservers);
  const [ipv4, ipv6] = await Promise.all([
    lookup.resolve4(normalized).catch(() => []),
    lookup.resolve6(normalized).catch(() => []),
  ]);
  const addresses = [...new Set([...ipv4, ...ipv6])];
  return {
    generatedAt: new Date().toISOString(),
    domain: normalized,
    resolved: addresses.length > 0,
    addresses,
    resolver,
    boundedAllowList: [...ALLOWED_DNS].sort(),
  };
}

async function firstTarget(kind) {
  if (kind === "internet") return { address: "1.1.1.1", source: "fixed_public_probe" };
  if (kind === "dns") {
    const resolver = parseResolver(await readFile(RESOLV_CONF, "utf8"));
    if (!resolver.nameservers[0]) throw new Error("No DNS resolver was observed");
    return { address: resolver.nameservers[0], source: "first_configured_resolver" };
  }
  const routes = await networkRoutes();
  const route = routes.defaultRoutes.find((item) => item.family === "ipv4" && !item.linkDown && item.gateway);
  if (!route) throw new Error("No active IPv4 default gateway was observed");
  return { address: route.gateway, source: "active_default_gateway" };
}

export async function pingTarget(kind = "gateway", count = 3) {
  if (!["gateway", "dns", "internet"].includes(kind)) throw new Error("Ping target is not allow-listed");
  const safeCount = Math.max(1, Math.min(4, Number.parseInt(String(count), 10) || 3));
  const target = await firstTarget(kind);
  const binary = target.address.includes(":") ? "ping6" : "ping";
  const result = await command(binary, ["-n", "-c", String(safeCount), "-W", "2", target.address], 12000);
  const parsed = parsePing(`${result.stdout}\n${result.stderr}`);
  return {
    generatedAt: new Date().toISOString(),
    targetKind: kind,
    target: target.address,
    targetSource: target.source,
    reachable: parsed.received > 0,
    ...parsed,
    bounded: true,
  };
}

async function interfaceAddressMap() {
  const evidence = await networkInterfaces();
  return Object.fromEntries(evidence.interfaces.map((item) => [item.name, item.addresses.map((address) => address.address)]));
}

export async function networkOpenPorts() {
  const [sockets, addresses] = await Promise.all([
    command("ss", ["-H", "-lntup"]),
    interfaceAddressMap(),
  ]);
  if (!sockets.ok) throw new Error(`ss failed: ${sockets.stderr.trim() || "unknown error"}`);
  const listeners = parseListeningSockets(sockets.stdout, addresses);
  const lanReachable = listeners.filter((item) => item.lanReachable).length;
  const localhostOnly = listeners.filter((item) => item.scope === "localhost").length;
  return {
    generatedAt: new Date().toISOString(),
    observedListeners: listeners.length,
    lanReachable,
    localhostOnly,
    externalReachabilityMeasured: false,
    externalReachability: "not_verified",
    listeners,
  };
}

async function processRunning(name) {
  const entries = await readdir(HOST_PROC, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    if (!entry.isDirectory() || !/^\d+$/.test(entry.name)) continue;
    try {
      if ((await readFile(`${HOST_PROC}/${entry.name}/comm`, "utf8")).trim() === name) return true;
    } catch {
      // Processes can exit while the directory is being inspected.
    }
  }
  return false;
}

async function firewallSave(binary) {
  const result = await command(binary, []);
  return result.ok ? result.stdout : "";
}

function policies(saveText) {
  const result = {};
  for (const line of String(saveText ?? "").split(/\r?\n/)) {
    const match = line.match(/^:(INPUT|FORWARD|OUTPUT)\s+(ACCEPT|DROP|REJECT)/);
    if (match) result[match[1].toLowerCase()] = match[2].toLowerCase();
  }
  return result;
}

export async function firewallStatus() {
  const [savedText, savedRules, daemonRunning] = await Promise.all([
    firewallSave("iptables-save"),
    readFile(ZFW_RULES_PATH, "utf8").then(JSON.parse).catch(() => null),
    processRunning("zfwd"),
  ]);
  const ipv6Text = await firewallSave("ip6tables-save");
  const active = firewallChainPresent(savedText, "ZFW-IN", "INPUT");
  const ipv6Active = firewallChainPresent(ipv6Text, "ZFW-IN6", "INPUT");
  const enabledRules = Array.isArray(savedRules?.rules) ? savedRules.rules.filter((rule) => rule?.enabled) : [];
  const configured = enabledRules.length > 0;
  const state = active ? "active" : configured ? "configured_not_applied" : daemonRunning ? "service_only" : "not_configured";
  return {
    generatedAt: new Date().toISOString(),
    serviceRunning: daemonRunning,
    savedConfigurationObserved: Boolean(savedRules),
    savedPolicy: savedRules?.default_policy ?? null,
    savedLan: savedRules?.lan ?? null,
    savedHostIp: savedRules?.host_ip ?? null,
    savedRules: enabledRules.length,
    active,
    hooked: active,
    ipv6Active,
    state,
    ipv4Policies: policies(savedText),
    ipv6Policies: policies(ipv6Text),
    externalReachabilityMeasured: false,
    note: active
      ? "ZFW chains are present and hooked into the host firewall."
      : configured
        ? "ZFW has a saved policy, but its chains are not loaded into the active host firewall."
        : "No active ZFW chains or saved enabled rules were observed.",
  };
}

export async function securityScan() {
  const [firewall, ports] = await Promise.all([firewallStatus(), networkOpenPorts()]);
  const findings = [];
  if (firewall.state === "configured_not_applied") {
    findings.push({
      code: "zfw_configured_not_applied",
      severity: "attention",
      verified: true,
      message: "ZFW has saved deny-by-default rules, but no active ZFW chains are hooked into the host firewall.",
    });
  }
  if (firewall.ipv4Policies.input === "accept" && !firewall.active) {
    findings.push({
      code: "host_input_default_accept",
      severity: "attention",
      verified: true,
      message: "The observed IPv4 INPUT policy is ACCEPT and no active ZFW input chain was found.",
    });
  }
  if (ports.lanReachable > 0) {
    findings.push({
      code: "lan_listeners_observed",
      severity: "informational",
      verified: true,
      count: ports.lanReachable,
      message: `${ports.lanReachable} listening socket(s) are bound to the LAN or all interfaces.`,
    });
  }
  findings.push({
    code: "external_reachability_unverified",
    severity: "unknown",
    verified: false,
    message: "Internet reachability was not measured from outside the LAN.",
  });
  return {
    generatedAt: new Date().toISOString(),
    status: findings.some((item) => item.severity === "attention") ? "attention" : "healthy",
    attentionCount: findings.filter((item) => item.severity === "attention").length,
    observedListeners: ports.observedListeners,
    lanReachableListeners: ports.lanReachable,
    listeners: (ports.listeners ?? []).slice(0, 100),
    listenersBounded: true,
    maximumListeners: 100,
    externalReachabilityMeasured: false,
    firewall,
    findings,
  };
}
