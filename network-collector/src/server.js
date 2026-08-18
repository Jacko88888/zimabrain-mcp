import { chmod, mkdir, rm } from "node:fs/promises";
import http from "node:http";
import {
  dnsLookup,
  firewallStatus,
  networkInterfaces,
  networkOpenPorts,
  networkRoutes,
  pingTarget,
  securityScan,
} from "./collector.js";
import { systemSensors, zimaFailedServices, zimaJournalErrors, zimaRaucStatus } from "./system.js";
import { zimaBootDiagnostics } from "./boot.js";

const SOCKET_PATH = process.env.NETWORK_COLLECTOR_SOCKET ?? "/run/zimabrain-network/collector.sock";
const SOCKET_UID = Number.parseInt(process.env.SOCKET_UID ?? "1000", 10);
const SOCKET_GID = Number.parseInt(process.env.SOCKET_GID ?? "1000", 10);

const handlers = new Map([
  ["/interfaces", () => networkInterfaces()],
  ["/routes", () => networkRoutes()],
  ["/ports", () => networkOpenPorts()],
  ["/firewall", () => firewallStatus()],
  ["/security", () => securityScan()],
  ["/sensors", () => systemSensors()],
  ["/failed-services", () => zimaFailedServices()],
  ["/journal-errors", () => zimaJournalErrors()],
  ["/boot-errors", () => zimaBootDiagnostics()],
  ["/rauc", () => zimaRaucStatus()],
]);

const server = http.createServer(async (request, response) => {
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  if (request.method !== "GET") {
    response.writeHead(405).end(JSON.stringify({ collectorStatus: "error", error: "Method not allowed" }));
    return;
  }
  try {
    const url = new URL(request.url ?? "/", "http://collector.local");
    if (url.pathname === "/health") {
      response.writeHead(200).end(JSON.stringify({ status: "ok", name: "zimabrain-network-collector", version: "0.3.0", mode: "fixed-read-only" }));
      return;
    }
    let handler = handlers.get(url.pathname);
    if (url.pathname === "/dns") handler = () => dnsLookup(url.searchParams.get("domain"));
    if (url.pathname === "/ping") handler = () => pingTarget(url.searchParams.get("target") ?? "gateway", url.searchParams.get("count") ?? 3);
    if (!handler) {
      response.writeHead(404).end(JSON.stringify({ collectorStatus: "error", error: "Unknown endpoint" }));
      return;
    }
    const result = await handler();
    response.writeHead(200).end(JSON.stringify({ collectorStatus: "success", ...result }));
  } catch (error) {
    response.writeHead(500).end(JSON.stringify({ collectorStatus: "error", error: String(error?.message ?? error) }));
  }
});

const socketDirectory = SOCKET_PATH.slice(0, SOCKET_PATH.lastIndexOf("/"));
await mkdir(socketDirectory, { recursive: true });
await rm(SOCKET_PATH, { force: true });
server.listen(SOCKET_PATH, async () => {
  try {
    await chmod(SOCKET_PATH, 0o660);
    console.log(`ZimaBrain network collector listening on ${SOCKET_PATH} for UID ${SOCKET_UID} GID ${SOCKET_GID}`);
  } catch (error) {
    console.error(`Socket mode setup failed: ${error?.message ?? error}`);
    server.close(() => process.exit(1));
  }
});

async function shutdown() {
  server.close(async () => {
    await rm(SOCKET_PATH, { force: true }).catch(() => {});
    process.exit(0);
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
