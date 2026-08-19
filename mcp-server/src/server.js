import { randomUUID } from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { readAudit, writeAudit } from "./audit.js";
import { answerQuestion, readQuestionHistory } from "./brain.js";
import {
  btrfsHealth,
  dashboardEvidence,
  dockerContainers,
  dockerImages,
  dockerInfo,
  dockerInspect,
  dockerLogs,
  filesystemUsage,
  networkDns,
  networkInterfaces,
  networkOpenPorts,
  networkPing,
  networkRoutes,
  nvmeHealth,
  raidHealth,
  smartHealth,
  storageInventory,
  storageMounts,
  systemInfo,
  systemProcesses,
  systemSensors,
  zimaFailedServices,
  zimaFirewallStatus,
  zimaJournalErrors,
  zimaBootDiagnostics,
  zimaRaucStatus,
  zimaSecurityScan,
} from "./evidence.js";
import {
  backupInventory,
  backupStatus,
  dockerHealth,
  dockerHealthHistory,
  dockerStats,
  zimaApps,
  zimaAppVerify,
} from "./roadmap.js";

const port = Number.parseInt(process.env.PORT ?? "8718", 10);
const transports = new Map();
const SERVER_VERSION = "1.0.8";
const containerReference = z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9_.-]*$/);

function toolResult(value) {
  const structuredContent = Array.isArray(value)
    ? { count: value.length, items: value }
    : value;
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    structuredContent,
  };
}

function registerReadTool(server, name, description, inputSchema, handler, openWorld = false) {
  server.registerTool(
    name,
    {
      description,
      inputSchema,
      annotations: {
        title: name,
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: openWorld,
      },
    },
    async (args) => {
      const started = Date.now();
      try {
        const value = await handler(args);
        await writeAudit({ actor: "mcp-client", tool: name, result: "SUCCESS", durationMs: Date.now() - started });
        return toolResult(value);
      } catch (error) {
        await writeAudit({ actor: "mcp-client", tool: name, result: "ERROR", durationMs: Date.now() - started, error: String(error?.message ?? error) });
        return { content: [{ type: "text", text: `Tool failed: ${error?.message ?? error}` }], isError: true };
      }
    },
  );
}

async function serverInfo() {
  const checks = {};
  const tasks = {
    docker_stats: () => dockerStats(),
    docker_health: () => dockerHealth(),
    docker_health_history: () => dockerHealthHistory(),
    zima_boot_diagnostics: () => zimaBootDiagnostics(),
    backup_inventory: () => backupInventory(),
    backup_status: () => backupStatus(),
    zima_apps: () => zimaApps(),
  };
  let applications = null;
  for (const [name, task] of Object.entries(tasks)) {
    try {
      const value = await task();
      if (name === "zima_apps") applications = value;
      checks[name] = {
        ok: true,
        generatedAt: value?.generatedAt ?? null,
        observed: value?.observedContainers
          ?? value?.observedRunningContainers
          ?? value?.observedApplications
          ?? value?.repositories
          ?? value?.observedLines
          ?? value?.snapshots
          ?? null,
        state: value?.state ?? null,
      };
    } catch (error) {
      checks[name] = { ok: false, error: String(error?.message ?? error).slice(0, 300) };
    }
  }
  try {
    const abstention = await answerQuestion("What service is using disk?");
    checks.brain_disk_io_evidence = {
      ok: abstention.intent === "disk_io_service" && abstention.verification === "VERIFIED" && abstention.sources.includes("docker_stats"),
      intent: abstention.intent,
      verification: abstention.verification,
      sources: abstention.sources,
      engine: abstention.engine,
      sourceCommit: abstention.sourceCommit,
      answerPreview: String(abstention.answer ?? "").slice(0, 900),
    };
  } catch (error) {
    checks.brain_disk_io_evidence = { ok: false, error: String(error?.message ?? error).slice(0, 300) };
  }
  try {
    const [containersAnswer, currentContainers] = await Promise.all([
      answerQuestion("Which containers are not running?"),
      dockerContainers(),
    ]);
    const expectedRunning = currentContainers.filter((item) => item.state === "running").length;
    const expectedTotal = currentContainers.length;
    const fullBrainCountsMatch = String(containersAnswer.answer ?? "").includes(`Total containers inspected: ${expectedTotal}`)
      && String(containersAnswer.answer ?? "").includes(`Running containers: ${expectedRunning}`);
    checks.brain_container_routing = {
      ok: containersAnswer.intent === "containers_not_running"
        && containersAnswer.sources.includes("docker_ps")
        && containersAnswer.engine === "full-zimabrain+mcp"
        && fullBrainCountsMatch,
      expectedRunning,
      expectedTotal,
      fullBrainCountsMatch,
      intent: containersAnswer.intent,
      verification: containersAnswer.verification,
      sources: containersAnswer.sources,
      engine: containersAnswer.engine,
      sourceCommit: containersAnswer.sourceCommit,
      answerPreview: String(containersAnswer.answer ?? "").slice(0, 900),
    };
  } catch (error) {
    checks.brain_container_routing = { ok: false, error: String(error?.message ?? error).slice(0, 300) };
  }


  try {
    const qualityCases = [
      { question: "How many disks do I have?", intent: "disk_inventory", source: "storage_inventory" },
      { question: "Are my disks healthy?", intent: "disk_health", source: "smart_health" },
      { question: "What needs attention?", intent: "comprehensive_health", source: "docker_health" },
      { question: "Are my backups current?", intent: "backup_status", source: "backup_status" },
      { question: "What is exposed on the LAN?", intent: "network_exposure", source: "network_open_ports" },
      { question: "Why is Homarr showing attention?", intent: "app_verify", source: "zima_app_verify" },
    ];
    const answers = await Promise.all(qualityCases.map((item) => answerQuestion(item.question)));
    const cases = answers.map((answer, index) => {
      const expected = qualityCases[index];
      const text = String(answer.answer ?? "");
      const firstLine = text.split("\n").find((line) => line.trim())?.trim() ?? "";
      let evidenceAligned = true;
      if (answer.intent === "disk_inventory") {
        evidenceAligned = firstLine.includes(String(answer.evidence?.observedDisks ?? ""));
      } else if (answer.intent === "backup_status" && answer.evidence?.backup?.state === "not_configured") {
        evidenceAligned = /not verified|not configured/i.test(firstLine);
      } else if (answer.intent === "network_exposure") {
        const expectedSources = [
          "network_open_ports",
          "zima_firewall_status",
          "docker_ps",
          "zima_apps",
          "network_interfaces",
          "zima_security_scan",
        ];
        const expectedCount = Number(answer.evidence?.uniquePotentialListeners?.length ?? 0);
        const firewallState = String(answer.evidence?.firewall?.state ?? "");
        const noUnsupportedReachabilityClaim = !/LAN-reachable listening socket\(s\) were verified/i.test(text)
          && !/Internet exposure (?:was|is) verified/i.test(text);
        const uncertaintyPreserved = expectedCount === 0
          ? /LAN and internet reachability were not measured/i.test(text)
          : /may be accessible from the LAN/i.test(text)
            && /no LAN connection probe was performed/i.test(text)
            && /Internet exposure was not measured/i.test(text);
        const countAligned = expectedCount === 0
          ? /No listener bound to a LAN or all-interface address/i.test(firstLine)
          : firstLine.startsWith(`${expectedCount} unique port/service combination(s)`);
        const firewallAligned = firewallState === "service_only"
          ? /service is running, but no active ZFW hooks or saved enabled rules were observed/i.test(text)
          : true;
        evidenceAligned = expectedSources.every((source) => answer.sources.includes(source))
          && answer.verification === "PARTIALLY VERIFIED"
          && noUnsupportedReachabilityClaim
          && uncertaintyPreserved
          && countAligned
          && firewallAligned;
      } else if (answer.intent === "comprehensive_health" && Number(answer.evidence?.health?.unhealthy ?? 0) > 0) {
        evidenceAligned = /unhealthy/i.test(firstLine);
      } else if (answer.intent === "app_verify") {
        const state = String(answer.evidence?.verification?.state ?? "");
        evidenceAligned = /homarr/i.test(firstLine) && (!state || text.toLowerCase().includes(state.toLowerCase()));
      }
      const ok = answer.intent === expected.intent
        && answer.engine === "full-zimabrain+mcp"
        && answer.sourceCommit === "d1add8738146a04b42e7285965f6811467b88e47"
        && answer.sources.includes(expected.source)
        && firstLine.length >= 12
        && !firstLine.startsWith("#")
        && !text.includes("Plain-English answer")
        && text.includes("## Evidence and reasoning")
        && evidenceAligned;
      return {
        question: expected.question,
        ok,
        intent: answer.intent,
        verification: answer.verification,
        firstLine: firstLine.slice(0, 500),
        evidenceAligned,
        engine: answer.engine,
        sources: answer.sources,
      };
    });
    checks.brain_answer_quality = {
      ok: cases.every((item) => item.ok),
      passed: cases.filter((item) => item.ok).length,
      total: cases.length,
      cases,
    };
  } catch (error) {
    checks.brain_answer_quality = { ok: false, error: String(error?.message ?? error).slice(0, 300) };
  }

  const firstApplication = applications?.items?.[0];
  const reference = firstApplication?.project ?? firstApplication?.containers?.[0]?.name ?? null;
  if (reference) {
    try {
      const value = await zimaAppVerify(reference);
      checks.zima_app_verify = { ok: true, requested: reference, state: value.state };
    } catch (error) {
      checks.zima_app_verify = { ok: false, error: String(error?.message ?? error).slice(0, 300) };
    }
  } else {
    checks.zima_app_verify = { ok: true, state: "not_applicable", note: "No application reference was observed." };
  }
  return {
    name: "zimabrain-mcp-server",
    version: SERVER_VERSION,
    transport: "streamable-http",
    mode: "viewer",
    liveTools: 34,
    roadmapChecksPassed: Object.values(checks).every((item) => item.ok),
    roadmapChecks: checks,
  };
}

function createServer() {
  const server = new McpServer({ name: "zimabrain-mcp-server", version: SERVER_VERSION });

  registerReadTool(server, "server_info", "Describe the live MCP server and execute bounded self-checks for the completed original roadmap tools.", {}, serverInfo);
  registerReadTool(server, "system_info", "Read verified host OS, CPU, memory and uptime evidence.", {}, systemInfo);
  registerReadTool(server, "docker_info", "Read current Docker Engine totals, storage driver and root directory through the GET-only proxy.", {}, dockerInfo);
  registerReadTool(server, "system_sensors", "Read bounded host thermal and hwmon temperature evidence from sysfs.", {}, systemSensors);
  registerReadTool(server, "storage_mounts", "List verified host storage mount sources and targets.", {}, storageMounts);
  registerReadTool(server, "storage_inventory", "List physical disks, partitions, filesystems and approved mountpoints through the fixed storage collector.", {}, storageInventory);
  registerReadTool(server, "filesystem_usage", "Read capacity and usage for approved /DATA and /media filesystems.", {}, filesystemUsage);
  registerReadTool(server, "smart_health", "Read bounded SMART health, temperature, sector and CRC evidence from explicitly allowed SATA devices.", {}, smartHealth);
  registerReadTool(server, "nvme_health", "Read bounded NVMe health, temperature, endurance and media-error evidence from explicitly allowed controllers.", {}, nvmeHealth);
  registerReadTool(server, "btrfs_health", "Read Btrfs filesystem membership and persistent device error counters from explicitly allowed devices.", {}, btrfsHealth);
  registerReadTool(server, "raid_health", "Report configured MD RAID, multi-device Btrfs and observable ZFS state without claiming health when RAID is absent.", {}, raidHealth);
  registerReadTool(server, "docker_ps", "List Docker containers through the GET-only socket proxy.", {}, dockerContainers);
  registerReadTool(server, "docker_images", "List local Docker images through the GET-only socket proxy.", {}, dockerImages);
  registerReadTool(
    server,
    "docker_inspect",
    "Inspect one container while omitting environment, command, entrypoint and labels.",
    { container: containerReference },
    ({ container }) => dockerInspect(container),
  );
  registerReadTool(server, "network_interfaces", "Read host interfaces, link state and assigned addresses.", {}, networkInterfaces);
  registerReadTool(server, "network_routes", "Read host IPv4 and IPv6 routes and active default gateways.", {}, networkRoutes);
  registerReadTool(
    server,
    "net_dns",
    "Resolve one name from a fixed diagnostic allow-list through the host resolver.",
    { domain: z.enum(["github.com", "zimaspace.com", "cloudflare.com"]).default("github.com") },
    ({ domain }) => networkDns(domain),
    true,
  );
  registerReadTool(
    server,
    "net_ping",
    "Run a bounded ICMP reachability check against the active gateway, configured DNS resolver or fixed public probe.",
    { target: z.enum(["gateway", "dns", "internet"]).default("gateway"), count: z.number().int().min(1).max(4).default(3) },
    ({ target, count }) => networkPing(target, count),
    true,
  );
  registerReadTool(server, "network_open_ports", "List host listening sockets and classify local, LAN, overlay and bridge bind scope without claiming internet exposure.", {}, networkOpenPorts);
  registerReadTool(server, "zima_firewall_status", "Compare saved ZFW policy with active IPv4 and IPv6 firewall hooks.", {}, zimaFirewallStatus);
  registerReadTool(server, "zima_security_scan", "Report verified firewall, listener and bounded Docker privilege exposure findings without inferring internet reachability.", {}, zimaSecurityScan);
  registerReadTool(
    server,
    "docker_logs",
    "Read a bounded, redacted tail from one container (maximum 200 lines).",
    { container: containerReference, tail: z.number().int().min(1).max(200).default(100) },
    ({ container, tail }) => dockerLogs(container, tail),
  );
  registerReadTool(
    server,
    "system_processes",
    "List bounded host processes without command lines or environment data.",
    { sort: z.enum(["cpu", "memory", "pid"]).default("cpu"), limit: z.number().int().min(1).max(100).default(25) },
    ({ sort, limit }) => systemProcesses(sort, limit),
  );
  registerReadTool(server, "zima_failed_services", "Query failed host systemd units through one fixed read-only system-bus call, returning not_verified if the query fails.", {}, zimaFailedServices);
  registerReadTool(server, "zima_journal_errors", "Read and redact at most 200 emergency-to-error entries from fixed host journal directories.", {}, zimaJournalErrors);
  registerReadTool(server, "zima_rauc_status", "Read RAUC boot/configuration evidence and query installer properties through one fixed read-only system-bus call.", {}, zimaRaucStatus);
  registerReadTool(server, "docker_stats", "Read bounded live CPU, memory, network and block-I/O statistics for running containers through the GET-only Docker proxy.", {}, dockerStats);
  registerReadTool(server, "docker_health", "Detect unhealthy containers, restart-loop indicators, current ports and mounts, and compare against the previous bounded health snapshot.", {}, dockerHealth);
  registerReadTool(server, "docker_health_history", "Read the bounded local history of container state, health and restart indicators.", {}, dockerHealthHistory);
  registerReadTool(server, "zima_boot_diagnostics", "Read bounded current-boot warning-to-emergency journal and kernel evidence with fixed root-cause classification.", {}, zimaBootDiagnostics);
  registerReadTool(server, "backup_inventory", "Inventory bounded Borg repository structures and backup-related containers without claiming backup success from file activity alone.", {}, backupInventory);
  registerReadTool(server, "backup_status", "Report backup inventory, observable job state, and whether success, schedule, integrity and restore readiness are actually verified.", {}, backupStatus);
  registerReadTool(server, "zima_apps", "Inventory Compose-managed and standalone ZimaOS containers, images, configuration paths and approved bind-mount sources.", {}, zimaApps);
  registerReadTool(
    server,
    "zima_app_verify",
    "Verify one Compose project or container against current image, state, health, configuration-path and approved mount evidence.",
    { app: containerReference },
    ({ app }) => zimaAppVerify(app),
  );

  server.registerResource(
    "current-inventory",
    "zimaos://inventory/current",
    { description: "Current read-only ZimaOS evidence inventory", mimeType: "application/json" },
    async (uri) => ({
      contents: [{ uri: uri.href, mimeType: "application/json", text: JSON.stringify(await dashboardEvidence(), null, 2) }],
    }),
  );

  server.registerPrompt(
    "diagnose_system",
    {
      description: "Verifier-first system review using only current MCP evidence.",
      argsSchema: { question: z.string().min(3).max(500) },
    },
    async ({ question }) => ({
      messages: [{ role: "user", content: { type: "text", text: `Question: ${question}\nUse current MCP evidence only. Separate verified, partially verified, and not verified claims. Do not infer success without proof.` } }],
    }),
  );

  return server;
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "256kb" }));

app.get("/health", (_request, response) => {
  response.json({ status: "ok", name: "zimabrain-mcp-server", version: SERVER_VERSION, mode: "viewer", liveTools: 34, systemLayer: "fixed-read-only-collector", storageLayer: "fixed-read-only-collector", networkLayer: "fixed-read-only-collector" });
});

app.get("/api/dashboard", async (_request, response) => {
  const started = Date.now();
  try {
    const evidence = await dashboardEvidence();
    const auditWriteSuccessful = await writeAudit({
      actor: "ui-dashboard",
      tool: "dashboard_evidence",
      result: "SUCCESS",
      durationMs: Date.now() - started,
    });
    const [audit, questionHistory] = await Promise.all([readAudit(20), readQuestionHistory(50)]);
    response.set("Cache-Control", "no-store").json({
      ...evidence,
      audit,
      questionHistory,
      auditPersistence: auditWriteSuccessful ? "file" : "unavailable",
    });
  } catch (error) {
    await writeAudit({
      actor: "ui-dashboard",
      tool: "dashboard_evidence",
      result: "ERROR",
      durationMs: Date.now() - started,
      error: String(error?.message ?? error),
    });
    response.status(503).json({ status: "error", error: String(error?.message ?? error), generatedAt: new Date().toISOString() });
  }
});

app.post("/api/ask", async (request, response) => {
  const started = Date.now();
  try {
    const result = await answerQuestion(request.body?.question);
    await writeAudit({
      type: "question",
      actor: "ui-user",
      tool: `brain:${result.intent}`,
      result: "SUCCESS",
      durationMs: Date.now() - started,
      question: result.question,
      intent: result.intent,
      verification: result.verification,
      answer: result.answer,
      sources: result.sources,
      engine: result.engine,
      sourceCommit: result.sourceCommit,
    });
    response.set("Cache-Control", "no-store").json(result);
  } catch (error) {
    await writeAudit({
      actor: "ui-user",
      tool: "brain:question",
      result: "ERROR",
      durationMs: Date.now() - started,
      error: String(error?.message ?? error),
    });
    response.status(400).json({ status: "error", error: String(error?.message ?? error) });
  }
});

app.post("/mcp", async (request, response) => {
  const sessionId = request.header("mcp-session-id");
  try {
    let transport = sessionId ? transports.get(sessionId) : undefined;
    if (!transport && !sessionId && isInitializeRequest(request.body)) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        enableJsonResponse: true,
        onsessioninitialized: (id) => transports.set(id, transport),
      });
      transport.onclose = () => {
        if (transport.sessionId) transports.delete(transport.sessionId);
      };
      const server = createServer();
      await server.connect(transport);
    } else if (!transport) {
      response.status(400).json({ jsonrpc: "2.0", error: { code: -32000, message: "Invalid or missing MCP session" }, id: null });
      return;
    }
    await transport.handleRequest(request, response, request.body);
  } catch {
    if (!response.headersSent) {
      response.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal MCP error" }, id: null });
    }
  }
});

app.get("/mcp", async (request, response) => {
  const transport = transports.get(request.header("mcp-session-id"));
  if (!transport) return response.status(400).send("Invalid or missing MCP session");
  await transport.handleRequest(request, response);
});

app.delete("/mcp", async (request, response) => {
  const transport = transports.get(request.header("mcp-session-id"));
  if (!transport) return response.status(400).send("Invalid or missing MCP session");
  await transport.handleRequest(request, response);
});

app.listen(port, "0.0.0.0", () => {
  console.log(`ZimaBrain MCP server listening on ${port}`);
});

async function shutdown() {
  for (const transport of transports.values()) await transport.close();
  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
