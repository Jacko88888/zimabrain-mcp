import {
  dashboardEvidence,
  dockerContainers,
  networkInterfaces,
  networkOpenPorts,
  smartHealth,
  nvmeHealth,
  raidHealth,
  storageInventory,
  zimaFailedServices,
  zimaFirewallStatus,
  zimaSecurityScan,
} from "./evidence.js";
import { backupStatus, dockerHealth, dockerStats, zimaApps, zimaAppVerify } from "./roadmap.js";
import { readAudit } from "./audit.js";

function normalise(question) {
  return String(question ?? "").trim().replace(/\s+/g, " ");
}

function classify(question) {
  const q = question.toLowerCase();
  if (/what (service|process|container).*(using|use).*disk|disk (io|i\/o|activity|usage).*(service|process|container)/.test(q)) return "disk_io_service";
  if (/how many.*disk|disk.*how many/.test(q)) return "disk_inventory";
  if (/(disk|drive|smart|nvme).*(health|healthy|failing|failure)|are my (disk|drive)/.test(q)) return "disk_health";
  if (/which.*container.*(not running|stopped|exited)|container.*(not running|stopped|exited)/.test(q)) return "containers_not_running";
  if (/what.*(needs attention|wrong|problem|issue)|critical risk|system health|health.*system/.test(q)) return "comprehensive_health";
  if (/backup|borg|restore readiness/.test(q)) return "backup_status";
  if (/expos|open port|firewall|lan|security/.test(q)) return "network_exposure";
  if (/how many.*app|app.*how many/.test(q)) return "app_inventory";
  if (/homarr|app.*attention|verify.*app/.test(q)) return "app_verify";
  return "custom_question";
}

function result(intent, verification, answer, sources, evidence = {}) {
  return {
    intent,
    verification,
    answer,
    sources,
    evidence,
    generatedAt: new Date().toISOString(),
  };
}

function deviceLabel(item) {
  const name = item.name ?? item.device ?? "unknown";
  const model = String(item.model ?? "").trim();
  return model ? `${name} (${model})` : name;
}

function firewallSummary(firewall = {}) {
  if (firewall.state === "active" && firewall.active === true) {
    return "Active ZFW firewall hooks were verified.";
  }
  if (firewall.state === "configured_not_applied") {
    return "ZFW has saved enabled rules, but active firewall hooks were not observed.";
  }
  if (firewall.state === "service_only") {
    return "The ZFW service is running, but no active ZFW hooks or saved enabled rules were observed.";
  }
  if (firewall.state === "not_configured") {
    return "No running ZFW service, active ZFW hooks or saved enabled rules were observed.";
  }
  return "ZFW firewall enforcement could not be verified from the collected evidence.";
}

function publishedDockerPorts(containers = []) {
  return containers.flatMap((container) => (container.ports ?? [])
    .filter((port) => Number.isInteger(port.public))
    .map((port) => ({
      container: container.name ?? "unknown",
      hostIp: port.ip || "0.0.0.0",
      hostPort: port.public,
      containerPort: port.private,
      protocol: port.type ?? "tcp",
      potentiallyLanAccessible: !["127.0.0.1", "::1"].includes(port.ip),
    })));
}

function compactNetworkApplications(applications = {}) {
  const items = (applications.items ?? []).map((application) => ({
    project: application.project ?? null,
    containers: (application.containers ?? []).map((container) => ({
      name: container.name ?? "unknown",
      mounts: (container.mounts ?? []).map((mount) => ({
        source: mount.source ?? null,
        destination: mount.destination ?? null,
        readWrite: mount.readWrite === true,
        type: mount.type ?? null,
      })),
    })),
  }));
  return {
    observedApplications: applications.observedApplications ?? items.length,
    observedContainers: applications.observedContainers ?? items.reduce((count, item) => count + item.containers.length, 0),
    bounded: applications.bounded === true,
    maximumContainers: applications.maximumContainers ?? null,
    items,
  };
}

export function buildNetworkExposureResult({ scan = {}, ports = {}, firewall = {}, containers = [], applications = {}, interfaces = {} }) {
  const listeners = (ports.listeners ?? scan.listeners ?? []).filter((item) =>
    ["all_interfaces", "lan"].includes(item.scope)
  );
  const uniqueListeners = [...new Map(listeners.map((item) => [
    `${item.port}/${item.protocol}/${item.process ?? ""}`,
    item,
  ])).values()];
  const listenerSummary = uniqueListeners.slice(0, 30).map((item) =>
    `${item.port}/${item.protocol}${item.process ? ` (${item.process})` : ""}`
  ).join(", ");
  const publishedPorts = publishedDockerPorts(containers);
  const remoteAccessContainers = containers
    .filter((container) => /(cloudflare|cloudflared|tailscale|wireguard|zerotier|nginx|traefik|caddy|proxy|tunnel)/i.test(container.name ?? ""))
    .map((container) => container.name);
  const attentionFindings = (scan.findings ?? []).filter((finding) => finding.severity === "attention");
  const applicationEvidence = compactNetworkApplications(applications);
  const firewallText = firewallSummary(firewall);
  const verifiedConnectionProbe = ports.lanReachabilityMeasured === true;
  const externalMeasured = scan.externalReachabilityMeasured === true;

  const opening = uniqueListeners.length
    ? `${uniqueListeners.length} unique port/service combination(s) are listening on LAN or all-interface binds (${listeners.length} socket row(s)). They may be accessible from the LAN, but no LAN connection probe was performed. ${firewallText} Internet exposure was not measured.`
    : `No listener bound to a LAN or all-interface address was observed in the bounded socket inventory. This does not prove the host is unreachable. ${firewallText} LAN and internet reachability were not measured.`;

  return result(
    "network_exposure",
    verifiedConnectionProbe && externalMeasured ? "VERIFIED" : "PARTIALLY VERIFIED",
    opening,
    ["network_open_ports", "zima_firewall_status", "docker_ps", "zima_apps", "network_interfaces", "zima_security_scan"],
    {
      scan,
      ports,
      firewall,
      containers,
      applications: applicationEvidence,
      interfaces,
      potentiallyLanAccessibleListeners: listeners,
      uniquePotentialListeners: uniqueListeners,
      publishedDockerPorts: publishedPorts,
      remoteAccessContainers,
      attentionFindings,
      claimChecks: {
        socketBindObserved: true,
        lanConnectionProbePerformed: verifiedConnectionProbe,
        internetReachabilityMeasured: externalMeasured,
        firewallStateVerified: typeof firewall.state === "string",
        dockerPublishedPortsCollected: true,
        applicationMountEvidenceCollected: Array.isArray(applications.items),
      },
      listenerSummary,
    },
  );
}

async function answerQuestionFallback(rawQuestion) {
  const question = normalise(rawQuestion);
  if (question.length < 3 || question.length > 500) {
    throw new Error("Question must contain between 3 and 500 characters");
  }
  const intent = classify(question);

  let response;
  if (intent === "disk_io_service") {
    const first = await dockerStats();
    await new Promise(resolve => setTimeout(resolve, 1200));
    const second = await dockerStats();
    const before = new Map((first.items ?? []).map(item => [item.container, item]));
    const activity = (second.items ?? []).map(item => {
      const previous = before.get(item.container) ?? {};
      return {
        container: item.container,
        readBytes: Math.max(0, Number(item.blockReadBytes ?? 0) - Number(previous.blockReadBytes ?? 0)),
        writeBytes: Math.max(0, Number(item.blockWriteBytes ?? 0) - Number(previous.blockWriteBytes ?? 0)),
        cumulativeReadBytes: Number(item.blockReadBytes ?? 0),
        cumulativeWriteBytes: Number(item.blockWriteBytes ?? 0),
      };
    }).map(item => ({ ...item, totalBytes: item.readBytes + item.writeBytes }))
      .sort((a, b) => b.totalBytes - a.totalBytes);
    const active = activity.filter(item => item.totalBytes > 0);
    const format = bytes => bytes >= 1073741824 ? `${(bytes / 1073741824).toFixed(2)} GiB`
      : bytes >= 1048576 ? `${(bytes / 1048576).toFixed(2)} MiB`
      : bytes >= 1024 ? `${(bytes / 1024).toFixed(2)} KiB` : `${bytes} B`;
    response = result(intent, "VERIFIED",
      active.length
        ? `During a 1.2-second live sample, ${active.length} container(s) generated block I/O: ${active.slice(0, 8).map(item => `${item.container} (read ${format(item.readBytes)}, write ${format(item.writeBytes)})`).join("; ")}.`
        : "No running container generated measurable block I/O during the 1.2-second live sample. This does not prove there is no disk activity outside containers or outside the sample window.",
      ["docker_stats"],
      { sampleWindowMs: 1200, observedRunningContainers: second.observedRunningContainers, activity });
  } else if (intent === "disk_inventory") {
    const inventory = await storageInventory();
    const disks = inventory.disks ?? [];
    response = result(intent, "VERIFIED",
      `${inventory.observedDisks ?? disks.length} physical disks were observed: ${disks.map(deviceLabel).join(", ") || "none"}.`,
      ["storage_inventory"],
      { observedDisks: inventory.observedDisks ?? disks.length, disks });
  } else if (intent === "disk_health") {
    const [smart, nvme, raid] = await Promise.all([smartHealth(), nvmeHealth(), raidHealth()]);
    const smartDevices = smart.devices ?? [];
    const nvmeDevices = nvme.devices ?? [];
    const attention = [...smartDevices, ...nvmeDevices].filter(x => ["attention", "critical", "failed"].includes(x.status)).length;
    const fullyVerified = smartDevices.length > 0 && smartDevices.every(x => x.status && x.status !== "unknown")
      && nvmeDevices.every(x => x.healthVerified === true);
    response = result(intent, fullyVerified ? "VERIFIED" : "PARTIALLY VERIFIED",
      attention
        ? `${attention} storage device health result(s) require attention. Some health fields may remain unverified.`
        : fullyVerified
          ? `${smartDevices.length + nvmeDevices.length} storage devices were checked and no failing health result was reported.`
          : "No failing result was observed in the available checks, but complete SMART/NVMe health is not verified for every physical disk.",
      ["smart_health", "nvme_health", "raid_health"],
      { smart, nvme, raid });
  } else if (intent === "containers_not_running") {
    const containers = await dockerContainers();
    const stopped = containers.filter(x => x.state !== "running");
    response = result(intent, "VERIFIED",
      stopped.length
        ? `${stopped.length} of ${containers.length} observed containers are not running: ${stopped.map(x => x.name ?? x.names?.[0] ?? x.id?.slice(0,12) ?? "unknown").join(", ")}.`
        : `All ${containers.length} observed containers are running.`,
      ["docker_ps"],
      { observedContainers: containers.length, stopped });
  } else if (intent === "comprehensive_health") {
    const [health, failed, dashboard] = await Promise.all([dockerHealth(), zimaFailedServices(), dashboardEvidence()]);
    const unhealthy = (health.items ?? []).filter(x => x.state === "running" && x.health === "unhealthy");
    const failedItems = failed.items ?? failed.units ?? [];
    const findings = dashboard.findings ?? [];
    const attention = findings.filter(x => x.state === "attention");
    const nonContainerAttention = attention.filter(x => x.name !== "containers_healthy" && x.source !== "docker_ps");
    const messages = [...new Set([
      ...unhealthy.map(x => `${x.name ?? "container"} is unhealthy`),
      ...failedItems.map(x => `${x.name ?? x.unit ?? "service"} is failed`),
      ...nonContainerAttention.map(x => x.result),
    ].filter(Boolean))];
    response = result(intent, messages.length ? "VERIFIED" : "PARTIALLY VERIFIED",
      messages.length
        ? `${messages.length} evidence-backed attention signal(s) were observed: ${messages.join("; ")}.`
        : "No current attention signal was observed in the available container, service and dashboard evidence. This is not a guarantee that every domain is healthy.",
      ["docker_health", "zima_failed_services", "dashboard_evidence"],
      { health, failedServices: failed, findings, attentionMessages: messages });
  } else if (intent === "backup_status") {
    const backup = await backupStatus();
    const verified = backup.state === "verified" || backup.successVerified === true;
    response = result(intent, verified ? "VERIFIED" : "NOT VERIFIED",
      verified
        ? "Current backup evidence verifies the reported backup state."
        : `Backup success, integrity and restore readiness are not verified. Observed state: ${backup.state ?? "unknown"}.`,
      ["backup_status"],
      { backup });
  } else if (intent === "network_exposure") {
    const [scan, ports, firewall, containers, applications, interfaces] = await Promise.all([
      zimaSecurityScan(),
      networkOpenPorts(),
      zimaFirewallStatus(),
      dockerContainers(),
      zimaApps(),
      networkInterfaces(),
    ]);
    response = buildNetworkExposureResult({ scan, ports, firewall, containers, applications, interfaces });
  } else if (intent === "app_inventory") {
    const apps = await zimaApps();
    const count = apps.observedApplications ?? apps.items?.length ?? 0;
    response = result(intent, "VERIFIED", `${count} applications were observed in the current ZimaOS application inventory.`,
      ["zima_apps"], { apps });
  } else if (intent === "app_verify") {
    const apps = await zimaApps();
    const q = question.toLowerCase();
    const references = (item) => [
      item.project,
      item.name,
      ...(item.containers ?? []).flatMap(container => [container.name, container.service]),
    ].map(value => String(value ?? "").trim().toLowerCase()).filter(Boolean);
    const candidate = (apps.items ?? []).find(item => references(item).some(reference => q.includes(reference)))
      ?? (q.includes("homarr") ? (apps.items ?? []).find(item => references(item).some(reference => reference.includes("homarr"))) : null);
    if (!candidate) {
      response = result(intent, "NOT VERIFIED", "No matching application could be identified from the current application inventory.", ["zima_apps"]);
    } else {
      const reference = candidate.project ?? candidate.name ?? candidate.containers?.[0]?.name;
      const verification = await zimaAppVerify(reference);
      const reasons = [...new Set((verification.items ?? []).flatMap(item => [
        ...(item.containers ?? []).filter(container => container.state !== "running").map(container => `${container.name} is ${container.state}`),
        ...(item.containers ?? []).filter(container => container.state === "running" && container.health === "unhealthy").map(container => `${container.name} is unhealthy`),
        ...(item.missingImages ?? []).map(name => `image missing for ${name}`),
        ...(item.missingPaths ?? []).map(path => `required path is missing: ${path}`),
      ]))];
      const summary = verification.state === "healthy"
        ? "The application is running and no missing image or approved-path evidence was detected."
        : reasons.length
          ? `Attention is required because ${reasons.join("; ")}.`
          : "The application requires attention, but the available evidence does not identify a specific cause.";
      response = result(intent, verification.state === "healthy" ? "VERIFIED" : verification.verified ? "PARTIALLY VERIFIED" : "NOT VERIFIED",
        `${reference}: ${summary}`,
        ["zima_apps", "zima_app_verify"], { verification, reasons });
    }
  } else {
    const dashboard = await dashboardEvidence();
    response = result(intent, "NOT VERIFIED",
      "The current Brain does not have a verified domain route for this question. No answer was inferred from unrelated evidence.",
      ["dashboard_evidence"], { availableDomains: ["system", "docker", "storage", "network", "backup", "applications"] });
  }

  return { question, ...response };
}

export async function readQuestionHistory(limit = 50) {
  const records = await readAudit(1000);
  return records
    .filter(record => record.type === "question" && record.question && record.answer)
    .slice(0, limit)
    .map(record => ({
      question: record.question,
      intent: record.intent,
      verification: record.verification,
      answer: record.answer,
      sources: record.sources ?? [],
      engine: record.engine ?? null,
      sourceCommit: record.sourceCommit ?? null,
      generatedAt: record.timestamp,
    }));
}


const FULL_BRAIN_URL = process.env.FULL_BRAIN_URL ?? "http://brain:8601";
const FULL_BRAIN_SOURCE_COMMIT = "d1add8738146a04b42e7285965f6811467b88e47";

function cleanBrainAnswer(value) {
  return String(value ?? "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<\/li>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\n{3,}/g, "\n\n")
    .trim()
    .slice(0, 16000);
}

async function fullBrainAnswer(question, fallback) {
  const evidence = { fallback };
  if (["containers_not_running", "comprehensive_health", "custom_question"].includes(fallback.intent)) {
    evidence.containers = await dockerContainers();
  }
  const response = await fetch(FULL_BRAIN_URL + "/answer", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question, evidence }),
    signal: AbortSignal.timeout(45000),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.status !== "ok" || payload.sourceCommit !== FULL_BRAIN_SOURCE_COMMIT) {
    throw new Error(payload.error ?? `Full Brain HTTP ${response.status}`);
  }
  return payload;
}

function combineAnswers(brainAnswer, fallback) {
  let reasoning = cleanBrainAnswer(brainAnswer);
  const grounded = String(fallback.answer ?? "").trim();
  const sourceLine = (fallback.sources ?? []).join(" · ");
  const question = String(fallback.question ?? "").trim().toLowerCase();
  const lines = reasoning.split("\n");
  const isPreamble = (line) => {
    const value = String(line).replace(/^#{1,6}\s*/, "").replace("❓", "").trim().toLowerCase();
    return !value || value === "zimabrain answer" || value === "question asked" || value === question;
  };
  while (lines.length && isPreamble(lines[0])) lines.shift();
  reasoning = lines.join("\n").trim();
  const sections = [];
  if (grounded) sections.push(grounded);
  if (reasoning) sections.push(`## Evidence and reasoning\n\n${reasoning}`);
  if (sourceLine) sections.push(`## Evidence sources\n\n${sourceLine}`);
  return sections.join("\n\n");
}

export async function answerQuestion(rawQuestion) {
  const question = normalise(rawQuestion);
  const fallback = await answerQuestionFallback(question);
  try {
    const full = await fullBrainAnswer(question, fallback);
    const verification = fallback.intent === "custom_question"
      ? (full.verification ?? fallback.verification)
      : fallback.verification;
    return {
      ...fallback,
      verification,
      answer: combineAnswers(full.answer, fallback),
      sources: [...new Set([`zimabrain-full:${FULL_BRAIN_SOURCE_COMMIT.slice(0, 12)}`, ...(fallback.sources ?? [])])],
      evidence: {
        ...fallback.evidence,
        brain: {
          engine: full.engine,
          sourceRepository: full.sourceRepository,
          sourceCommit: full.sourceCommit,
          generatedAt: full.generatedAt,
          mcpVerification: fallback.verification,
        },
      },
      engine: "full-zimabrain+mcp",
      sourceCommit: full.sourceCommit,
    };
  } catch (error) {
    return {
      ...fallback,
      engine: "mcp-evidence-fallback",
      brainUnavailable: true,
      brainError: String(error?.message ?? error).slice(0, 300),
    };
  }
}
