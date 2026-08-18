import { readFile, rename, writeFile } from "node:fs/promises";

const DOCKER_API = process.env.DOCKER_API ?? "http://docker-proxy:2375";
const STORAGE_COLLECTOR_URL = process.env.STORAGE_COLLECTOR_URL ?? "http://storage-collector:8720";
const HISTORY_PATH = process.env.CONTAINER_HISTORY_PATH ?? "/data/container-health-history.json";
const MAX_CONTAINERS = 100;
const memoryHistory = [];
let historyPersistence = "memory";
const COMPOSE_LABELS = [
  "com.docker.compose.project",
  "com.docker.compose.project.working_dir",
  "com.docker.compose.project.config_files",
  "com.docker.compose.service",
  "com.docker.compose.version",
];

async function dockerGet(path, timeout = 10000) {
  const response = await fetch(`${DOCKER_API}${path}`, {
    signal: AbortSignal.timeout(timeout),
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error(`Docker proxy returned HTTP ${response.status}`);
  return response.json();
}

async function storageGet(endpoint, query = {}) {
  const parameters = new URLSearchParams();
  for (const [key, values] of Object.entries(query)) {
    for (const value of Array.isArray(values) ? values : [values]) parameters.append(key, String(value));
  }
  const response = await fetch(`${STORAGE_COLLECTOR_URL}/${endpoint}${parameters.size ? `?${parameters}` : ""}`, {
    signal: AbortSignal.timeout(20000),
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error(`Storage collector returned HTTP ${response.status}`);
  const payload = await response.json();
  if (payload?.collectorStatus !== "success") throw new Error(`Storage collector failed: ${payload?.error ?? "unknown error"}`);
  return payload;
}

async function inspectContainers(containers) {
  const results = [];
  for (let index = 0; index < containers.length; index += 10) {
    const batch = containers.slice(index, index + 10);
    results.push(...await Promise.all(batch.map((container) =>
      dockerGet(`/containers/${encodeURIComponent(container.Id)}/json`).catch(() => null)
    )));
  }
  return results.filter(Boolean);
}

function containerName(value) {
  return String(value?.Name ?? value?.Names?.[0] ?? "unknown").replace(/^\//, "");
}

function uptimeSeconds(startedAt) {
  const started = Date.parse(startedAt ?? "");
  return Number.isFinite(started) ? Math.max(0, Math.floor((Date.now() - started) / 1000)) : null;
}

export function calculateDockerCpu(stats) {
  const cpuDelta = Number(stats?.cpu_stats?.cpu_usage?.total_usage ?? 0) - Number(stats?.precpu_stats?.cpu_usage?.total_usage ?? 0);
  const systemDelta = Number(stats?.cpu_stats?.system_cpu_usage ?? 0) - Number(stats?.precpu_stats?.system_cpu_usage ?? 0);
  const cpus = Number(stats?.cpu_stats?.online_cpus ?? stats?.cpu_stats?.cpu_usage?.percpu_usage?.length ?? 1) || 1;
  if (cpuDelta <= 0 || systemDelta <= 0) return 0;
  return Number(((cpuDelta / systemDelta) * cpus * 100).toFixed(2));
}

export function normalizeDockerStats(stats, name) {
  const memory = stats?.memory_stats ?? {};
  const cache = Number(memory?.stats?.inactive_file ?? memory?.stats?.cache ?? 0);
  const used = Math.max(0, Number(memory.usage ?? 0) - cache);
  const limit = Number(memory.limit ?? 0);
  const sum = (collection) => Object.values(collection ?? {}).reduce((total, item) => total + Number(item ?? 0), 0);
  const network = Object.values(stats?.networks ?? {});
  const block = stats?.blkio_stats?.io_service_bytes_recursive ?? [];
  return {
    container: name,
    readAt: stats?.read ?? new Date().toISOString(),
    cpuPercent: calculateDockerCpu(stats),
    memoryUsageBytes: used,
    memoryLimitBytes: limit,
    memoryPercent: limit > 0 ? Number(((used / limit) * 100).toFixed(2)) : null,
    networkRxBytes: network.reduce((total, item) => total + Number(item.rx_bytes ?? 0), 0),
    networkTxBytes: network.reduce((total, item) => total + Number(item.tx_bytes ?? 0), 0),
    blockReadBytes: sum(Object.fromEntries(block.filter((item) => String(item.op).toLowerCase() === "read").map((item, index) => [index, item.value]))),
    blockWriteBytes: sum(Object.fromEntries(block.filter((item) => String(item.op).toLowerCase() === "write").map((item, index) => [index, item.value]))),
  };
}

export async function dockerStats() {
  const containers = (await dockerGet("/containers/json?all=0&size=0")).slice(0, MAX_CONTAINERS);
  const items = [];
  for (let index = 0; index < containers.length; index += 10) {
    const batch = containers.slice(index, index + 10);
    items.push(...await Promise.all(batch.map(async (container) => {
      const stats = await dockerGet(`/containers/${encodeURIComponent(container.Id)}/stats?stream=false&one-shot=true`, 15000);
      return normalizeDockerStats(stats, String(container.Names?.[0] ?? "unknown").replace(/^\//, ""));
    })));
  }
  return {
    generatedAt: new Date().toISOString(),
    observedRunningContainers: containers.length,
    bounded: true,
    maximumContainers: MAX_CONTAINERS,
    items,
  };
}

async function readHistory() {
  try {
    const value = JSON.parse(await readFile(HISTORY_PATH, "utf8"));
    historyPersistence = "file";
    return Array.isArray(value) ? value.slice(-200) : [];
  } catch {
    historyPersistence = "memory";
    return memoryHistory.slice(-200);
  }
}

async function saveHistory(items) {
  const history = await readHistory();
  const snapshot = {
    at: new Date().toISOString(),
    items: items.map(({ name, state, health, restartCount, restartLoop }) => ({ name, state, health, restartCount, restartLoop })),
  };
  const next = [...history, snapshot].slice(-200);
  const temporary = `${HISTORY_PATH}.tmp`;
  try {
    await writeFile(temporary, JSON.stringify(next), { encoding: "utf8", mode: 0o600 });
    await rename(temporary, HISTORY_PATH);
    historyPersistence = "file";
  } catch {
    memoryHistory.splice(0, memoryHistory.length, ...next);
    historyPersistence = "memory";
  }
  return { history: next, previous: history.at(-1) ?? null, current: snapshot, persistence: historyPersistence };
}

function verifyRuntimeConfiguration(detail) {
  const configuredPorts = Object.entries(detail.HostConfig?.PortBindings ?? {}).flatMap(([containerPort, bindings]) =>
    (bindings ?? []).map((binding) => ({
      containerPort,
      hostIp: binding.HostIp || null,
      hostPort: binding.HostPort || null,
    }))
  );
  const actualPorts = Object.entries(detail.NetworkSettings?.Ports ?? {}).flatMap(([containerPort, bindings]) =>
    (bindings ?? []).map((binding) => ({
      containerPort,
      hostIp: binding.HostIp || null,
      hostPort: binding.HostPort || null,
    }))
  );
  const actualPortKeys = new Set(actualPorts.map((item) => `${item.containerPort}:${item.hostIp}:${item.hostPort}`));
  const missingPortBindings = configuredPorts.filter((item) => !actualPortKeys.has(`${item.containerPort}:${item.hostIp}:${item.hostPort}`));

  const bindTargets = (detail.HostConfig?.Binds ?? []).map((value) => String(value).split(":")[1]).filter(Boolean);
  const mountTargets = (detail.HostConfig?.Mounts ?? []).map((item) => item.Target).filter(Boolean);
  const configuredMountTargets = [...new Set([...bindTargets, ...mountTargets])];
  const actualMountTargets = new Set((detail.Mounts ?? []).map((item) => item.Destination));
  const missingMountTargets = configuredMountTargets.filter((target) => !actualMountTargets.has(target));

  return {
    ports: {
      configured: configuredPorts.length,
      active: actualPorts.length,
      verified: missingPortBindings.length === 0,
      missingBindings: missingPortBindings,
    },
    mounts: {
      configured: configuredMountTargets.length,
      active: actualMountTargets.size,
      verified: missingMountTargets.length === 0,
      missingTargets: missingMountTargets,
    },
  };
}

export async function dockerHealth() {
  const containers = (await dockerGet("/containers/json?all=1&size=0")).slice(0, MAX_CONTAINERS);
  const details = await inspectContainers(containers);
  const items = details.map((detail) => {
    const state = detail.State ?? {};
    const uptime = uptimeSeconds(state.StartedAt);
    const restartCount = Number(detail.RestartCount ?? 0);
    const restartLoop = state.Restarting === true || (state.Running === true && restartCount >= 3 && uptime !== null && uptime < 3600);
    const runtimeVerification = verifyRuntimeConfiguration(detail);
    return {
      name: containerName(detail),
      image: detail.Config?.Image ?? null,
      state: state.Status ?? null,
      health: state.Health?.Status ?? "not-reported",
      restartCount,
      uptimeSeconds: uptime,
      restartLoop,
      restartLoopReason: state.Restarting === true
        ? "docker_state_restarting"
        : restartLoop
          ? "three_or_more_restarts_with_less_than_one_hour_uptime"
          : null,
      portVerification: runtimeVerification.ports,
      mountVerification: runtimeVerification.mounts,
      publishedPorts: detail.NetworkSettings?.Ports ?? {},
      mounts: (detail.Mounts ?? []).map((mount) => ({
        source: mount.Source,
        destination: mount.Destination,
        readWrite: Boolean(mount.RW),
        type: mount.Type,
      })),
    };
  }).sort((a, b) => a.name.localeCompare(b.name));
  const saved = await saveHistory(items).catch(() => ({ previous: null }));
  const previousByName = new Map((saved.previous?.items ?? []).map((item) => [item.name, item]));
  const changes = items.flatMap((item) => {
    const before = previousByName.get(item.name);
    if (!before) return [{ container: item.name, change: "newly_observed" }];
    const fields = ["state", "health", "restartCount", "restartLoop"];
    const changed = fields.filter((field) => before[field] !== item[field]);
    return changed.length ? [{ container: item.name, change: "state_changed", fields: changed, before, after: Object.fromEntries(fields.map((field) => [field, item[field]])) }] : [];
  });
  return {
    generatedAt: new Date().toISOString(),
    observedContainers: items.length,
    unhealthy: items.filter((item) => item.health === "unhealthy").length,
    restartLoops: items.filter((item) => item.restartLoop).length,
    portVerificationFailures: items.filter((item) => !item.portVerification.verified).length,
    mountVerificationFailures: items.filter((item) => !item.mountVerification.verified).length,
    comparisonAvailable: Boolean(saved.previous),
    historyPersistence: saved.persistence ?? historyPersistence,
    changes,
    bounded: true,
    maximumContainers: MAX_CONTAINERS,
    items,
  };
}

export async function dockerHealthHistory() {
  const history = await readHistory();
  return {
    snapshots: history.length,
    oldestAt: history[0]?.at ?? null,
    newestAt: history.at(-1)?.at ?? null,
    bounded: true,
    maximumSnapshots: 200,
    persistence: historyPersistence,
    items: history,
  };
}

function composeLabels(detail) {
  const labels = detail.Config?.Labels ?? {};
  return Object.fromEntries(COMPOSE_LABELS.filter((key) => labels[key]).map((key) => [key, String(labels[key]).slice(0, 1000)]));
}

function approvedPath(value) {
  return value === "/DATA" || value?.startsWith("/DATA/") || value === "/media" || value?.startsWith("/media/");
}

async function appEvidence() {
  const [containers, images] = await Promise.all([
    dockerGet("/containers/json?all=1&size=0"),
    dockerGet("/images/json?all=1"),
  ]);
  const details = await inspectContainers(containers.slice(0, MAX_CONTAINERS));
  const imageIds = new Set(images.map((image) => image.Id));
  const paths = new Set();
  const normalized = details.map((detail) => {
    const labels = composeLabels(detail);
    const workingDirectory = labels["com.docker.compose.project.working_dir"] ?? null;
    const configFiles = labels["com.docker.compose.project.config_files"]?.split(",").map((item) => item.trim()).filter(Boolean) ?? [];
    const mounts = (detail.Mounts ?? []).map((mount) => ({
      source: mount.Source,
      destination: mount.Destination,
      readWrite: Boolean(mount.RW),
      type: mount.Type,
    }));
    if (approvedPath(workingDirectory)) paths.add(workingDirectory);
    for (const file of configFiles) if (approvedPath(file)) paths.add(file);
    for (const mount of mounts) if (approvedPath(mount.source)) paths.add(mount.source);
    return {
      name: containerName(detail),
      project: labels["com.docker.compose.project"] ?? null,
      service: labels["com.docker.compose.service"] ?? null,
      workingDirectory,
      configFiles,
      image: detail.Config?.Image ?? null,
      imageId: detail.Image ?? null,
      imageAvailable: imageIds.has(detail.Image),
      state: detail.State?.Status ?? null,
      health: detail.State?.Health?.Status ?? "not-reported",
      mounts,
    };
  });
  const pathEvidence = paths.size ? await storageGet("paths", { path: [...paths] }) : { items: [] };
  const pathByName = new Map((pathEvidence.items ?? []).map((item) => [item.path, item]));
  for (const item of normalized) {
    item.workingDirectoryEvidence = item.workingDirectory ? pathByName.get(item.workingDirectory) ?? null : null;
    item.configFileEvidence = item.configFiles.map((path) => approvedPath(path)
      ? pathByName.get(path) ?? { path, exists: false, error: "not_verified" }
      : { path, exists: null, error: "outside_approved_roots" });
    item.mountEvidence = item.mounts
      .filter((mount) => approvedPath(mount.source))
      .map((mount) => pathByName.get(mount.source) ?? { path: mount.source, exists: false, error: "not_verified" });
  }
  return normalized;
}

export async function zimaApps() {
  const containers = await appEvidence();
  const projects = new Map();
  for (const container of containers) {
    const key = container.project ?? `unmanaged:${container.name}`;
    if (!projects.has(key)) projects.set(key, { project: container.project, managedByCompose: Boolean(container.project), containers: [] });
    projects.get(key).containers.push(container);
  }
  const items = [...projects.values()].map((project) => ({
    ...project,
    state: project.containers.every((item) => item.state === "running" && item.health !== "unhealthy") ? "running" : "attention",
    missingImages: project.containers.filter((item) => !item.imageAvailable).map((item) => item.name),
    missingPaths: project.containers.flatMap((item) => [
      ...(item.workingDirectoryEvidence?.exists === false ? [item.workingDirectoryEvidence.path] : []),
      ...item.configFileEvidence.filter((path) => path.exists === false).map((path) => path.path),
      ...item.mountEvidence.filter((path) => path.exists === false).map((path) => path.path),
    ]).filter((value, index, values) => values.indexOf(value) === index),
  })).sort((a, b) => String(a.project ?? a.containers[0]?.name).localeCompare(String(b.project ?? b.containers[0]?.name)));
  return {
    generatedAt: new Date().toISOString(),
    observedApplications: items.length,
    observedContainers: containers.length,
    composeApplications: items.filter((item) => item.managedByCompose).length,
    applicationsWithMissingImages: items.filter((item) => item.missingImages.length).length,
    applicationsWithMissingPaths: items.filter((item) => item.missingPaths.length).length,
    bounded: true,
    maximumContainers: MAX_CONTAINERS,
    items,
  };
}

export async function zimaAppVerify(app) {
  const inventory = await zimaApps();
  const normalized = String(app ?? "").trim().toLowerCase();
  const matches = inventory.items.filter((item) =>
    String(item.project ?? "").toLowerCase() === normalized
    || item.containers.some((container) => container.name.toLowerCase() === normalized)
  );
  return {
    generatedAt: inventory.generatedAt,
    requested: app,
    verified: matches.length > 0,
    state: matches.length === 0
      ? "not_found"
      : matches.some((item) => item.state !== "running" || item.missingImages.length || item.missingPaths.length)
        ? "attention"
        : "healthy",
    items: matches,
  };
}

function backupContainers(details) {
  return details.filter((detail) => /(borg|borgmatic|restic|kopia|duplicati|backup)/i.test(`${containerName(detail)} ${detail.Config?.Image ?? ""}`))
    .map((detail) => ({
      name: containerName(detail),
      image: detail.Config?.Image ?? null,
      state: detail.State?.Status ?? null,
      health: detail.State?.Health?.Status ?? "not-reported",
      startedAt: detail.State?.StartedAt ?? null,
      restartCount: Number(detail.RestartCount ?? 0),
    }));
}

export async function backupInventory() {
  const storage = await storageGet("backups");
  const containers = await dockerGet("/containers/json?all=1&size=0");
  const details = await inspectContainers(containers.slice(0, MAX_CONTAINERS));
  const jobs = backupContainers(details);
  return {
    generatedAt: new Date().toISOString(),
    ...storage,
    observedBackupContainers: jobs.length,
    backupContainers: jobs,
  };
}

export async function backupStatus() {
  const inventory = await backupInventory();
  const repositoryObserved = inventory.repositories > 0;
  const runningJobs = inventory.backupContainers.filter((item) => item.state === "running").length;
  const failedJobs = inventory.backupContainers.filter((item) => item.state === "exited" || item.health === "unhealthy").length;
  const state = failedJobs
    ? "attention"
    : repositoryObserved
      ? "partially_verified"
      : "not_configured";
  return {
    generatedAt: inventory.generatedAt,
    state,
    repositoryInventoryVerified: inventory.verifiedInventory === true,
    repositoryObserved,
    repositories: inventory.repositories,
    latestRepositoryActivity: inventory.latestRepositoryActivity,
    latestSuccessfulBackup: inventory.latestSuccessfulBackup,
    successfulBackupTimeVerified: inventory.successfulBackupTimeVerified,
    scheduleVerified: inventory.scheduleVerified,
    integrityVerified: inventory.integrityVerified,
    restoreTestVerified: inventory.restoreTestVerified,
    recoveryReadiness: inventory.integrityVerified && inventory.restoreTestVerified ? "verified" : "not_verified",
    observedBackupContainers: inventory.observedBackupContainers,
    runningBackupContainers: runningJobs,
    failedBackupContainers: failedJobs,
    items: inventory.items,
    backupContainers: inventory.backupContainers,
    note: repositoryObserved
      ? "Repository structures were observed, but success time, schedule, integrity and restore readiness remain unverified unless explicit evidence is available."
      : "No backup repository structure was observed inside the bounded approved roots.",
  };
}
