import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { calculateDockerCpu, normalizeDockerStats } from "../src/roadmap.js";

test("Docker performance calculations are bounded and deterministic", () => {
  const stats = {
    read: "2026-08-16T00:00:00Z",
    cpu_stats: { cpu_usage: { total_usage: 300, percpu_usage: [1, 1] }, system_cpu_usage: 1000, online_cpus: 2 },
    precpu_stats: { cpu_usage: { total_usage: 100 }, system_cpu_usage: 200 },
    memory_stats: { usage: 1000, limit: 2000, stats: { inactive_file: 100 } },
    networks: { eth0: { rx_bytes: 10, tx_bytes: 20 } },
    blkio_stats: { io_service_bytes_recursive: [{ op: "Read", value: 30 }, { op: "Write", value: 40 }] },
  };
  assert.equal(calculateDockerCpu(stats), 50);
  assert.deepEqual(normalizeDockerStats(stats, "demo"), {
    container: "demo",
    readAt: "2026-08-16T00:00:00Z",
    cpuPercent: 50,
    memoryUsageBytes: 900,
    memoryLimitBytes: 2000,
    memoryPercent: 45,
    networkRxBytes: 10,
    networkTxBytes: 20,
    blockReadBytes: 30,
    blockWriteBytes: 40,
  });
});

test("all original roadmap completion tools are registered read-only", async () => {
  const [server, roadmap, evidence] = await Promise.all([
    readFile(new URL("../src/server.js", import.meta.url), "utf8"),
    readFile(new URL("../src/roadmap.js", import.meta.url), "utf8"),
    readFile(new URL("../src/evidence.js", import.meta.url), "utf8"),
  ]);
  for (const name of [
    "docker_stats",
    "docker_health",
    "docker_health_history",
    "zima_boot_diagnostics",
    "backup_inventory",
    "backup_status",
    "zima_apps",
    "zima_app_verify",
  ]) {
    assert.match(server, new RegExp(`registerReadTool\\(\\s*server,\\s*"${name}"`));
  }
  assert.match(server, /registerReadTool\(server, "server_info"/);
  assert.match(server, /registerReadTool\(server, "docker_info"/);
  assert.match(server, /liveTools:\s*34/);
  assert.match(evidence, /zimaBootDiagnostics = \(\) => networkCollectorGet\("boot-errors"\)/);
  assert.doesNotMatch(roadmap, /node:child_process|execFile|spawn/);
});

test("application and backup path checks stay behind the fixed storage collector", async () => {
  const roadmap = await readFile(new URL("../src/roadmap.js", import.meta.url), "utf8");
  assert.match(roadmap, /storageGet\("paths"/);
  assert.match(roadmap, /storageGet\("backups"\)/);
  assert.match(roadmap, /value === "\/DATA"/);
  assert.match(roadmap, /value === "\/media"/);
});

test("container health history has a bounded memory fallback", async () => {
  const roadmap = await readFile(new URL("../src/roadmap.js", import.meta.url), "utf8");
  assert.match(roadmap, /const memoryHistory = \[\]/);
  assert.match(roadmap, /maximumSnapshots: 200/);
  assert.match(roadmap, /historyPersistence = "memory"/);
  assert.match(roadmap, /memoryHistory\.splice/);
});
