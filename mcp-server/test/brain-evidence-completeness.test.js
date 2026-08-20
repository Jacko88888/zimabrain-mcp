import assert from "node:assert/strict";
import test from "node:test";

import {
  buildContainerSecurityResult,
  buildSystemMetricsResult,
  classify,
} from "../src/brain.js";

test("Dario's questions use dedicated evidence routes", () => {
  assert.equal(
    classify("What is the current CPU usage, memory usage, uptime and system timezone of my ZimaOS?"),
    "system_metrics",
  );
  assert.equal(
    classify("Which containers have elevated privileges or Docker socket access?"),
    "container_security",
  );
});

test("system metrics are verified only when every requested field is captured", () => {
  const complete = buildSystemMetricsResult(
    "What is the current CPU usage, memory usage, uptime and system timezone of my ZimaOS?",
    {
      cpuUsagePercent: 12.5,
      memoryUsagePercent: 40,
      usedMemoryBytes: 4 * 1024 ** 3,
      totalMemoryBytes: 10 * 1024 ** 3,
      uptimeSeconds: 90061,
      timezone: "Europe/Berlin",
      swapTotalBytes: 0,
      swapUsedBytes: 0,
      coverage: { cpuUsage: true, memory: true, uptime: true, timezone: true },
    },
  );
  assert.equal(complete.verification, "VERIFIED");
  assert.match(complete.answer, /CPU usage: 12\.5%/);
  assert.match(complete.answer, /System timezone: Europe\/Berlin/);

  const incomplete = buildSystemMetricsResult(
    "What is the current CPU usage, memory usage, uptime and system timezone of my ZimaOS?",
    {
      timezone: "Europe/Berlin",
      coverage: { cpuUsage: false, memory: false, uptime: false, timezone: true },
    },
  );
  assert.equal(incomplete.verification, "PARTIALLY VERIFIED");
  assert.deepEqual(incomplete.evidence.missing, ["cpuUsage", "memory", "uptime"]);
});

test("zero Docker inspections is evidence absence, never a zero-risk result", () => {
  const unavailable = buildContainerSecurityResult({
    observedContainers: 23,
    inspectedContainers: 0,
    failedInspections: 23,
    complete: false,
  });
  assert.equal(unavailable.verification, "NOT VERIFIED");
  assert.match(unavailable.answer, /0 of 23/);
  assert.match(unavailable.answer, /No zero-risk conclusion/);

  const complete = buildContainerSecurityResult({
    observedContainers: 3,
    inspectedContainers: 3,
    failedInspections: 0,
    complete: true,
    privileged: ["example-privileged"],
    dockerSocket: ["example-socket"],
    hostPid: [],
    hostNetwork: [],
  });
  assert.equal(complete.verification, "PARTIALLY VERIFIED");
  assert.match(complete.answer, /example-privileged/);
  assert.match(complete.answer, /example-socket/);
});
