import test from "node:test";
import assert from "node:assert/strict";

import { buildComprehensiveHealthResult } from "../src/brain.js";


test("comprehensive health remains partial when reachability and NVMe health are unverified", () => {
  const result = buildComprehensiveHealthResult({
    health: {
      items: [{ name: "app", state: "running", health: "healthy" }],
    },
    failed: {
      state: "clear",
      observedFailedServices: 0,
      services: [],
    },
    dashboard: {
      findings: [{
        state: "attention",
        name: "no_critical_exposure",
        source: "zima_firewall_status",
        result: "ZFW has saved rules but is not applied; external reachability remains unverified",
      }],
    },
    containers: [{ name: "app", state: "running", ports: [] }],
    storage: { observedDisks: 1, disks: [{ name: "sda" }] },
    smart: { devices: [{ device: "/dev/sda", status: "healthy" }] },
    nvme: {
      devices: [{ device: "/dev/nvme0", status: "unknown", healthVerified: false }],
    },
    raid: { status: "not_applicable" },
    firewall: { state: "configured_not_applied", active: false },
    ports: { listeners: [], lanReachabilityMeasured: false },
    interfaces: { interfaces: [{ name: "eth0" }] },
    scan: { externalReachabilityMeasured: false, findings: [] },
  });

  assert.equal(result.intent, "comprehensive_health");
  assert.equal(result.verification, "PARTIALLY VERIFIED");
  assert.match(result.answer, /saved rules but is not applied/i);
  assert.equal(result.evidence.failedServices.state, "clear");
  assert.equal(result.evidence.coverage.lanConnectionProbePerformed, false);
});


test("clear failed-service evidence does not create a failed-unit message", () => {
  const result = buildComprehensiveHealthResult({
    health: { items: [] },
    failed: { state: "clear", observedFailedServices: 0, services: [] },
    dashboard: { findings: [] },
    smart: { devices: [] },
    nvme: { devices: [] },
    firewall: { state: "active", active: true },
    ports: { listeners: [], lanReachabilityMeasured: true },
    scan: { externalReachabilityMeasured: true, findings: [] },
  });

  assert.doesNotMatch(result.answer, /service is failed/i);
});
