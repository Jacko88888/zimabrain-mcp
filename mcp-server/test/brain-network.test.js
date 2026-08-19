import assert from "node:assert/strict";
import test from "node:test";
import { buildNetworkExposureResult } from "../src/brain.js";

function fixture(overrides = {}) {
  return {
    scan: {
      externalReachabilityMeasured: false,
      findings: [
        { code: "lan_listeners_observed", severity: "informational", verified: true },
        { code: "external_reachability_unverified", severity: "unknown", verified: false },
      ],
    },
    ports: {
      externalReachabilityMeasured: false,
      listeners: [
        { port: 8621, protocol: "tcp", process: "docker-proxy", address: "0.0.0.0", scope: "all_interfaces" },
        { port: 8790, protocol: "tcp", process: "docker-proxy", address: "127.0.0.1", scope: "localhost" },
      ],
    },
    firewall: {
      state: "service_only",
      serviceRunning: true,
      active: false,
      savedRules: 0,
    },
    containers: [
      {
        name: "zimabrain-mcp-ui",
        ports: [{ private: 3000, public: 8621, type: "tcp", ip: "0.0.0.0" }],
      },
      {
        name: "zimabrain-mcp",
        ports: [{ private: 8718, public: 8790, type: "tcp", ip: "127.0.0.1" }],
      },
      { name: "tailscale", ports: [] },
    ],
    applications: {
      items: [{
        containers: [{
          name: "zimabrain-mcp-ui",
          mounts: [{ source: "/DATA/AppData/zimabrain-mcp", destination: "/app", readWrite: true }],
        }],
      }],
    },
    interfaces: { interfaces: [{ name: "eth0", addresses: [{ address: "192.0.2.10" }] }] },
    ...overrides,
  };
}

test("network answer distinguishes listening binds from measured LAN reachability", () => {
  const answer = buildNetworkExposureResult(fixture());

  assert.equal(answer.verification, "PARTIALLY VERIFIED");
  assert.match(answer.answer, /^1 unique port\/service combination\(s\) are listening/);
  assert.match(answer.answer, /may be accessible from the LAN/i);
  assert.match(answer.answer, /no LAN connection probe was performed/i);
  assert.match(answer.answer, /Internet exposure was not measured/i);
  assert.doesNotMatch(answer.answer, /LAN-reachable listening socket\(s\) were verified/i);
  assert.equal(answer.evidence.uniquePotentialListeners.length, 1);
  assert.equal(answer.evidence.publishedDockerPorts.length, 2);
  assert.deepEqual(answer.evidence.remoteAccessContainers, ["tailscale"]);
});

test("service_only is described as a running service without verified enforcement", () => {
  const answer = buildNetworkExposureResult(fixture());

  assert.match(answer.answer, /ZFW service is running/i);
  assert.match(answer.answer, /no active ZFW hooks or saved enabled rules were observed/i);
  assert.doesNotMatch(answer.answer, /ZFW (?:is|appears) active/i);
  assert.equal(answer.evidence.firewall.state, "service_only");
});

test("active firewall wording requires both active state and active evidence", () => {
  const answer = buildNetworkExposureResult(fixture({
    firewall: { state: "active", serviceRunning: true, active: true, savedRules: 3 },
  }));

  assert.match(answer.answer, /Active ZFW firewall hooks were verified/i);
});

test("network answer records every evidence source used by the claim", () => {
  const answer = buildNetworkExposureResult(fixture());

  assert.deepEqual(answer.sources, [
    "network_open_ports",
    "zima_firewall_status",
    "docker_ps",
    "zima_apps",
    "network_interfaces",
    "zima_security_scan",
  ]);
  assert.deepEqual(answer.evidence.claimChecks, {
    socketBindObserved: true,
    lanConnectionProbePerformed: false,
    internetReachabilityMeasured: false,
    firewallStateVerified: true,
    dockerPublishedPortsCollected: true,
    applicationMountEvidenceCollected: true,
  });
});
