import assert from "node:assert/strict";
import test from "node:test";
import { classifyBind, firewallChainPresent, parseListeningSockets, parsePing, parseResolver } from "../src/parsers.js";

test("resolver parsing keeps valid nameservers and search domains", () => {
  assert.deepEqual(parseResolver("search lan\nnameserver 192.168.1.1\nnameserver fd00::1\n"), {
    nameservers: ["192.168.1.1", "fd00::1"],
    search: ["lan"],
  });
});

test("ping parsing returns bounded packet and timing evidence", () => {
  const value = parsePing("3 packets transmitted, 3 packets received, 0% packet loss\nround-trip min/avg/max = 0.800/1.200/1.900 ms");
  assert.equal(value.received, 3);
  assert.equal(value.packetLossPercent, 0);
  assert.equal(value.averageMs, 1.2);
});

test("socket parsing classifies LAN without claiming internet exposure", () => {
  const rows = parseListeningSockets(
    'tcp LISTEN 0 128 0.0.0.0:8621 0.0.0.0:* users:(("node",pid=42,fd=8))\ntcp LISTEN 0 128 127.0.0.1:8489 0.0.0.0:* users:(("zfwd",pid=9,fd=8))',
    { eth0: ["192.168.1.100"] },
  );
  assert.equal(rows[0].scope, "localhost");
  assert.equal(rows[1].scope, "all_interfaces");
  assert.equal(rows[1].internetReachability, "not_verified");
});

test("bind classification distinguishes overlay and bridge addresses", () => {
  const addresses = { tailscale0: ["100.64.1.2"], docker0: ["172.17.0.1"], eth0: ["192.168.1.100"] };
  assert.equal(classifyBind("100.64.1.2", addresses), "overlay");
  assert.equal(classifyBind("172.17.0.1", addresses), "container_bridge");
  assert.equal(classifyBind("192.168.1.100", addresses), "lan");
});

test("firewall requires both a chain and its hook", () => {
  assert.equal(firewallChainPresent(":ZFW-IN - [0:0]\n-A INPUT -j ZFW-IN\n", "ZFW-IN", "INPUT"), true);
  assert.equal(firewallChainPresent(":ZFW-IN - [0:0]\n", "ZFW-IN", "INPUT"), false);
});
