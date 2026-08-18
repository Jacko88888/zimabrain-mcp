import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("network adapter exposes only fixed Unix-socket endpoints", async () => {
  const source = await readFile(new URL("../src/evidence.js", import.meta.url), "utf8");
  assert.match(source, /socketPath:\s*NETWORK_COLLECTOR_SOCKET/);
  assert.match(source, /new Set\(\["interfaces", "routes", "dns", "ping", "ports", "firewall", "security", "sensors", "failed-services", "journal-errors", "boot-errors", "rauc"\]\)/);
  assert.match(source, /networkDns = \(domain\) => networkCollectorGet\("dns", \{ domain \}\)/);
  assert.match(source, /networkPing = \(target, count\) => networkCollectorGet\("ping", \{ target, count \}\)/);
  assert.doesNotMatch(source, /NETWORK_COLLECTOR_URL/);
});
