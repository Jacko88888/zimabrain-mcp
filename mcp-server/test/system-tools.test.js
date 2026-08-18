import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("System and ZimaOS tools use only fixed collector endpoints", async () => {
  const [server, evidence] = await Promise.all([
    readFile(new URL("../src/server.js", import.meta.url), "utf8"),
    readFile(new URL("../src/evidence.js", import.meta.url), "utf8"),
  ]);
  for (const name of ["system_sensors", "zima_failed_services", "zima_journal_errors", "zima_rauc_status"]) {
    assert.match(server, new RegExp(`registerReadTool\\(server, "${name}"`));
  }
  assert.match(evidence, /systemSensors = \(\) => networkCollectorGet\("sensors"\)/);
  assert.match(evidence, /zimaFailedServices = \(\) => networkCollectorGet\("failed-services"\)/);
  assert.match(evidence, /zimaJournalErrors = \(\) => networkCollectorGet\("journal-errors"\)/);
  assert.match(evidence, /zimaRaucStatus = \(\) => networkCollectorGet\("rauc"\)/);
  assert.doesNotMatch(evidence, /execFile|spawn|systemctl|journalctl|rauc\s+status/);
  assert.match(server, /liveTools:\s*34/);
});

test("Compose exposes only the exact approved read-only System and ZimaOS evidence", async () => {
  const compose = await readFile(new URL("../../compose.zb2-v0.10.yaml", import.meta.url), "utf8");
  assert.match(compose, /\/run\/dbus\/system_bus_socket:\/run\/dbus\/system_bus_socket:ro/);
  assert.match(compose, /\/etc\/rauc\/system\.conf:\/host\/etc\/rauc\/system\.conf:ro/);
  assert.match(compose, /\/run\/log\/journal:\/host\/run\/log\/journal:ro/);
  assert.match(compose, /\/var\/log\/journal:\/host\/var\/log\/journal:ro/);
  assert.doesNotMatch(compose, /- \/run\/dbus:\/run\/dbus/);
});
