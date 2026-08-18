import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parseFailedUnits, parseJournalJsonLines, parseRaucProperties } from "../src/system.js";

test("failed-unit parser returns only units whose active state is failed", () => {
  const value = `
    array [
      struct {
        string "example.service"
        string "Example service"
        string "loaded"
        string "failed"
        string "failed"
        string ""
        object path "/org/freedesktop/systemd1/unit/example_2eservice"
      }
      struct {
        string "healthy.service"
        string "Healthy service"
        string "loaded"
        string "active"
        string "running"
      }
    ]`;
  assert.deepEqual(parseFailedUnits(value), [{
    unit: "example.service",
    description: "Example service",
    loadState: "loaded",
    activeState: "failed",
    subState: "failed",
  }]);
});

test("RAUC property parser keeps bounded scalar evidence", () => {
  const value = `
    dict entry(
      string "Operation"
      variant string "idle"
    )
    dict entry(
      string "BootSlot"
      variant string "system.a"
    )
    dict entry(
      string "Progress"
      variant uint32 100
    )`;
  assert.deepEqual(parseRaucProperties(value), { Operation: "idle", BootSlot: "system.a", Progress: 100 });
});

test("journal parser keeps only error priorities and redacts secrets", () => {
  const value = [
    JSON.stringify({
      PRIORITY: "3",
      __REALTIME_TIMESTAMP: "1786850000000000",
      _SYSTEMD_UNIT: "example.service",
      SYSLOG_IDENTIFIER: "example",
      _PID: "42",
      _TRANSPORT: "journal",
      MESSAGE: "request failed token=very-secret",
    }),
    JSON.stringify({ PRIORITY: "6", MESSAGE: "informational" }),
  ].join("\n");
  const items = parseJournalJsonLines(value, "persistent");
  assert.equal(items.length, 1);
  assert.equal(items[0].priority, 3);
  assert.equal(items[0].unit, "example.service");
  assert.match(items[0].message, /token=\[REDACTED\]/);
  assert.doesNotMatch(items[0].message, /very-secret/);
});

test("network collector socket uses a private setgid tmpfs shared with the MCP identity", async () => {
  const [source, compose] = await Promise.all([
    readFile(new URL("../src/server.js", import.meta.url), "utf8"),
    readFile(new URL("../../compose.zb2-v0.10.yaml", import.meta.url), "utf8"),
  ]);
  assert.match(source, /chmod\(SOCKET_PATH, 0o660\)/);
  assert.doesNotMatch(source, /chown|setfacl|0o666|0o777/);
  assert.match(compose, /source: network-run/);
  assert.match(compose, /type: tmpfs/);
  assert.match(compose, /uid=0,gid=1000,mode=2770,size=16m/);
});
