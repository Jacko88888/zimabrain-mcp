import assert from "node:assert/strict";
import test from "node:test";
import { classifyBootCause, parseBootJournalLines } from "../src/boot.js";

test("boot diagnostics classify critical root causes", () => {
  assert.equal(classifyBootCause("Out of memory: Killed process 42"), "memory_oom");
  assert.equal(classifyBootCause("nvme0: I/O error while reading"), "storage_io");
  assert.equal(classifyBootCause("BTRFS error: parent transid verify failed"), "filesystem");
  assert.equal(classifyBootCause("kernel panic - not syncing"), "kernel_fault");
  assert.equal(classifyBootCause("Failed to start service", "demo.service"), "service");
});

test("boot journal parser is bounded to warnings and redacts credentials", () => {
  const output = [
    JSON.stringify({
      PRIORITY: "3",
      __REALTIME_TIMESTAMP: "1786850000000000",
      _BOOT_ID: "boot1",
      _SYSTEMD_UNIT: "demo.service",
      _TRANSPORT: "journal",
      MESSAGE: "authentication failed token=very-secret",
    }),
    JSON.stringify({ PRIORITY: "6", MESSAGE: "informational" }),
  ].join("\n");
  const items = parseBootJournalLines(output, "persistent");
  assert.equal(items.length, 1);
  assert.equal(items[0].cause, "security");
  assert.match(items[0].message, /token=\[REDACTED\]/);
  assert.doesNotMatch(items[0].message, /very-secret/);
});
