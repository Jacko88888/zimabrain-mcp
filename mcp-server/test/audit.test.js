import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("audit writes and reads bounded records without affecting evidence handlers", async () => {
  const directory = await mkdtemp(join(tmpdir(), "zimabrain-audit-"));
  try {
    process.env.AUDIT_PATH = join(directory, "audit.jsonl");
    const audit = await import(`../src/audit.js?test=${Date.now()}`);
    assert.equal(await audit.writeAudit({ tool: "system_sensors", result: "SUCCESS" }), true);
    assert.deepEqual((await audit.readAudit(1)).map(({ tool, result }) => ({ tool, result })), [
      { tool: "system_sensors", result: "SUCCESS" },
    ]);
  } finally {
    delete process.env.AUDIT_PATH;
    await rm(directory, { recursive: true, force: true });
  }
});
