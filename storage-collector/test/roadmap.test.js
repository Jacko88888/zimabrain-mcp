import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { backupInventory, verifyApprovedPaths } from "../src/roadmap.js";

test("backup inventory remains bounded and does not claim success without archive evidence", async () => {
  const value = await backupInventory();
  assert.equal(value.verifiedInventory, true);
  assert.equal(value.successfulBackupTimeVerified, false);
  assert.equal(value.integrityVerified, false);
  assert.equal(value.restoreTestVerified, false);
  assert.equal(value.maximumDirectories, 1500);
});

test("approved path verifier rejects paths outside DATA and media", async () => {
  const value = await verifyApprovedPaths(["/etc/shadow"]);
  assert.equal(value.items.length, 1);
  assert.equal(value.items[0].exists, false);
  assert.equal(value.items[0].error, "not_verified");
});

test("storage roadmap collector is read-only", async () => {
  const source = await readFile(new URL("../src/roadmap.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /writeFile|appendFile|rename|rm\(|unlink|mkdir/);
});
