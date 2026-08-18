import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { systemEvidenceSummary } from "../src/evidence-health.js";

function payloads() {
  return new Map([
    ["/sensors", { collectorStatus: "success", verified: true }],
    ["/failed-services", { collectorStatus: "success", verified: true }],
    ["/journal-errors", { collectorStatus: "success", verified: true }],
    ["/rauc", { collectorStatus: "success", verified: true, updateStateVerified: true }],
  ]);
}

test("system evidence summary records all four verified tool results", () => {
  assert.deepEqual(systemEvidenceSummary(payloads()), {
    allVerified: true,
    results: {
      "/sensors": true,
      "/failed-services": true,
      "/journal-errors": true,
      "/rauc": true,
    },
  });
});

test("system evidence summary reports partial RAUC evidence without gating service health", () => {
  const value = payloads();
  value.get("/rauc").updateStateVerified = false;
  assert.equal(systemEvidenceSummary(value).allVerified, false);
  assert.equal(systemEvidenceSummary(value).results["/rauc"], false);
});



test("socket startup preserves least privilege on the private shared tmpfs", async () => {
  const source = await readFile(new URL("../src/server.js", import.meta.url), "utf8");
  assert.match(source, /chmod\(SOCKET_PATH, 0o660\)/);
  assert.doesNotMatch(source, /chown|setfacl|0o666|0o777/);
});
