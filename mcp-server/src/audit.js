import { appendFile, mkdir, readFile } from "node:fs/promises";

const auditPath = process.env.AUDIT_PATH ?? "/data/audit.jsonl";
const unavailableCodes = new Set(["EACCES", "EPERM", "EROFS"]);

export async function writeAudit(entry) {
  try {
    await mkdir(new URL(".", `file://${auditPath}`).pathname, { recursive: true });
    const record = { timestamp: new Date().toISOString(), ...entry };
    await appendFile(auditPath, `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600 });
    return true;
  } catch (error) {
    if (unavailableCodes.has(error?.code)) return false;
    throw error;
  }
}

export async function readAudit(limit = 20) {
  try {
    const text = await readFile(auditPath, "utf8");
    return text
      .trim()
      .split("\n")
      .filter(Boolean)
      .slice(-limit)
      .reverse()
      .map((line) => JSON.parse(line));
  } catch (error) {
    if (error?.code === "ENOENT" || unavailableCodes.has(error?.code)) return [];
    throw error;
  }
}
