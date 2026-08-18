import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const PERSISTENT_JOURNAL = process.env.PERSISTENT_JOURNAL ?? "/host/var/log/journal";
const RUNTIME_JOURNAL = process.env.RUNTIME_JOURNAL ?? "/host/run/log/journal";
const MAX_BOOT_LINES = 200;

async function journal(args) {
  try {
    const { stdout } = await execFileAsync("journalctl", args, {
      timeout: 15000,
      maxBuffer: 4 * 1024 * 1024,
      encoding: "utf8",
    });
    return { ok: true, stdout };
  } catch (error) {
    return { ok: false, stdout: String(error?.stdout ?? "") };
  }
}

function redact(value) {
  return String(value ?? "")
    .replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/(bearer\s+)[A-Za-z0-9._~+\/-]+=*/gi, "$1[REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED_JWT]")
    .replace(/(https?:\/\/[^\s:/@]+:)[^\s@]+@/gi, "$1[REDACTED]@")
    .replace(/\b(password|passwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization|cookie)(\s*[:=]\s*)([^\s,;]+)/gi, "$1$2[REDACTED]")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .slice(0, 2000);
}

export function classifyBootCause(message, unit = "") {
  const value = `${unit} ${message}`.toLowerCase();
  if (/kernel panic|oops:|general protection fault|watchdog.*lockup|segfault/.test(value)) return "kernel_fault";
  if (/out of memory|oom-kill|killed process .*memory/.test(value)) return "memory_oom";
  if (/i\/o error|ata.*error|nvme.*error|medium error|uncorrectable|reset.*link|blk_update_request/.test(value)) return "storage_io";
  if (/btrfs.*error|ext4-fs error|xfs.*corrupt|filesystem.*error|read-only file system/.test(value)) return "filesystem";
  if (/failed to mount|mount.*failed|dependency failed.*mount/.test(value)) return "mount";
  if (/network.*unreachable|link is down|dns.*fail|dhcp.*fail|connection timed out/.test(value)) return "network";
  if (/permission denied|authentication fail|unauthorized|certificate.*error/.test(value)) return "security";
  if (/failed|failure|error/.test(value) && /\.service|systemd|unit/.test(value)) return "service";
  return "other";
}

export function parseBootJournalLines(output, source, kernelOnly = false) {
  const items = [];
  for (const line of String(output ?? "").split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      const priority = Number.parseInt(String(entry.PRIORITY ?? ""), 10);
      if (!Number.isInteger(priority) || priority < 0 || priority > 4) continue;
      const message = redact(entry.MESSAGE ?? "");
      const unit = String(entry._SYSTEMD_UNIT ?? "").slice(0, 256) || null;
      const transport = String(entry._TRANSPORT ?? "").slice(0, 64) || null;
      const kernel = kernelOnly || transport === "kernel" || entry._KERNEL_SUBSYSTEM !== undefined;
      items.push({
        source,
        priority,
        timestamp: /^\d+$/.test(String(entry.__REALTIME_TIMESTAMP ?? ""))
          ? new Date(Number(entry.__REALTIME_TIMESTAMP) / 1000).toISOString()
          : null,
        bootId: String(entry._BOOT_ID ?? "").slice(0, 64) || null,
        unit,
        identifier: String(entry.SYSLOG_IDENTIFIER ?? entry._COMM ?? "").slice(0, 128) || null,
        transport,
        kernel,
        cause: classifyBootCause(message, unit ?? ""),
        message,
      });
    } catch {
      // Malformed journal output is ignored.
    }
  }
  return items;
}

export async function zimaBootDiagnostics() {
  const readableSources = [];
  const collected = [];
  for (const [source, directory] of [["persistent", PERSISTENT_JOURNAL], ["runtime", RUNTIME_JOURNAL]]) {
    const common = [
      `--directory=${directory}`,
      "--boot=0",
      "--priority=0..4",
      `--lines=${MAX_BOOT_LINES}`,
      "--output=json",
      "--no-pager",
    ];
    const [all, kernel] = await Promise.all([
      journal(common),
      journal([...common, "--dmesg"]),
    ]);
    if (all.ok) {
      readableSources.push(source);
      collected.push(...parseBootJournalLines(all.stdout, source, false));
    }
    if (kernel.ok) collected.push(...parseBootJournalLines(kernel.stdout, source, true));
  }

  const unique = [...new Map(collected.map((item) => [
    `${item.bootId}:${item.timestamp}:${item.unit}:${item.message}`,
    item,
  ])).values()].slice(-MAX_BOOT_LINES);
  const causeCounts = {};
  for (const item of unique) causeCounts[item.cause] = (causeCounts[item.cause] ?? 0) + 1;
  const critical = unique.filter((item) => item.priority <= 2 || ["kernel_fault", "memory_oom", "storage_io", "filesystem"].includes(item.cause));

  return {
    generatedAt: new Date().toISOString(),
    verified: readableSources.length > 0,
    state: readableSources.length ? (critical.length ? "attention" : "bounded_clear") : "not_verified",
    currentBootOnly: true,
    readableSources: [...new Set(readableSources)],
    observedLines: unique.length,
    criticalFindings: critical.length,
    kernelLines: unique.filter((item) => item.kernel).length,
    causeCounts,
    bounded: true,
    maximumReturnedLines: MAX_BOOT_LINES,
    redacted: true,
    items: unique,
    note: readableSources.length
      ? "Current-boot warning-to-emergency entries were classified from fixed host journal directories."
      : "Current-boot journal evidence could not be read; no boot-health claim is made.",
  };
}
