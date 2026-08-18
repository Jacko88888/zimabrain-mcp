import { execFile } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const HOST_PROC = process.env.HOST_PROC ?? "/host/proc";
const HOST_SYS = process.env.HOST_SYS ?? "/host/sys";
const RAUC_SYSTEM_CONF = process.env.RAUC_SYSTEM_CONF ?? "/host/etc/rauc/system.conf";
const SYSTEM_BUS_SOCKET = process.env.SYSTEM_BUS_SOCKET ?? "/run/dbus/system_bus_socket";
const PERSISTENT_JOURNAL = process.env.PERSISTENT_JOURNAL ?? "/host/var/log/journal";
const RUNTIME_JOURNAL = process.env.RUNTIME_JOURNAL ?? "/host/run/log/journal";
const MAX_SENSOR_ENTRIES = 256;
const MAX_ERROR_LINES = 200;

async function fixedCommand(file, args, timeout = 8000) {
  try {
    const { stdout, stderr } = await execFileAsync(file, args, {
      timeout,
      maxBuffer: 4 * 1024 * 1024,
      env: {
        ...process.env,
        DBUS_SYSTEM_BUS_ADDRESS: `unix:path=${SYSTEM_BUS_SOCKET}`,
      },
    });
    return { ok: true, stdout, stderr, exitCode: 0 };
  } catch (error) {
    return {
      ok: false,
      stdout: String(error?.stdout ?? ""),
      stderr: String(error?.stderr ?? error?.message ?? "command failed").slice(0, 500),
      exitCode: Number.isInteger(error?.code) ? error.code : null,
    };
  }
}

async function text(path, maximum = 4096) {
  const value = await readFile(path, "utf8");
  return value.slice(0, maximum).trim();
}

function temperatureCelsius(raw) {
  const numeric = Number.parseFloat(String(raw ?? "").trim());
  if (!Number.isFinite(numeric)) return null;
  const celsius = Math.abs(numeric) > 500 ? numeric / 1000 : numeric;
  if (celsius < -100 || celsius > 250) return null;
  return Number(celsius.toFixed(1));
}

export async function systemSensors() {
  const sensors = [];
  const thermalRoot = `${HOST_SYS}/class/thermal`;
  const thermalEntries = await readdir(thermalRoot, { withFileTypes: true }).catch(() => []);
  for (const entry of thermalEntries) {
    if (sensors.length >= MAX_SENSOR_ENTRIES || !entry.isDirectory() || !/^thermal_zone\d+$/.test(entry.name)) continue;
    const root = `${thermalRoot}/${entry.name}`;
    const [kind, raw] = await Promise.all([
      text(`${root}/type`).catch(() => entry.name),
      text(`${root}/temp`).catch(() => ""),
    ]);
    const celsius = temperatureCelsius(raw);
    if (celsius !== null) sensors.push({ source: "thermal", device: entry.name, label: kind, celsius });
  }

  const hwmonRoot = `${HOST_SYS}/class/hwmon`;
  const hwmonEntries = await readdir(hwmonRoot, { withFileTypes: true }).catch(() => []);
  for (const entry of hwmonEntries) {
    if (sensors.length >= MAX_SENSOR_ENTRIES || !entry.isDirectory() || !/^hwmon\d+$/.test(entry.name)) continue;
    const root = `${hwmonRoot}/${entry.name}`;
    const device = await text(`${root}/name`).catch(() => entry.name);
    const files = await readdir(root).catch(() => []);
    for (const file of files.filter((name) => /^temp\d+_input$/.test(name)).sort()) {
      if (sensors.length >= MAX_SENSOR_ENTRIES) break;
      const index = file.match(/^temp(\d+)_input$/)?.[1];
      const [raw, label] = await Promise.all([
        text(`${root}/${file}`).catch(() => ""),
        text(`${root}/temp${index}_label`).catch(() => `temp${index}`),
      ]);
      const celsius = temperatureCelsius(raw);
      if (celsius !== null) sensors.push({ source: "hwmon", device, label, celsius });
    }
  }

  const unique = [...new Map(sensors.map((item) => [`${item.source}:${item.device}:${item.label}`, item])).values()];
  return {
    generatedAt: new Date().toISOString(),
    verified: unique.length > 0,
    observedSensors: unique.length,
    bounded: true,
    maximumEntries: MAX_SENSOR_ENTRIES,
    sensors: unique,
    note: unique.length ? "Temperatures were read from host sysfs." : "No readable host thermal or hwmon temperature evidence was observed.",
  };
}

export function parseFailedUnits(output) {
  const units = [];
  const blocks = String(output ?? "").match(/struct\s*\{[\s\S]*?\n\s*\}/g) ?? [];
  for (const block of blocks) {
    const strings = [...block.matchAll(/string\s+"((?:[^"\\]|\\.)*)"/g)].map((match) => match[1].replace(/\\"/g, '"'));
    if (strings.length < 5 || strings[3] !== "failed") continue;
    units.push({
      unit: strings[0],
      description: strings[1],
      loadState: strings[2],
      activeState: strings[3],
      subState: strings[4],
    });
  }
  return units.slice(0, 200);
}

export async function zimaFailedServices() {
  const result = await fixedCommand("dbus-send", [
    "--system",
    "--print-reply",
    "--dest=org.freedesktop.systemd1",
    "/org/freedesktop/systemd1",
    "org.freedesktop.systemd1.Manager.ListUnitsFiltered",
    "array:string:failed",
  ]);
  if (!result.ok) {
    return {
      generatedAt: new Date().toISOString(),
      verified: false,
      state: "not_verified",
      observedFailedServices: null,
      services: [],
      note: "The host systemd manager could not be queried through the fixed read-only system-bus call; no claim about failed services is made.",
    };
  }
  const services = parseFailedUnits(result.stdout);
  return {
    generatedAt: new Date().toISOString(),
    verified: true,
    state: services.length ? "attention" : "clear",
    observedFailedServices: services.length,
    bounded: true,
    maximumEntries: 200,
    services,
    note: services.length ? "Failed units were reported by the host systemd manager." : "The host systemd manager reported no failed units.",
  };
}

function redactLogLine(line) {
  return String(line ?? "")
    .replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/(bearer\s+)[A-Za-z0-9._~+\/-]+=*/gi, "$1[REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED_JWT]")
    .replace(/(https?:\/\/[^\s:/@]+:)[^\s@]+@/gi, "$1[REDACTED]@")
    .replace(/\b(password|passwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization|cookie)(\s*[:=]\s*)([^\s,;]+)/gi, "$1$2[REDACTED]")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .slice(0, 2000);
}

export function parseJournalJsonLines(output, source) {
  const items = [];
  for (const line of String(output ?? "").split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      const priority = Number.parseInt(String(entry.PRIORITY ?? ""), 10);
      if (!Number.isInteger(priority) || priority < 0 || priority > 3) continue;
      items.push({
        source,
        priority,
        timestamp: /^\d+$/.test(String(entry.__REALTIME_TIMESTAMP ?? ""))
          ? new Date(Number(entry.__REALTIME_TIMESTAMP) / 1000).toISOString()
          : null,
        unit: String(entry._SYSTEMD_UNIT ?? "").slice(0, 256) || null,
        identifier: String(entry.SYSLOG_IDENTIFIER ?? entry._COMM ?? "").slice(0, 128) || null,
        pid: /^\d+$/.test(String(entry._PID ?? "")) ? Number(entry._PID) : null,
        transport: String(entry._TRANSPORT ?? "").slice(0, 64) || null,
        message: redactLogLine(entry.MESSAGE ?? ""),
      });
    } catch {
      // Ignore malformed or non-JSON output without widening the evidence claim.
    }
  }
  return items.slice(-MAX_ERROR_LINES);
}

export async function zimaJournalErrors() {
  const readableSources = [];
  const errors = [];
  for (const [source, directory] of [["persistent", PERSISTENT_JOURNAL], ["runtime", RUNTIME_JOURNAL]]) {
    const result = await fixedCommand("journalctl", [
      `--directory=${directory}`,
      "--priority=0..3",
      `--lines=${MAX_ERROR_LINES}`,
      "--output=json",
      "--no-pager",
    ], 15000);
    if (!result.ok) continue;
    readableSources.push(source);
    errors.push(...parseJournalJsonLines(result.stdout, source));
  }
  const items = errors.slice(-MAX_ERROR_LINES);
  return {
    generatedAt: new Date().toISOString(),
    verified: readableSources.length > 0,
    state: readableSources.length ? (items.length ? "attention" : "bounded_clear") : "not_verified",
    readableSources,
    observedErrorLines: items.length,
    bounded: true,
    maximumReturnedLines: MAX_ERROR_LINES,
    priorities: [0, 1, 2, 3],
    redacted: true,
    items,
    note: readableSources.length
      ? "The last bounded emergency-to-error entries were read from fixed host journal directories."
      : "Neither approved host journal directory could be read; journal error state is not verified.",
  };
}

function parseIni(textValue) {
  const values = {};
  let section = "";
  for (const raw of String(textValue ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sectionMatch = line.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) {
      section = sectionMatch[1];
      continue;
    }
    const separator = line.indexOf("=");
    if (separator < 1) continue;
    values[`${section}.${line.slice(0, separator).trim()}`] = line.slice(separator + 1).trim();
  }
  return values;
}

export function parseRaucProperties(output) {
  const lines = String(output ?? "").split(/\r?\n/).map((line) => line.trim());
  const values = {};
  for (let index = 0; index < lines.length; index += 1) {
    const key = lines[index].match(/^string\s+"([A-Za-z][A-Za-z0-9]*)"$/)?.[1];
    if (!key) continue;
    for (let offset = 1; offset <= 4 && index + offset < lines.length; offset += 1) {
      const valueLine = lines[index + offset];
      const stringValue = valueLine.match(/^(?:variant\s+)?string\s+"(.*)"$/)?.[1];
      if (stringValue !== undefined) {
        values[key] = stringValue;
        break;
      }
      const boolValue = valueLine.match(/^(?:variant\s+)?boolean\s+(true|false)$/)?.[1];
      if (boolValue !== undefined) {
        values[key] = boolValue === "true";
        break;
      }
      const numberValue = valueLine.match(/^(?:variant\s+)?(?:byte|u?int(?:16|32|64)|double)\s+([0-9.]+)$/)?.[1];
      if (numberValue !== undefined) {
        values[key] = Number(numberValue);
        break;
      }
      if (/^string\s+"[A-Za-z]/.test(valueLine)) break;
    }
  }
  return values;
}

export async function zimaRaucStatus() {
  const [cmdline, configText, dbus] = await Promise.all([
    text(`${HOST_PROC}/cmdline`, 16384).catch(() => ""),
    text(RAUC_SYSTEM_CONF, 64 * 1024).catch(() => ""),
    fixedCommand("dbus-send", [
      "--system",
      "--print-reply",
      "--dest=de.pengutronix.rauc",
      "/",
      "org.freedesktop.DBus.Properties.GetAll",
      "string:de.pengutronix.rauc.Installer",
    ]),
  ]);
  const config = parseIni(configText);
  const properties = dbus.ok ? parseRaucProperties(dbus.stdout) : {};
  const bootSlot = cmdline.match(/(?:^|\s)rauc\.slot=([^\s]+)/)?.[1]
    ?? cmdline.match(/(?:^|\s)bootchooser\.active=([^\s]+)/)?.[1]
    ?? properties.BootSlot
    ?? null;
  const operation = properties.Operation ?? null;
  const lastError = properties.LastError ?? null;
  const updateStateVerified = dbus.ok && operation !== null;
  return {
    generatedAt: new Date().toISOString(),
    verified: Boolean(bootSlot || configText || dbus.ok),
    bootSlot,
    bootSlotVerified: Boolean(bootSlot),
    compatible: properties.Compatible ?? config["system.compatible"] ?? null,
    variant: properties.Variant ?? config["system.variant"] ?? null,
    bootloader: config["system.bootloader"] ?? null,
    operation,
    updateStateVerified,
    lastError: lastError || null,
    state: lastError ? "attention" : updateStateVerified ? (operation === "idle" ? "idle" : "busy") : "partially_verified",
    note: updateStateVerified
      ? "RAUC update state was queried through the fixed read-only system-bus call."
      : "RAUC update operation state was not available; only boot/configuration evidence is reported.",
  };
}
