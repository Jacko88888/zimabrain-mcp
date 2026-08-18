import { lstat, readFile, readdir, stat } from "node:fs/promises";

const ROOTS = ["/host/DATA/AppData", "/host/media"];
const MAX_DIRECTORIES = 1500;
const MAX_REPOSITORIES = 40;
const CANDIDATE = /(borg|backup|repository|repo|archive|snapshot)/i;

function publicPath(value) {
  return value.replace(/^\/host/, "") || "/";
}

function approvedHostPath(value) {
  const normalized = String(value ?? "").replace(/\/+$/, "");
  if (normalized === "/DATA" || normalized.startsWith("/DATA/")) return `/host${normalized}`;
  if (normalized === "/media" || normalized.startsWith("/media/")) return `/host${normalized}`;
  throw new Error("Path is outside the approved storage roots");
}

async function directoryEntries(path) {
  return readdir(path, { withFileTypes: true }).catch(() => []);
}

async function borgRepository(path, names) {
  if (!names.has("config")) return null;
  const config = await readFile(`${path}/config`, "utf8").catch(() => "");
  if (!/^\[repository\]/m.test(config)) return null;
  const metadata = [];
  for (const name of [...names].filter((value) => value === "config" || /^(?:index|hints|integrity)\./.test(value)).slice(0, 100)) {
    const item = await stat(`${path}/${name}`).catch(() => null);
    if (item) metadata.push(item.mtimeMs);
  }
  const latestMetadataMs = metadata.length ? Math.max(...metadata) : null;
  return {
    type: "borg",
    path: publicPath(path),
    readable: true,
    latestRepositoryActivity: latestMetadataMs ? new Date(latestMetadataMs).toISOString() : null,
    latestSuccessfulBackup: null,
    archiveCount: null,
    archiveListVerified: false,
    integrityCheckVerified: false,
    restoreTestVerified: false,
    encryptedRepositoryMayRequireCredentials: /encryption/.test(config),
  };
}

export async function backupInventory() {
  const queue = ROOTS.map((path) => ({ path, depth: 0, candidate: false }));
  const repositories = [];
  let observedDirectories = 0;
  let bounded = false;

  while (queue.length && observedDirectories < MAX_DIRECTORIES && repositories.length < MAX_REPOSITORIES) {
    const current = queue.shift();
    const entries = await directoryEntries(current.path);
    observedDirectories += 1;
    const names = new Set(entries.map((entry) => entry.name));
    const repository = await borgRepository(current.path, names);
    if (repository) repositories.push(repository);

    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name.startsWith(".") || ["node_modules", "lost+found"].includes(entry.name)) continue;
      const candidate = current.candidate || CANDIDATE.test(entry.name);
      const nextDepth = current.depth + 1;
      if (nextDepth <= 2 || (candidate && nextDepth <= 5)) {
        queue.push({ path: `${current.path}/${entry.name}`, depth: nextDepth, candidate });
      }
    }
  }
  if (queue.length) bounded = true;

  const latestActivity = repositories
    .map((item) => item.latestRepositoryActivity)
    .filter(Boolean)
    .sort()
    .at(-1) ?? null;

  return {
    verifiedInventory: true,
    roots: ROOTS.map(publicPath),
    observedDirectories,
    repositories: repositories.length,
    latestRepositoryActivity: latestActivity,
    latestSuccessfulBackup: null,
    successfulBackupTimeVerified: false,
    scheduleVerified: false,
    integrityVerified: false,
    restoreTestVerified: false,
    bounded,
    maximumDirectories: MAX_DIRECTORIES,
    maximumRepositories: MAX_REPOSITORIES,
    items: repositories,
    note: repositories.length
      ? "Borg repository structures were observed. Repository activity is not proof of a successful backup, integrity check or restore test."
      : "No Borg repository structure was found inside the bounded approved roots.",
  };
}

export async function verifyApprovedPaths(paths) {
  const unique = [...new Set((paths ?? []).map(String))].slice(0, 100);
  const items = [];
  for (const value of unique) {
    try {
      const host = approvedHostPath(value);
      const info = await lstat(host);
      items.push({
        path: value,
        exists: true,
        type: info.isDirectory() ? "directory" : info.isFile() ? "file" : "other",
        mode: (info.mode & 0o777).toString(8),
        modifiedAt: info.mtime.toISOString(),
      });
    } catch (error) {
      items.push({
        path: value,
        exists: false,
        type: null,
        error: error?.code === "ENOENT" ? "not_found" : "not_verified",
      });
    }
  }
  return { verified: true, bounded: true, maximumPaths: 100, items };
}
