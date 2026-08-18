"""Read-only Docker inventory for the ZimaBrain Snapshot Lab."""

from datetime import datetime, timezone
import hashlib
import html
import json
from urllib.parse import quote


PERSISTENT_SOURCE_ROOTS = (
    "/DATA",
    "/media",
    "/mnt",
    "/var/lib/casaos_data",
)

RUNTIME_DESTINATIONS = (
    "/dev",
    "/proc",
    "/run",
    "/sys",
    "/var/run",
)

DESTINATION_ROOTS = (
    "/DATA",
    "/media",
    "/mnt",
)

NATIVE_DESTINATION_FILESYSTEMS = {
    "btrfs",
    "ext4",
    "xfs",
}

REVIEW_DESTINATION_FILESYSTEMS = {
    "exfat",
    "fuseblk",
    "ntfs",
    "ntfs3",
}

EXCLUDED_DESTINATION_FILESYSTEMS = {
    "iso9660",
    "vfat",
}

SOURCE_SCAN_SCRIPT = r'''import json
import os
import stat
import sys

root = sys.argv[1]
result = {
    "path": root,
    "resolved_path": "",
    "device": "",
    "stat_device": "",
    "mountpoint": "",
    "filesystem": "",
    "mount_source": "",
    "regular_file_bytes": 0,
    "regular_files": 0,
    "directories": 0,
    "symlinks": 0,
    "special_entries": 0,
    "volatile_entries_skipped": 0,
    "volatile_paths": [],
    "mount_boundaries_skipped": 0,
    "error_count": 0,
    "errors": [],
}

def record_error(path, exc):
    result["error_count"] += 1
    if len(result["errors"]) < 50:
        result["errors"].append(f"{path}: {exc}")

def decode_mount_path(value):
    replacements = {
        r"\040": " ",
        r"\011": "\t",
        r"\012": "\n",
        r"\134": "\\",
    }
    for encoded, decoded in replacements.items():
        value = value.replace(encoded, decoded)
    return value

def path_is_under(path, mountpoint):
    clean_path = path.rstrip("/") or "/"
    clean_mount = mountpoint.rstrip("/") or "/"
    if clean_mount == "/":
        return clean_path.startswith("/")
    return clean_path == clean_mount or clean_path.startswith(clean_mount + "/")

def read_mounts():
    rows = []
    with open("/proc/self/mountinfo", "r", encoding="utf-8") as handle:
        for line in handle:
            left, right = line.rstrip("\n").split(" - ", 1)
            fields = left.split()
            filesystem = right.split()
            mountpoint = decode_mount_path(fields[4])
            rows.append({
                "mountpoint": mountpoint.rstrip("/") or "/",
                "device": fields[2],
                "filesystem": filesystem[0] if filesystem else "",
                "source": decode_mount_path(filesystem[1]) if len(filesystem) > 1 else "",
            })
    return rows

def resolve_mount(path):
    matches = [item for item in MOUNTS if path_is_under(path, item["mountpoint"])]
    if not matches:
        return None
    return max(matches, key=lambda item: len(item["mountpoint"]))

try:
    MOUNTS = read_mounts()
except (OSError, ValueError) as exc:
    MOUNTS = []
    record_error("/proc/self/mountinfo", exc)

try:
    root_stat = os.lstat(root)
except OSError as exc:
    record_error(root, exc)
else:
    result["resolved_path"] = os.path.realpath(root)
    try:
        scan_root_stat = os.stat(result["resolved_path"], follow_symlinks=True)
    except OSError as exc:
        scan_root_stat = root_stat
        record_error(result["resolved_path"], exc)
    result["stat_device"] = f"{os.major(scan_root_stat.st_dev)}:{os.minor(scan_root_stat.st_dev)}"
    try:
        mount = resolve_mount(result["resolved_path"])
    except (OSError, ValueError) as exc:
        mount = None
        record_error("/proc/self/mountinfo", exc)

    if mount is None:
        record_error(result["resolved_path"], "no matching host mount was found")
    else:
        result["device"] = mount["device"]
        result["mountpoint"] = mount["mountpoint"]
        result["filesystem"] = mount["filesystem"]
        result["mount_source"] = mount["source"]

    root_device = scan_root_stat.st_dev
    if stat.S_ISREG(scan_root_stat.st_mode):
        result["regular_files"] = 1
        result["regular_file_bytes"] = scan_root_stat.st_size
    elif stat.S_ISDIR(scan_root_stat.st_mode):
        pending = [result["resolved_path"]]
        while pending:
            current = pending.pop()
            result["directories"] += 1
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_symlink():
                                result["symlinks"] += 1
                                continue

                            entry_stat = entry.stat(follow_symlinks=False)
                            entry_mount = resolve_mount(os.path.realpath(entry.path))
                            if entry_mount is None or entry_mount.get("device") != result["device"]:
                                result["mount_boundaries_skipped"] += 1
                            elif stat.S_ISDIR(entry_stat.st_mode):
                                pending.append(entry.path)
                            elif stat.S_ISREG(entry_stat.st_mode):
                                result["regular_files"] += 1
                                result["regular_file_bytes"] += entry_stat.st_size
                            elif stat.S_ISFIFO(entry_stat.st_mode) or stat.S_ISSOCK(entry_stat.st_mode):
                                result["volatile_entries_skipped"] += 1
                                if len(result["volatile_paths"]) < 50:
                                    result["volatile_paths"].append(entry.path)
                            else:
                                result["special_entries"] += 1
                        except OSError as exc:
                            record_error(entry.path, exc)
            except OSError as exc:
                record_error(current, exc)
    else:
        result["special_entries"] = 1

print(json.dumps(result, sort_keys=True))
'''

DESTINATION_SCAN_SCRIPT = r'''import json
import os

roots = ("/DATA", "/media", "/mnt")
ignored_filesystems = {
    "cgroup", "cgroup2", "debugfs", "devtmpfs", "overlay", "proc",
    "ramfs", "squashfs", "sysfs", "tmpfs", "tracefs",
}

def decode_mount_path(value):
    replacements = {
        r"\040": " ",
        r"\011": "\t",
        r"\012": "\n",
        r"\134": "\\",
    }
    for encoded, decoded in replacements.items():
        value = value.replace(encoded, decoded)
    return value

def under_roots(path):
    clean = path.rstrip("/") or "/"
    return any(clean == root or clean.startswith(root + "/") for root in roots)

rows = []
errors = []

try:
    handle = open("/proc/self/mountinfo", "r", encoding="utf-8")
except OSError as exc:
    errors.append(f"/proc/self/mountinfo: {exc}")
else:
    with handle:
        for line in handle:
            try:
                left, right = line.rstrip("\n").split(" - ", 1)
                fields = left.split()
                filesystem = right.split()
                mountpoint = decode_mount_path(fields[4])
                options = fields[5].split(",")
                filesystem_type = filesystem[0]
                source = decode_mount_path(filesystem[1]) if len(filesystem) > 1 else ""

                if not under_roots(mountpoint) or filesystem_type in ignored_filesystems:
                    continue

                stats = os.statvfs(mountpoint)
                rows.append({
                    "mountpoint": mountpoint,
                    "source": source,
                    "filesystem": filesystem_type,
                    "device": fields[2],
                    "writable": "rw" in options,
                    "total_bytes": stats.f_blocks * stats.f_frsize,
                    "free_bytes": stats.f_bavail * stats.f_frsize,
                })
            except Exception as exc:
                errors.append(str(exc))

rows.sort(key=lambda item: item["mountpoint"])
print(json.dumps({"destinations": rows, "errors": errors}, sort_keys=True))
'''


def _under(path, roots):
    clean = str(path or "").rstrip("/") or "/"
    return any(clean == root or clean.startswith(root + "/") for root in roots)


def source_identifier(source):
    return hashlib.sha256(str(source or "").encode("utf-8", errors="surrogatepass")).hexdigest()


def _strictly_under(path, parent):
    clean_path = str(path or "").rstrip("/") or "/"
    clean_parent = str(parent or "").rstrip("/") or "/"
    if clean_path == clean_parent:
        return False
    if clean_parent == "/":
        return clean_path.startswith("/")
    return clean_path.startswith(clean_parent + "/")


def classify_mount(mount):
    mount_type = str(mount.get("Type") or "unknown")
    source = str(mount.get("Source") or "")
    destination = str(mount.get("Destination") or "")

    if mount_type == "tmpfs":
        return "excluded", "Temporary in-memory mount"
    if destination == "/var/run/docker.sock" or source == "/var/run/docker.sock":
        return "excluded", "Docker control socket"
    if _under(destination, RUNTIME_DESTINATIONS):
        return "excluded", "Runtime/system mount"
    if mount_type == "volume":
        return "candidate", "Docker named volume"
    if mount_type == "bind" and _under(source, PERSISTENT_SOURCE_ROOTS):
        return "candidate", "Persistent host path"
    if mount_type == "bind":
        return "review", "Bind source is outside recognised persistent roots"
    return "review", f"Unsupported or unknown mount type: {mount_type}"


def _published_ports(inspect_data):
    bindings = (inspect_data.get("HostConfig") or {}).get("PortBindings") or {}
    rows = []
    for container_port, host_bindings in sorted(bindings.items()):
        if not host_bindings:
            rows.append({"container": container_port, "host_ip": "", "host_port": ""})
            continue
        for binding in host_bindings:
            rows.append({
                "container": container_port,
                "host_ip": str(binding.get("HostIp") or ""),
                "host_port": str(binding.get("HostPort") or ""),
            })
    return rows


def _unique_candidate_sources(containers):
    sources = {}
    for container in containers:
        for mount in container.get("mounts") or []:
            if mount.get("decision") != "candidate" or not mount.get("source"):
                continue

            source = mount["source"]
            source_id = source_identifier(source)
            mount["source_id"] = source_id
            item = sources.setdefault(source_id, {
                "source_id": source_id,
                "source": source,
                "types": [],
                "volume_names": [],
                "reasons": [],
                "consumers": [],
                "measurement_status": "NOT MEASURED",
            })

            for key, value in (
                ("types", mount.get("type")),
                ("volume_names", mount.get("name")),
                ("reasons", mount.get("reason")),
            ):
                if value and value not in item[key]:
                    item[key].append(value)

            consumer = {
                "container": container.get("name") or "unknown",
                "destination": mount.get("destination") or "",
                "rw": bool(mount.get("rw")),
            }
            if consumer not in item["consumers"]:
                item["consumers"].append(consumer)

    rows = list(sources.values())
    for item in rows:
        item["consumers"].sort(key=lambda row: (row["container"].lower(), row["destination"]))
    rows.sort(key=lambda item: item["source"].lower())

    for item in rows:
        parents = [
            {
                "source_id": other["source_id"],
                "source": other["source"],
            }
            for other in rows
            if _strictly_under(item["source"], other["source"])
        ]
        parents.sort(key=lambda parent: len(parent["source"]), reverse=True)
        item["parent_sources"] = parents
        item["nested_source_count"] = sum(
            _strictly_under(other["source"], item["source"])
            for other in rows
        )
    return rows


def collect_inventory(docker_get):
    result = {
        "mode": "read-only-inventory",
        "verification_status": "NOT VERIFIED",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "docker_engine": {},
        "containers": [],
        "sources": [],
        "summary": {},
        "errors": [],
        "limitations": [
            "No files were copied and no backup was created.",
            "Source byte measurement is read-only and must be started by the user.",
            "A running application can change its source while measurement is in progress.",
            "Captured bytes, archive bytes and archive checksums are unavailable until a snapshot exists.",
            "Restore readiness requires a successful test restoration.",
        ],
    }

    try:
        version = docker_get("/version") or {}
        result["docker_engine"] = {
            "version": str(version.get("Version") or "unknown"),
            "api_version": str(version.get("ApiVersion") or "unknown"),
        }
        summaries = docker_get("/containers/json?all=1")
    except Exception as exc:
        result["errors"].append(f"Docker API access failed: {exc}")
        return result

    if not isinstance(summaries, list):
        result["errors"].append("Docker API did not return a container list.")
        return result

    inspection_failures = 0
    for summary in summaries:
        container_id = str(summary.get("Id") or "")
        try:
            inspected = docker_get(f"/containers/{quote(container_id, safe='')}/json") or {}
        except Exception as exc:
            inspected = {}
            result["errors"].append(f"Container {container_id[:12]} inspection failed: {exc}")

        if not isinstance(inspected, dict) or not inspected.get("Id"):
            inspection_failures += 1
            inspected = {}

        config = inspected.get("Config") or {}
        state = inspected.get("State") or {}
        labels = config.get("Labels") or summary.get("Labels") or {}
        names = summary.get("Names") or []
        name = str(inspected.get("Name") or (names[0] if names else container_id[:12])).lstrip("/")

        mounts = []
        for mount in inspected.get("Mounts") or []:
            decision, reason = classify_mount(mount)
            mounts.append({
                "type": str(mount.get("Type") or "unknown"),
                "name": str(mount.get("Name") or ""),
                "source": str(mount.get("Source") or ""),
                "destination": str(mount.get("Destination") or ""),
                "rw": bool(mount.get("RW")),
                "decision": decision,
                "reason": reason,
            })

        networks = sorted(((inspected.get("NetworkSettings") or {}).get("Networks") or {}).keys())
        health = (state.get("Health") or {}).get("Status") or "not-configured"
        result["containers"].append({
            "name": name,
            "id": str(inspected.get("Id") or container_id)[:12],
            "image_ref": str(config.get("Image") or summary.get("Image") or "unknown"),
            "image_id": str(inspected.get("Image") or summary.get("ImageID") or ""),
            "state": str(state.get("Status") or summary.get("State") or "unknown"),
            "health": str(health),
            "compose_project": str(labels.get("com.docker.compose.project") or ""),
            "mounts": mounts,
            "ports": _published_ports(inspected),
            "networks": networks,
        })

    result["containers"].sort(key=lambda item: item["name"].lower())
    result["sources"] = _unique_candidate_sources(result["containers"])
    all_mounts = [mount for item in result["containers"] for mount in item["mounts"]]
    candidate_mounts = sum(mount["decision"] == "candidate" for mount in all_mounts)
    result["summary"] = {
        "containers": len(result["containers"]),
        "running": sum(item["state"] == "running" for item in result["containers"]),
        "stopped": sum(item["state"] != "running" for item in result["containers"]),
        "unique_images": len({item["image_id"] or item["image_ref"] for item in result["containers"]}),
        "mounts": len(all_mounts),
        "candidate_mounts": candidate_mounts,
        "unique_candidate_sources": len(result["sources"]),
        "duplicate_candidate_references": candidate_mounts - len(result["sources"]),
        "review_mounts": sum(mount["decision"] == "review" for mount in all_mounts),
        "excluded_mounts": sum(mount["decision"] == "excluded" for mount in all_mounts),
        "inspection_failures": inspection_failures,
    }
    result["verification_status"] = "VERIFIED" if inspection_failures == 0 else "PARTIALLY VERIFIED"
    return result


def find_candidate_source(inventory, source_id):
    wanted = str(source_id or "")
    return next((item for item in inventory.get("sources") or [] if item.get("source_id") == wanted), None)


def destination_identifier(device, mountpoint):
    value = f"{device}\0{mountpoint}"
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


def _destination_alias_rank(mountpoint):
    path = str(mountpoint or "")
    if path == "/DATA" or path.startswith("/media/"):
        return 0
    if path.startswith("/DATA/.media/"):
        return 1
    if path == "/media":
        return 2
    if path.startswith("/mnt/"):
        return 3
    return 4


def classify_destination(destination):
    mountpoint = str(destination.get("mountpoint") or "")
    filesystem = str(destination.get("filesystem") or "").lower()
    writable = bool(destination.get("writable"))
    free_bytes = int(destination.get("free_bytes", 0) or 0)

    if mountpoint == "/mnt/boot" or mountpoint.startswith("/mnt/boot/"):
        return "excluded", "ZimaOS boot storage"
    if mountpoint == "/mnt/overlay" or mountpoint.startswith("/mnt/overlay/"):
        return "excluded", "ZimaOS overlay storage"
    if filesystem in EXCLUDED_DESTINATION_FILESYSTEMS:
        return "excluded", f"Filesystem is unsuitable for snapshot storage: {filesystem}"
    if not writable:
        return "excluded", "Mount is read-only"
    if free_bytes <= 0:
        return "excluded", "No writable free capacity reported"
    if filesystem in NATIVE_DESTINATION_FILESYSTEMS:
        return "candidate", "Native Linux filesystem"
    if filesystem in REVIEW_DESTINATION_FILESYSTEMS:
        return "review", "Filesystem may not preserve Linux ownership, permissions or links"
    return "review", f"Filesystem requires compatibility review: {filesystem or 'unknown'}"


def collect_destinations(command_runner, timeout=20):
    result = {
        "mode": "read-only-destination-inventory",
        "verification_status": "NOT VERIFIED",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "destinations": [],
        "summary": {},
        "errors": [],
        "limitations": [
            "No destination directory was created.",
            "Free capacity can change after this preflight.",
            "Capacity is compared against logical source bytes only; archive and filesystem overhead are not calculated yet.",
            "A destination on the same filesystem as any selected source is blocked.",
        ],
    }

    try:
        completed = command_runner(["python3", "-c", DESTINATION_SCAN_SCRIPT], timeout=timeout)
    except Exception as exc:
        result["errors"].append(f"Destination inventory runner failed: {exc}")
        return result

    if not isinstance(completed, dict):
        result["errors"].append("Destination inventory runner returned an invalid result.")
        return result

    stdout = str(completed.get("stdout") or "")
    if not completed.get("ok"):
        detail = str(completed.get("stderr") or stdout or "Destination inventory failed.").strip()
        result["errors"].append(detail)
        return result

    try:
        payload = json.loads(stdout)
    except Exception as exc:
        result["errors"].append(f"Destination inventory returned invalid JSON: {exc}")
        return result

    if not isinstance(payload, dict) or not isinstance(payload.get("destinations"), list):
        result["errors"].append("Destination inventory response is missing its destination list.")
        return result

    result["errors"].extend(str(error) for error in (payload.get("errors") or []))
    raw_rows = []
    for raw in payload["destinations"]:
        if not isinstance(raw, dict):
            result["errors"].append("Destination inventory contained a non-object row.")
            continue
        mountpoint = str(raw.get("mountpoint") or "")
        if not mountpoint.startswith("/") or not _under(mountpoint, DESTINATION_ROOTS):
            result["errors"].append(f"Destination mountpoint is outside approved roots: {mountpoint}")
            continue
        try:
            total_bytes = max(0, int(raw.get("total_bytes", 0) or 0))
            free_bytes = max(0, int(raw.get("free_bytes", 0) or 0))
        except (TypeError, ValueError):
            result["errors"].append(f"Destination capacity is invalid: {mountpoint}")
            continue
        raw_rows.append({
            "mountpoint": mountpoint,
            "source": str(raw.get("source") or ""),
            "filesystem": str(raw.get("filesystem") or "unknown"),
            "device": str(raw.get("device") or ""),
            "writable": bool(raw.get("writable")),
            "total_bytes": total_bytes,
            "free_bytes": free_bytes,
        })

    by_device = {}
    for row in raw_rows:
        device_key = row["device"] or f"mountpoint:{row['mountpoint']}"
        by_device.setdefault(device_key, []).append(row)

    destinations = []
    aliases_collapsed = 0
    for rows in by_device.values():
        rows.sort(key=lambda row: (_destination_alias_rank(row["mountpoint"]), len(row["mountpoint"]), row["mountpoint"]))
        chosen = dict(rows[0])
        chosen["aliases"] = sorted({row["mountpoint"] for row in rows})
        aliases_collapsed += max(0, len(rows) - 1)
        decision, reason = classify_destination(chosen)
        chosen["decision"] = decision
        chosen["reason"] = reason
        chosen["destination_id"] = destination_identifier(chosen["device"], chosen["mountpoint"])
        destinations.append(chosen)

    destinations.sort(key=lambda row: (row["decision"] != "candidate", row["decision"] != "review", row["mountpoint"].lower()))
    result["destinations"] = destinations
    result["summary"] = {
        "raw_mounts": len(raw_rows),
        "unique_devices": len(destinations),
        "aliases_collapsed": aliases_collapsed,
        "candidate_destinations": sum(row["decision"] == "candidate" for row in destinations),
        "review_destinations": sum(row["decision"] == "review" for row in destinations),
        "excluded_destinations": sum(row["decision"] == "excluded" for row in destinations),
    }
    result["verification_status"] = "VERIFIED" if not result["errors"] else "PARTIALLY VERIFIED"
    return result


def find_destination(destination_inventory, destination_id):
    wanted = str(destination_id or "")
    return next(
        (item for item in destination_inventory.get("destinations") or [] if item.get("destination_id") == wanted),
        None,
    )


def measure_source(source, command_runner, timeout=120):
    result = {
        "mode": "source-logical-byte-measurement",
        "measurement_status": "FAILED",
        "snapshot_status": "NOT CREATED",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_id": str((source or {}).get("source_id") or ""),
        "source": str((source or {}).get("source") or ""),
        "resolved_path": "",
        "device": "",
        "stat_device": "",
        "mountpoint": "",
        "filesystem": "",
        "mount_source": "",
        "regular_file_bytes": 0,
        "regular_files": 0,
        "directories": 0,
        "symlinks": 0,
        "special_entries": 0,
        "volatile_entries_skipped": 0,
        "volatile_paths": [],
        "mount_boundaries_skipped": 0,
        "error_count": 0,
        "errors": [],
    }

    path = result["source"]
    if not path.startswith("/"):
        result["errors"].append("Candidate source is not an absolute host path.")
        result["error_count"] = 1
        return result

    try:
        completed = command_runner(["python3", "-c", SOURCE_SCAN_SCRIPT, path], timeout=timeout)
    except Exception as exc:
        result["errors"].append(f"Host measurement runner failed: {exc}")
        result["error_count"] = 1
        return result

    if not isinstance(completed, dict):
        result["errors"].append("Host measurement runner returned an invalid result.")
        result["error_count"] = 1
        return result

    stdout = str(completed.get("stdout") or "")
    if not completed.get("ok"):
        detail = str(completed.get("stderr") or stdout or "Host measurement failed.").strip()
        result["errors"].append(detail)
        result["error_count"] = 1
        return result

    try:
        measured = json.loads(stdout)
    except Exception as exc:
        result["errors"].append(f"Host measurement returned invalid JSON: {exc}")
        result["error_count"] = 1
        return result

    if not isinstance(measured, dict) or measured.get("path") != path:
        result["errors"].append("Host measurement response did not match the requested source.")
        result["error_count"] = 1
        return result

    for key in (
        "regular_file_bytes",
        "regular_files",
        "directories",
        "symlinks",
        "special_entries",
        "volatile_entries_skipped",
        "mount_boundaries_skipped",
        "error_count",
    ):
        try:
            result[key] = max(0, int(measured.get(key, 0) or 0))
        except (TypeError, ValueError):
            result["errors"].append(f"Invalid numeric measurement for {key}.")
            result["error_count"] += 1

    for key in (
        "resolved_path",
        "device",
        "stat_device",
        "mountpoint",
        "filesystem",
        "mount_source",
    ):
        result[key] = str(measured.get(key) or "")

    result["volatile_paths"] = [str(path) for path in (measured.get("volatile_paths") or [])[:50]]

    if not result["device"]:
        result["errors"].append("Host measurement did not resolve the canonical source filesystem device.")
        result["error_count"] += 1

    result["errors"].extend(str(error) for error in (measured.get("errors") or []))
    result["measurement_status"] = "MEASURED" if result["error_count"] == 0 and not result["errors"] else "PARTIAL"
    return result


def render_inventory_page(
    inventory,
    app_version,
    destination_inventory=None,
    verified_snapshot=None,
    csrf_value="",
    verified_restore=None,
):
    esc = lambda value: html.escape(str(value or ""))
    status = esc(inventory.get("verification_status"))
    summary = inventory.get("summary") or {}
    errors = inventory.get("errors") or []
    destination_inventory = destination_inventory or {
        "verification_status": "NOT VERIFIED",
        "destinations": [],
        "summary": {},
        "errors": ["Destination inventory was not collected."],
    }
    destination_status = esc(destination_inventory.get("verification_status"))
    destination_summary = destination_inventory.get("summary") or {}
    destination_errors = destination_inventory.get("errors") or []
    verified_snapshot = verified_snapshot or {
        "verification_status": "NOT CREATED",
        "snapshot_status": "NOT CREATED",
        "manifest": None,
        "errors": [],
    }
    verified_manifest = verified_snapshot.get("manifest") or {}
    verified_source = verified_manifest.get("source") or {}
    verified_archive = verified_manifest.get("archive") or {}
    verified_status = str(verified_snapshot.get("verification_status") or "NOT CREATED")
    verified_is_valid = verified_status == "VERIFIED" and bool(verified_manifest)
    verified_badge = "VERIFIED" if verified_is_valid else verified_status
    verified_message = (
        f"Snapshot {verified_manifest.get('snapshot_id')} verified from its stored manifest and archive."
        if verified_is_valid
        else "No verified snapshot has been created."
    )
    verified_submessage = (
        f"{verified_source.get('regular_files', 0)} files · source device {verified_source.get('device', 'unknown')} · restore {verified_manifest.get('restore_status', 'NOT TESTED')}"
        if verified_is_valid
        else "Measuring source bytes does not prove that files were captured."
    )
    verified_logical_bytes = verified_source.get("regular_file_bytes") if verified_is_valid else None
    verified_archive_bytes = verified_archive.get("stored_bytes") if verified_is_valid else None
    verified_checksum = verified_archive.get("sha256") if verified_is_valid else None
    verified_logical_display = f"{int(verified_logical_bytes):,} B" if verified_logical_bytes is not None else "Unavailable"
    verified_archive_display = f"{int(verified_archive_bytes):,} B" if verified_archive_bytes is not None else "Unavailable"
    verified_difference_display = "0 B" if verified_is_valid else "Unavailable"
    verified_checksum_display = str(verified_checksum or "Unavailable")
    verified_destination = verified_manifest.get("destination") or {}
    verified_restore = verified_restore or {
        "verification_status": "NOT TESTED",
        "restore_status": "NOT TESTED",
        "manifest": None,
        "errors": [],
    }
    restore_manifest = verified_restore.get("manifest") or {}
    restore_record = restore_manifest.get("restore") or {}
    restore_matches_snapshot = bool(
        verified_is_valid
        and restore_manifest
        and restore_manifest.get("snapshot_id") == verified_manifest.get("snapshot_id")
    )
    restore_is_valid = bool(
        restore_matches_snapshot
        and verified_restore.get("verification_status") == "VERIFIED"
        and verified_restore.get("restore_status") == "VERIFIED"
    )
    restore_badge = "VERIFIED" if restore_is_valid else "NOT TESTED"
    restore_message = (
        f"Isolated restore for snapshot {restore_manifest.get('snapshot_id')} reverified from disk."
        if restore_is_valid
        else "No isolated restore test has been verified for this snapshot."
    )
    restore_submessage = (
        f"{restore_record.get('regular_files', 0)} files · live source not overwritten · application not started"
        if restore_is_valid
        else "The test will create a new path and will never overwrite the live Snapshot Lab source."
    )
    restore_target = (
        str(restore_record.get("path") or "")
        if restore_is_valid
        else (
            str(verified_destination.get("mountpoint") or "").rstrip("/")
            + "/zimabrain-restore-tests/"
            + str(verified_manifest.get("snapshot_id") or "")
            if verified_is_valid
            else "Unavailable"
        )
    )
    restore_bytes = restore_record.get("regular_file_bytes") if restore_is_valid else None
    restore_files = restore_record.get("regular_files") if restore_is_valid else None
    restore_bytes_display = f"{int(restore_bytes):,} B" if restore_bytes is not None else "Unavailable"
    restore_files_display = f"{int(restore_files):,}" if restore_files is not None else "Unavailable"
    restore_difference_display = "0 B" if restore_is_valid else "Unavailable"

    cards = "".join(
        f'<div class="card"><span>{esc(label)}</span><strong>{esc(summary.get(key, 0))}</strong></div>'
        for key, label in (
            ("containers", "Containers"),
            ("running", "Running"),
            ("unique_images", "Images"),
            ("unique_candidate_sources", "Unique sources"),
            ("review_mounts", "Needs review"),
            ("excluded_mounts", "Excluded runtime mounts"),
        )
    )

    source_rows = []
    for source in inventory.get("sources") or []:
        source_id = esc(source["source_id"])
        source_path = esc(source["source"])
        consumers = ", ".join(
            f"{item['container']} → {item['destination']}" for item in source.get("consumers") or []
        )
        parents = source.get("parent_sources") or []
        parent_hint = ""
        if parents:
            parent_hint = f"Nested under candidate source: {parents[0]['source']}"
        elif source.get("nested_source_count"):
            parent_hint = f"Contains {source['nested_source_count']} nested candidate source(s)."
        source_rows.append(
            f'<div class="source-row" id="source-row-{source_id}">'
            f'<label><input class="source-check" type="checkbox" value="{source_id}" data-source-path="{source_path}" data-parent-hint="{esc(parent_hint)}"> '
            f'<b>{source_path}</b></label>'
            f'<div class="source-meta">Used by: {esc(consumers or "No consumer details")}</div>'
            f'<div class="source-overlap" id="source-overlap-{source_id}">{esc(parent_hint)}</div>'
            '<div class="source-measurement">'
            f'<span id="source-bytes-{source_id}">Source logical bytes: not measured</span>'
            f'<small id="source-detail-{source_id}">Select this source, then measure it.</small>'
            "</div></div>"
        )

    if not source_rows:
        source_rows.append('<p class="muted">No candidate source paths were identified.</p>')

    destination_options = ['<option value="">Choose a verified destination…</option>']
    for destination in destination_inventory.get("destinations") or []:
        if destination.get("decision") == "excluded":
            continue
        destination_id = esc(destination.get("destination_id"))
        mountpoint = esc(destination.get("mountpoint"))
        device = esc(destination.get("device"))
        filesystem = esc(destination.get("filesystem"))
        free_bytes = int(destination.get("free_bytes", 0) or 0)
        total_bytes = int(destination.get("total_bytes", 0) or 0)
        decision = str(destination.get("decision") or "review")
        reason = esc(destination.get("reason"))
        disabled = " disabled" if decision != "candidate" else ""
        label_prefix = "" if decision == "candidate" else "[REVIEW REQUIRED] "
        destination_options.append(
            f'<option value="{destination_id}" data-mountpoint="{mountpoint}" '
            f'data-device="{device}" data-filesystem="{filesystem}" '
            f'data-free-bytes="{free_bytes}" data-total-bytes="{total_bytes}" '
            f'data-reason="{reason}"{disabled}>'
            f'{esc(label_prefix)}{mountpoint} · {filesystem} · {free_bytes:,} B free'
            "</option>"
        )

    rows = []
    for item in inventory.get("containers") or []:
        candidates = sum(mount["decision"] == "candidate" for mount in item["mounts"])
        reviews = sum(mount["decision"] == "review" for mount in item["mounts"])
        mount_lines = "".join(
            "<li>"
            f"<b>{esc(mount['decision'].upper())}</b> "
            f"{esc(mount['source'] or mount['name'])} → {esc(mount['destination'])} "
            f"({esc(mount['reason'])})"
            "</li>"
            for mount in item["mounts"]
        ) or "<li>No mounts reported by Docker.</li>"
        rows.append(
            "<tr>"
            f"<td><b>{esc(item['name'])}</b><br><small>{esc(item['compose_project'])}</small></td>"
            f"<td>{esc(item['state'])}<br><small>health: {esc(item['health'])}</small></td>"
            f"<td>{esc(item['image_ref'])}<br><small>{esc(item['image_id'][:19])}</small></td>"
            f"<td>{candidates} candidate / {reviews} review<details><summary>Mount evidence</summary><ul>{mount_lines}</ul></details></td>"
            "</tr>"
        )

    all_errors = (
        list(errors)
        + [f"Destination: {error}" for error in destination_errors]
        + [f"Verified snapshot: {error}" for error in (verified_snapshot.get("errors") or [])]
        + [f"Verified restore: {error}" for error in (verified_restore.get("errors") or [])]
    )
    error_html = "" if not all_errors else '<div class="errors"><b>Collection errors</b><ul>' + "".join(
        f"<li>{esc(error)}</li>" for error in all_errors
    ) + "</ul></div>"

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>ZimaBrain Snapshot Inventory</title>
<style>
body{{margin:0;background:#080b10;color:#e8edf2;font-family:Arial,sans-serif}}main{{max-width:1500px;margin:auto;padding:28px}}
a{{color:#93c5fd}}button{{background:#2563eb;color:white;border:0;border-radius:9px;padding:10px 14px;font-weight:700;cursor:pointer}}button.execute{{background:#b91c1c}}button:disabled{{opacity:.55;cursor:not-allowed}}
.top{{display:flex;justify-content:space-between;gap:20px;align-items:center;flex-wrap:wrap}}.badge{{border:1px solid #3b82f6;background:#172554;padding:7px 11px;border-radius:999px;font-weight:800}}
.notice{{margin:20px 0;padding:16px;border:1px solid #f59e0b;background:#422006;border-radius:12px}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}}
.card,.pane{{background:#111827;border:1px solid #263241;border-radius:14px;padding:14px}}.card span{{display:block;color:#9aa8b5;font-size:13px}}.card strong{{display:block;font-size:26px;margin-top:6px}}
.split{{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:16px;margin-top:20px}}.pane-head{{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}}.pane h2{{margin:0}}
.source-list{{margin-top:14px}}.source-row{{padding:13px 0;border-top:1px solid #263241;word-break:break-word}}.source-row:first-child{{border-top:0}}.source-meta,.muted{{color:#9aa8b5}}.source-meta{{font-size:13px;margin:6px 0}}.source-overlap{{color:#fbbf24;font-size:13px;margin-bottom:5px}}.source-measurement{{display:grid;grid-template-columns:1fr;gap:4px}}.source-measurement small{{color:#9aa8b5}}
.awaiting{{min-height:260px;display:grid;place-content:center;text-align:center;color:#9aa8b5}}.compare-grid{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:18px}}.compare-grid div{{border-top:1px solid #263241;padding-top:10px}}.compare-grid strong{{display:block;margin-top:5px}}
.destination-block,.restore-block{{margin-top:16px;padding:14px;border:1px solid #334155;border-radius:12px;background:#0b1220}}.destination-block label{{display:block;font-weight:700;margin-bottom:7px}}select{{width:100%;box-sizing:border-box;background:#080b10;color:#e8edf2;border:1px solid #475569;border-radius:8px;padding:10px}}.destination-detail,.preflight-status{{margin-top:9px}}.plan-actions{{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}}.plan-pane{{margin-top:16px}}pre{{white-space:pre-wrap;word-break:break-word;background:#080b10;border:1px solid #263241;border-radius:10px;padding:12px;max-height:420px;overflow:auto}}[hidden]{{display:none!important}}
table{{width:100%;border-collapse:collapse;margin-top:20px;background:#111827}}th,td{{border:1px solid #263241;padding:11px;text-align:left;vertical-align:top}}th{{background:#172033}}small{{color:#9aa8b5}}details{{margin-top:7px}}li{{margin:5px 0;word-break:break-word}}
.errors{{margin-top:16px;padding:14px;background:#450a0a;border:1px solid #ef4444;border-radius:12px}}.links a{{margin-left:12px}}.measurement-total{{margin-top:12px;font-weight:700}}
@media(max-width:850px){{.split{{grid-template-columns:1fr}}.awaiting{{min-height:160px}}}}@media(max-width:520px){{main{{padding:18px}}.compare-grid{{grid-template-columns:1fr}}}}
</style></head><body><main>
<div class="top"><div><h1>ZimaBrain Snapshot Inventory</h1><p>Read-only Docker, host-path and destination evidence from the current unit.</p></div><div class="links"><span class="badge">INVENTORY {status}</span><span class="badge">DESTINATIONS {destination_status}</span><a href="/snapshot/full">Simple All AppData</a><a href="/">Back to ZimaBrain</a><a href="/api/v1/snapshot/inventory">Inventory JSON</a><a href="/api/v1/snapshot/destinations">Destination JSON</a></div></div>
<div class="notice"><b>Restricted Lab snapshot and isolated restore testing enabled.</b> v0.6 can restore-test only a verified /DATA/AppData/zimabrain-snapshot-lab archive into a new /DATA/zimabrain-restore-tests path. No production source can be overwritten or started from restored data.</div>
<p><small>App {esc(app_version)} · Generated {esc(inventory.get('generated_at'))} · Docker {esc((inventory.get('docker_engine') or {}).get('version'))}</small></p>
<div class="cards">{cards}</div>{error_html}
<div class="split">
  <section class="pane">
    <div class="pane-head"><div><h2>Planned Snapshot</h2><p class="muted">Exact duplicate paths are counted once. Overlapping selections are blocked.</p></div><button id="measure-selected" type="button" disabled>Measure selected sources</button></div>
    <div id="measurement-total" class="measurement-total">Selected measured total: 0 B</div>
    <div class="destination-block">
      <label for="snapshot-destination">Snapshot destination</label>
      <select id="snapshot-destination">{''.join(destination_options)}</select>
      <div id="destination-detail" class="destination-detail muted">Select a native Linux destination. No directory will be created.</div>
      <div id="preflight-status" class="preflight-status"><b>Preflight:</b> select and measure at least one source.</div>
      <div class="plan-actions">
        <button id="build-plan" type="button" disabled>Build proposed manifest</button>
        <button id="download-plan" type="button" disabled>Download manifest</button>
        <button class="execute" id="create-lab-snapshot" type="button" disabled>Create verified Lab snapshot</button>
      </div>
      <small id="execution-note">Execution is restricted to the Snapshot Lab data source and requires a separate native Linux filesystem.</small><br>
      <small>Destinations: {esc(destination_summary.get('candidate_destinations', 0))} eligible · {esc(destination_summary.get('review_destinations', 0))} review · {esc(destination_summary.get('excluded_destinations', 0))} excluded · {esc(destination_summary.get('aliases_collapsed', 0))} aliases collapsed</small>
    </div>
    <div class="source-list">{''.join(source_rows)}</div>
  </section>
  <section class="pane">
    <div class="pane-head"><div><h2>Verified Snapshot</h2><p class="muted">Populated only after the stored archive checksum and manifest verify.</p></div><span class="badge" id="verified-badge">{esc(verified_badge)}</span></div>
    <div class="awaiting"><div><b id="verified-message">{esc(verified_message)}</b><p id="verified-submessage">{esc(verified_submessage)}</p></div></div>
    <div class="compare-grid">
      <div><span class="muted">Captured logical bytes</span><strong id="verified-logical-bytes">{esc(verified_logical_display)}</strong></div>
      <div><span class="muted">Difference from captured source</span><strong id="verified-difference">{esc(verified_difference_display)}</strong></div>
      <div><span class="muted">Stored archive bytes</span><strong id="verified-archive-bytes">{esc(verified_archive_display)}</strong></div>
      <div><span class="muted">Archive SHA-256</span><strong id="verified-checksum">{esc(verified_checksum_display)}</strong></div>
    </div>
    <div class="restore-block">
      <div class="pane-head"><div><h3>Isolated Restore Test</h3><p class="muted" id="restore-message">{esc(restore_message)}</p></div><span class="badge" id="restore-badge">{esc(restore_badge)}</span></div>
      <p id="restore-submessage">{esc(restore_submessage)}</p>
      <div class="compare-grid">
        <div><span class="muted">Restored logical bytes</span><strong id="restore-bytes">{esc(restore_bytes_display)}</strong></div>
        <div><span class="muted">Difference from snapshot</span><strong id="restore-difference">{esc(restore_difference_display)}</strong></div>
        <div><span class="muted">Restored files</span><strong id="restore-files">{esc(restore_files_display)}</strong></div>
        <div><span class="muted">Isolated target</span><strong id="restore-target">{esc(restore_target)}</strong></div>
      </div>
      <div class="plan-actions"><button class="execute" id="restore-lab-snapshot" type="button"{' disabled' if not verified_is_valid or restore_is_valid else ''}>Run isolated restore test</button></div>
      <small id="restore-note">Server-side verification will recheck the stored manifest and archive before creating a new isolated path.</small>
    </div>
  </section>
</div>
<section class="pane plan-pane" id="plan-panel">
  <div class="pane-head"><div><h2>Proposed Snapshot Plan</h2><p class="muted">Browser proposal only. The server independently revalidates every execution input.</p></div><span class="badge" id="plan-badge">NOT BUILT</span></div>
  <p id="plan-summary">Select, measure and preflight the source and destination first.</p>
  <pre id="manifest-preview" hidden></pre>
</section>
<h2>Container and mount evidence</h2>
<table><thead><tr><th>Container</th><th>Runtime state</th><th>Verified local image reference</th><th>Mount classification</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<script>
(function(){{
  const button = document.getElementById("measure-selected");
  const total = document.getElementById("measurement-total");
  const checks = Array.from(document.querySelectorAll(".source-check"));
  const destinationSelect = document.getElementById("snapshot-destination");
  const destinationDetail = document.getElementById("destination-detail");
  const preflightStatus = document.getElementById("preflight-status");
  const buildPlanButton = document.getElementById("build-plan");
  const downloadPlanButton = document.getElementById("download-plan");
  const createLabSnapshotButton = document.getElementById("create-lab-snapshot");
  const executionNote = document.getElementById("execution-note");
  const planBadge = document.getElementById("plan-badge");
  const planSummary = document.getElementById("plan-summary");
  const manifestPreview = document.getElementById("manifest-preview");
  const inventoryGeneratedAt = {json.dumps(str(inventory.get("generated_at") or ""))};
  const destinationGeneratedAt = {json.dumps(str(destination_inventory.get("generated_at") or ""))};
  const appVersion = {json.dumps(str(app_version or ""))};
  const csrfValue = {json.dumps(str(csrf_value or ""))};
  const labTestSource = "/DATA/AppData/zimabrain-snapshot-lab";
  const executionReserveBytes = 64 * 1024 * 1024;
  const verifiedBadge = document.getElementById("verified-badge");
  const verifiedMessage = document.getElementById("verified-message");
  const verifiedSubmessage = document.getElementById("verified-submessage");
  const verifiedLogicalBytes = document.getElementById("verified-logical-bytes");
  const verifiedDifference = document.getElementById("verified-difference");
  const verifiedArchiveBytes = document.getElementById("verified-archive-bytes");
  const verifiedChecksum = document.getElementById("verified-checksum");
  const restoreLabButton = document.getElementById("restore-lab-snapshot");
  const restoreBadge = document.getElementById("restore-badge");
  const restoreMessage = document.getElementById("restore-message");
  const restoreSubmessage = document.getElementById("restore-submessage");
  const restoreBytes = document.getElementById("restore-bytes");
  const restoreDifference = document.getElementById("restore-difference");
  const restoreFiles = document.getElementById("restore-files");
  const restoreTarget = document.getElementById("restore-target");
  const restoreNote = document.getElementById("restore-note");
  let activeVerifiedSnapshotId = {json.dumps(str(verified_manifest.get("snapshot_id") or "") if verified_is_valid else "")};
  let currentManifest = null;

  function normalisePath(value){{
    const clean = String(value || "").replace(/[/]+$/, "");
    return clean || "/";
  }}

  function pathsOverlap(left, right){{
    const a = normalisePath(left);
    const b = normalisePath(right);
    if (a === b) return true;
    if (a === "/" || b === "/") return true;
    return a.startsWith(b + "/") || b.startsWith(a + "/");
  }}

  function selectedChecks(){{
    return checks.filter((item) => item.checked);
  }}

  function selectedMeasuredTotal(){{
    let bytes = 0;
    selectedChecks().forEach((item) => {{
      const row = document.getElementById("source-row-" + item.value);
      bytes += Number((row && row.dataset.measuredBytes) || "0");
    }});
    return bytes;
  }}

  function refreshTotal(){{
    const bytes = selectedMeasuredTotal();
    total.textContent = "Selected measured total: " + bytes.toLocaleString("en-US") + " B";
  }}

  function selectedDestination(){{
    if (!destinationSelect || !destinationSelect.value) return null;
    const option = destinationSelect.options[destinationSelect.selectedIndex];
    return {{
      destination_id: option.value,
      mountpoint: option.dataset.mountpoint || "",
      device: option.dataset.device || "",
      filesystem: option.dataset.filesystem || "",
      free_bytes: Number(option.dataset.freeBytes || "0"),
      total_bytes: Number(option.dataset.totalBytes || "0"),
      reason: option.dataset.reason || "",
    }};
  }}

  function evaluatePreflight(){{
    const selected = selectedChecks();
    const rows = selected.map((item) => document.getElementById("source-row-" + item.value));
    const allMeasured = selected.length > 0 && rows.every((row) => row && row.dataset.measurementStatus === "MEASURED" && row.dataset.sourceDevice);
    const destination = selectedDestination();
    const requiredBytes = selectedMeasuredTotal();
    const executionRequiredBytes = requiredBytes + executionReserveBytes;
    const sameDeviceSources = destination && allMeasured
      ? rows.filter((row) => row.dataset.sourceDevice === destination.device).map((row) => row.dataset.sourcePath)
      : [];
    const capacitySufficient = Boolean(destination) && destination.free_bytes >= executionRequiredBytes;
    const separateFilesystem = Boolean(destination) && sameDeviceSources.length === 0;
    const ready = selected.length > 0 && allMeasured && Boolean(destination) && capacitySufficient && separateFilesystem;

    return {{
      selected: selected,
      rows: rows,
      destination: destination,
      requiredBytes: requiredBytes,
      executionRequiredBytes: executionRequiredBytes,
      allMeasured: allMeasured,
      capacitySufficient: capacitySufficient,
      separateFilesystem: separateFilesystem,
      sameDeviceSources: sameDeviceSources,
      ready: ready,
    }};
  }}

  function invalidatePlan(){{
    currentManifest = null;
    downloadPlanButton.disabled = true;
    createLabSnapshotButton.disabled = true;
    executionNote.textContent = "Execution is restricted to the Snapshot Lab data source and requires a separate native Linux filesystem.";
    planBadge.textContent = "NOT BUILT";
    planSummary.textContent = "Selection or measurement changed. Build a new proposed manifest after preflight passes.";
    manifestPreview.hidden = true;
    manifestPreview.textContent = "";
  }}

  function refreshDestinationDetail(){{
    const destination = selectedDestination();
    if (!destination) {{
      destinationDetail.textContent = "Select a native Linux destination. No directory will be created.";
      return;
    }}
    const targetPath = normalisePath(destination.mountpoint) + "/zimabrain-snapshots";
    destinationDetail.textContent = destination.mountpoint + " · device " + destination.device + " · " + destination.filesystem + " · " + destination.free_bytes.toLocaleString("en-US") + " B free of " + destination.total_bytes.toLocaleString("en-US") + " B · proposed target " + targetPath;
  }}

  function refreshPreflight(){{
    const state = evaluatePreflight();
    buildPlanButton.disabled = !state.ready || button.dataset.busy === "1";

    if (state.selected.length === 0) {{
      preflightStatus.textContent = "Preflight: select and measure at least one source.";
    }} else if (!state.allMeasured) {{
      preflightStatus.textContent = "Preflight: every selected source must have a verified byte measurement.";
    }} else if (!state.destination) {{
      preflightStatus.textContent = "Preflight: choose a destination.";
    }} else if (!state.separateFilesystem) {{
      preflightStatus.textContent = "Preflight blocked: destination uses the same filesystem device as " + state.sameDeviceSources.join(", ") + ".";
    }} else if (!state.capacitySufficient) {{
      preflightStatus.textContent = "Preflight blocked: destination has " + state.destination.free_bytes.toLocaleString("en-US") + " B free but execution requires " + state.executionRequiredBytes.toLocaleString("en-US") + " B including reserve.";
    }} else {{
      const remaining = state.destination.free_bytes - state.executionRequiredBytes;
      preflightStatus.textContent = "Execution preflight ready: separate filesystem confirmed; " + state.requiredBytes.toLocaleString("en-US") + " logical B plus " + executionReserveBytes.toLocaleString("en-US") + " B reserve; " + state.destination.free_bytes.toLocaleString("en-US") + " B free; " + remaining.toLocaleString("en-US") + " B beyond minimum.";
    }}
  }}

  function syncSelectionState(){{
    const busy = button.dataset.busy === "1";
    const selected = selectedChecks();

    checks.forEach((item) => {{
      const overlapLine = document.getElementById("source-overlap-" + item.value);
      const blocker = item.checked ? null : selected.find((other) => pathsOverlap(item.dataset.sourcePath, other.dataset.sourcePath));
      item.disabled = busy || Boolean(blocker);
      if (overlapLine) {{
        overlapLine.textContent = blocker
          ? "Selection blocked because it overlaps: " + blocker.dataset.sourcePath
          : (item.dataset.parentHint || "");
      }}
    }});

    button.disabled = selected.length === 0 || busy;
    refreshTotal();
    refreshPreflight();
  }}

  checks.forEach((item) => item.addEventListener("change", function(){{
    invalidatePlan();
    syncSelectionState();
  }}));

  destinationSelect.addEventListener("change", function(){{
    invalidatePlan();
    refreshDestinationDetail();
    refreshPreflight();
  }});

  button.addEventListener("click", async function(){{
    const selected = selectedChecks();
    invalidatePlan();
    button.dataset.busy = "1";
    syncSelectionState();

    for (const item of selected) {{
      const sourceId = item.value;
      const row = document.getElementById("source-row-" + sourceId);
      const byteLine = document.getElementById("source-bytes-" + sourceId);
      const detailLine = document.getElementById("source-detail-" + sourceId);
      byteLine.textContent = "Source logical bytes: measuring…";
      detailLine.textContent = "Read-only host scan in progress.";

      try {{
        const response = await fetch("/api/v1/snapshot/source/" + encodeURIComponent(sourceId) + "/measure", {{credentials: "same-origin"}});
        const data = await response.json();
        if (!response.ok || data.measurement_status === "FAILED") {{
          throw new Error((data.errors || []).join("; ") || "Measurement failed");
        }}
        if (data.measurement_status !== "MEASURED") {{
          throw new Error((data.errors || []).join("; ") || "Measurement was only partial");
        }}
        byteLine.textContent = "Source logical bytes: " + Number(data.regular_file_bytes).toLocaleString("en-US") + " B";
        detailLine.textContent = data.regular_files.toLocaleString("en-US") + " files · " + data.directories.toLocaleString("en-US") + " directories · " + data.symlinks.toLocaleString("en-US") + " symlinks · " + data.mount_boundaries_skipped.toLocaleString("en-US") + " mount boundaries skipped · canonical mount " + data.mountpoint + " · " + data.filesystem + " · device " + data.device + " · " + data.measurement_status;
        row.dataset.measuredBytes = String(data.regular_file_bytes);
        row.dataset.measurementStatus = data.measurement_status;
        row.dataset.sourceDevice = data.device || "";
        row.dataset.sourceResolvedPath = data.resolved_path || "";
        row.dataset.sourceStatDevice = data.stat_device || "";
        row.dataset.sourceMountpoint = data.mountpoint || "";
        row.dataset.sourceFilesystem = data.filesystem || "";
        row.dataset.sourceMountSource = data.mount_source || "";
        row.dataset.measuredAt = data.generated_at || "";
        row.dataset.regularFiles = String(data.regular_files);
        row.dataset.directories = String(data.directories);
        row.dataset.symlinks = String(data.symlinks);
        row.dataset.specialEntries = String(data.special_entries);
        row.dataset.mountBoundariesSkipped = String(data.mount_boundaries_skipped);
        row.dataset.sourcePath = item.dataset.sourcePath;
      }} catch (error) {{
        byteLine.textContent = "Source logical bytes: not verified";
        detailLine.textContent = String(error.message || error);
        delete row.dataset.measuredBytes;
        delete row.dataset.measurementStatus;
        delete row.dataset.sourceDevice;
        delete row.dataset.sourceResolvedPath;
        delete row.dataset.sourceStatDevice;
        delete row.dataset.sourceMountpoint;
        delete row.dataset.sourceFilesystem;
        delete row.dataset.sourceMountSource;
        delete row.dataset.measuredAt;
      }}
      refreshTotal();
    }}

    button.dataset.busy = "0";
    syncSelectionState();
  }});

  buildPlanButton.addEventListener("click", function(){{
    const state = evaluatePreflight();
    if (!state.ready) return;

    const targetPath = normalisePath(state.destination.mountpoint) + "/zimabrain-snapshots";
    const sources = state.selected.map((item) => {{
      const row = document.getElementById("source-row-" + item.value);
      return {{
        source_id: item.value,
        source: item.dataset.sourcePath,
        resolved_path: row.dataset.sourceResolvedPath,
        device: row.dataset.sourceDevice,
        stat_device: row.dataset.sourceStatDevice,
        mountpoint: row.dataset.sourceMountpoint,
        filesystem: row.dataset.sourceFilesystem,
        mount_source: row.dataset.sourceMountSource,
        measurement_status: row.dataset.measurementStatus,
        measured_at: row.dataset.measuredAt,
        regular_file_bytes: Number(row.dataset.measuredBytes || "0"),
        regular_files: Number(row.dataset.regularFiles || "0"),
        directories: Number(row.dataset.directories || "0"),
        symlinks: Number(row.dataset.symlinks || "0"),
        special_entries: Number(row.dataset.specialEntries || "0"),
        mount_boundaries_skipped: Number(row.dataset.mountBoundariesSkipped || "0"),
      }};
    }});

    currentManifest = {{
      schema: "zimabrain.snapshot-plan.v1",
      plan_status: "READY FOR REVIEW",
      snapshot_status: "NOT CREATED",
      mode: "PROPOSED PREFLIGHT ONLY",
      created_at: new Date().toISOString(),
      app_version: appVersion,
      inventory_generated_at: inventoryGeneratedAt,
      destination_inventory_generated_at: destinationGeneratedAt,
      sources: sources,
      totals: {{
        selected_sources: sources.length,
        regular_file_bytes: state.requiredBytes,
        execution_reserve_bytes: executionReserveBytes,
        minimum_free_bytes_required: state.executionRequiredBytes,
        regular_files: sources.reduce((sum, item) => sum + item.regular_files, 0),
        directories: sources.reduce((sum, item) => sum + item.directories, 0),
        symlinks: sources.reduce((sum, item) => sum + item.symlinks, 0),
      }},
      destination: {{
        destination_id: state.destination.destination_id,
        mountpoint: state.destination.mountpoint,
        proposed_target: targetPath,
        device: state.destination.device,
        filesystem: state.destination.filesystem,
        total_bytes: state.destination.total_bytes,
        free_bytes_before: state.destination.free_bytes,
        estimated_free_bytes_after_logical_source: state.destination.free_bytes - state.requiredBytes,
        estimated_free_bytes_beyond_minimum: state.destination.free_bytes - state.executionRequiredBytes,
      }},
      checks: {{
        no_overlapping_sources: true,
        all_sources_measured: state.allMeasured,
        destination_is_separate_filesystem: state.separateFilesystem,
        destination_capacity_sufficient: state.capacitySufficient,
        execution_reserve_included: true,
        compression_assumed_for_capacity: false,
      }},
      limitations: [
        "No snapshot directory or archive has been created.",
        "Running applications can change after measurement.",
        "Database consistency has not been established.",
        "Archive checksums and restore readiness are unavailable.",
        "The 64 MiB execution reserve is a safety minimum; actual stored archive bytes are determined during execution.",
        "This browser-generated proposal is not authoritative for execution.",
        "All evidence must be revalidated immediately before execution.",
      ],
    }};

    planBadge.textContent = "READY FOR REVIEW";
    planSummary.textContent = sources.length + " source(s) · " + state.requiredBytes.toLocaleString("en-US") + " B · destination " + state.destination.mountpoint + " · no files copied";
    manifestPreview.textContent = JSON.stringify(currentManifest, null, 2);
    manifestPreview.hidden = false;
    downloadPlanButton.disabled = false;
    const labExecutionEligible = sources.length === 1 && sources[0].source === labTestSource;
    createLabSnapshotButton.disabled = !labExecutionEligible;
    executionNote.textContent = labExecutionEligible
      ? "Restricted execution available: the server will discard this browser proposal and independently revalidate the Lab source and destination."
      : "Execution unavailable: Snapshot Lab execution permits exactly one source, /DATA/AppData/zimabrain-snapshot-lab.";
  }});

  function renderVerifiedManifest(manifest){{
    const source = manifest.source || {{}};
    const archive = manifest.archive || {{}};
    const destination = manifest.destination || {{}};
    activeVerifiedSnapshotId = String(manifest.snapshot_id || "");
    verifiedBadge.textContent = "VERIFIED";
    verifiedMessage.textContent = "Snapshot " + (activeVerifiedSnapshotId || "unknown") + " verified from its stored manifest and archive.";
    verifiedSubmessage.textContent = Number(source.regular_files || 0).toLocaleString("en-US") + " files · source device " + String(source.device || "unknown") + " · restore " + String(manifest.restore_status || "NOT TESTED");
    verifiedLogicalBytes.textContent = Number(source.regular_file_bytes || 0).toLocaleString("en-US") + " B";
    verifiedDifference.textContent = "0 B";
    verifiedArchiveBytes.textContent = Number(archive.stored_bytes || 0).toLocaleString("en-US") + " B";
    verifiedChecksum.textContent = String(archive.sha256 || "Unavailable");
    restoreBadge.textContent = "NOT TESTED";
    restoreMessage.textContent = "No isolated restore test has been verified for this snapshot.";
    restoreSubmessage.textContent = "The test will create a new path and will never overwrite the live Snapshot Lab source.";
    restoreBytes.textContent = "Unavailable";
    restoreDifference.textContent = "Unavailable";
    restoreFiles.textContent = "Unavailable";
    restoreTarget.textContent = String(destination.mountpoint || "").replace(/[/]+$/, "") + "/zimabrain-restore-tests/" + activeVerifiedSnapshotId;
    restoreNote.textContent = "Server-side verification will recheck the stored manifest and archive before creating a new isolated path.";
    restoreLabButton.textContent = "Run isolated restore test";
    restoreLabButton.disabled = !activeVerifiedSnapshotId;
  }}

  function renderVerifiedRestore(manifest){{
    const restored = manifest.restore || {{}};
    restoreBadge.textContent = "VERIFIED";
    restoreMessage.textContent = "Isolated restore for snapshot " + String(manifest.snapshot_id || "unknown") + " reverified from disk.";
    restoreSubmessage.textContent = Number(restored.regular_files || 0).toLocaleString("en-US") + " files · live source not overwritten · application not started";
    restoreBytes.textContent = Number(restored.regular_file_bytes || 0).toLocaleString("en-US") + " B";
    restoreDifference.textContent = Number(restored.difference_bytes || 0).toLocaleString("en-US") + " B";
    restoreFiles.textContent = Number(restored.regular_files || 0).toLocaleString("en-US");
    restoreTarget.textContent = String(restored.path || "Unavailable");
    restoreNote.textContent = "Persistent verification rechecks the snapshot manifest, archive SHA-256 and restored files from disk.";
    restoreLabButton.textContent = "Isolated restore verified";
    restoreLabButton.disabled = true;
  }}

  createLabSnapshotButton.addEventListener("click", async function(){{
    if (!currentManifest || currentManifest.sources.length !== 1 || currentManifest.sources[0].source !== labTestSource) return;
    const confirmed = window.confirm(
      "Create a restricted Lab snapshot now?\\n\\n" +
      "Source: " + labTestSource + "\\n" +
      "Destination: " + currentManifest.destination.mountpoint + "/zimabrain-snapshots\\n\\n" +
      "The Lab remains running. Only an isolated restore test is available after capture."
    );
    if (!confirmed) return;

    createLabSnapshotButton.disabled = true;
    createLabSnapshotButton.textContent = "Creating and verifying…";
    executionNote.textContent = "Server-side revalidation, capture and checksum comparison in progress.";

    try {{
      const response = await fetch("/api/v1/snapshot/create-lab-test", {{
        method: "POST",
        credentials: "same-origin",
        headers: {{
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfValue,
        }},
        body: JSON.stringify({{
          source_id: currentManifest.sources[0].source_id,
          destination_id: currentManifest.destination.destination_id,
        }}),
      }});
      const data = await response.json();
      if (!response.ok || data.snapshot_status !== "VERIFIED" || !data.manifest) {{
        throw new Error((data.errors || []).join("; ") || "Snapshot execution did not verify");
      }}
      renderVerifiedManifest(data.manifest);
      planBadge.textContent = "EXECUTED";
      planSummary.textContent = "Restricted Lab snapshot created and independently verified. An isolated restore test is now available.";
      executionNote.textContent = "Verified archive created. The stored archive SHA-256 and per-file checksums match the captured source.";
      createLabSnapshotButton.textContent = "Verified Lab snapshot created";
    }} catch (error) {{
      planBadge.textContent = "EXECUTION FAILED";
      planSummary.textContent = String(error.message || error);
      executionNote.textContent = "No verified snapshot was accepted. Review the reported failure before retrying.";
      createLabSnapshotButton.textContent = "Create verified Lab snapshot";
      createLabSnapshotButton.disabled = false;
    }}
  }});

  restoreLabButton.addEventListener("click", async function(){{
    if (!activeVerifiedSnapshotId) return;
    const target = restoreTarget.textContent;
    const confirmed = window.confirm(
      "Run the isolated restore test now?\\n\\n" +
      "Snapshot: " + activeVerifiedSnapshotId + "\\n" +
      "New target: " + target + "\\n\\n" +
      "The live Snapshot Lab source will not be overwritten. Existing restore paths are never replaced."
    );
    if (!confirmed) return;

    restoreLabButton.disabled = true;
    restoreLabButton.textContent = "Restoring and verifying…";
    restoreBadge.textContent = "RUNNING";
    restoreMessage.textContent = "Server-side snapshot revalidation and isolated extraction are in progress.";
    restoreNote.textContent = "Every restored file will be compared with the captured manifest before completion is accepted.";

    try {{
      const response = await fetch("/api/v1/snapshot/restore-lab-test", {{
        method: "POST",
        credentials: "same-origin",
        headers: {{
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfValue,
        }},
        body: JSON.stringify({{snapshot_id: activeVerifiedSnapshotId}}),
      }});
      const data = await response.json();
      if (!response.ok || data.restore_status !== "VERIFIED" || !data.manifest) {{
        throw new Error((data.errors || []).join("; ") || "Isolated restore test did not verify");
      }}
      renderVerifiedRestore(data.manifest);
    }} catch (error) {{
      restoreBadge.textContent = "NOT VERIFIED";
      restoreMessage.textContent = String(error.message || error);
      restoreSubmessage.textContent = "No restore result was accepted. The live source was not selected as a restore target.";
      restoreNote.textContent = "Review the reported failure before retrying.";
      restoreLabButton.textContent = "Run isolated restore test";
      restoreLabButton.disabled = false;
    }}
  }});

  downloadPlanButton.addEventListener("click", function(){{
    if (!currentManifest) return;
    const payload = JSON.stringify(currentManifest, null, 2) + "\\n";
    const blob = new Blob([payload], {{type: "application/json"}});
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "zimabrain-snapshot-plan-" + currentManifest.created_at.replace(/[:.]/g, "-") + ".json";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }});

  refreshDestinationDetail();
  syncSelectionState();
}})();
</script>
</main></body></html>"""
