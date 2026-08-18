"""Restricted, verifier-first snapshot execution for the Snapshot Lab."""

from datetime import datetime, timezone
import json
import os
import secrets

from brain import snapshot_inventory
from brain import recovery_readiness
from brain import recovery_completion


LAB_TEST_SOURCE = "/DATA/AppData/zimabrain-snapshot-lab"
FULL_APPDATA_SOURCE = "/DATA/AppData"
CASAOS_APPS_SOURCE = "/var/lib/casaos/apps"
SNAPSHOT_DIRECTORY_NAME = "zimabrain-snapshots"
FULL_SNAPSHOT_DIRECTORY_NAME = "zimabrain-full-snapshots"
MAX_LAB_SOURCE_BYTES = 256 * 1024 * 1024
MAX_FULL_SOURCE_BYTES = 64 * 1024 * 1024 * 1024
MAX_APP_DEFINITION_BYTES = 256 * 1024 * 1024
MAX_NAMED_VOLUME_BYTES = 64 * 1024 * 1024 * 1024
MINIMUM_OVERHEAD_BYTES = 64 * 1024 * 1024
RECONSTRUCTION_HANDOFF_CONTAINER_DIRECTORY = "/data"
RECONSTRUCTION_HANDOFF_HOST_DIRECTORY = "/DATA/AppData/zimabrain-snapshot-lab"


def generate_snapshot_id():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)


CREATE_SNAPSHOT_SCRIPT = r'''import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone

source = sys.argv[1]
destination = sys.argv[2]
snapshot_id = sys.argv[3]
expected_source_device = sys.argv[4]
expected_destination_device = sys.argv[5]
expected_logical_bytes = int(sys.argv[6])
expected_source = sys.argv[7]
snapshot_directory_name = sys.argv[8]
snapshot_mode = sys.argv[9]
component_source = sys.argv[10] if len(sys.argv) > 10 else ""
expected_component_device = sys.argv[11] if len(sys.argv) > 11 else ""
expected_component_bytes = int(sys.argv[12]) if len(sys.argv) > 12 else 0
named_volume_plan = json.loads(sys.argv[13]) if len(sys.argv) > 13 else []
expected_source_files = int(sys.argv[14]) if len(sys.argv) > 14 else 0
expected_component_files = int(sys.argv[15]) if len(sys.argv) > 15 else 0
reconstruction_handoff_path = sys.argv[16] if len(sys.argv) > 16 else ""
external_bind_plan = json.loads(sys.argv[17]) if len(sys.argv) > 17 else []
reconstruction_evidence = {}
MINIMUM_OVERHEAD_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024

result = {
    "mode": "restricted-lab-snapshot-execution",
    "execution_status": "FAILED",
    "snapshot_status": "NOT CREATED",
    "verification_status": "NOT VERIFIED",
    "snapshot_id": snapshot_id,
    "errors": [],
}
pending_path = ""
base_path = ""
base_created = False
progress_path = ""
progress_state = None
progress_started = 0.0
progress_last_write = 0.0


def publish_progress(force=False):
    global progress_last_write
    if not progress_path or progress_state is None:
        return
    now = time.monotonic()
    if not force and now - progress_last_write < 0.5:
        return
    elapsed = max(0.0, now - progress_started)
    processed = int(progress_state["work_bytes_processed"])
    total = max(1, int(progress_state["work_bytes_total"]))
    percent = min(99.9, processed * 100.0 / total)
    if progress_state["status"] == "VERIFIED":
        percent = 100.0
    progress_state.update({
        "percent": round(percent, 1),
        "elapsed_seconds": round(elapsed, 1),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })
    temporary = progress_path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(progress_state, handle, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, progress_path)
    progress_last_write = now


def initialize_progress(path, identifier, logical_total, files_total):
    global progress_path, progress_state, progress_started, progress_last_write
    progress_path = path
    progress_started = time.monotonic()
    progress_last_write = 0.0
    logical_total = max(0, int(logical_total))
    progress_state = {
        "schema": "zimabrain.snapshot-progress.v1",
        "snapshot_id": identifier,
        "status": "RUNNING",
        "phase": "Revalidating capture sources",
        "work_bytes_processed": 0,
        "work_bytes_total": max(1, logical_total * 5),
        "captured_bytes": 0,
        "logical_bytes_total": logical_total,
        "files_processed": 0,
        "files_total": max(
            0,
            int(files_total) * 4
            + 2
            + len(named_volume_plan)
            + len(external_bind_plan),
        ),
        "error": "",
    }
    publish_progress(force=True)


def set_progress_phase(phase):
    if progress_state is not None:
        progress_state["phase"] = str(phase)
        publish_progress(force=True)


def advance_work(byte_count, captured_bytes=0):
    if progress_state is not None:
        progress_state["work_bytes_processed"] += max(0, int(byte_count))
        progress_state["captured_bytes"] += max(0, int(captured_bytes))
        publish_progress()


def record_processed_file():
    if progress_state is not None:
        progress_state["files_processed"] += 1
        publish_progress()


def finish_progress(status, phase, error=""):
    if progress_state is not None:
        progress_state["status"] = str(status)
        progress_state["phase"] = str(phase)
        progress_state["error"] = str(error)
        if status == "VERIFIED":
            progress_state["work_bytes_processed"] = progress_state["work_bytes_total"]
            progress_state["captured_bytes"] = progress_state["logical_bytes_total"]
            progress_state["files_processed"] = progress_state["files_total"]
        publish_progress(force=True)


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


def path_is_under(path, parent):
    clean_path = os.path.normpath(path)
    clean_parent = os.path.normpath(parent)
    return clean_path == clean_parent or clean_path.startswith(clean_parent.rstrip("/") + "/")


def paths_overlap(left, right):
    return path_is_under(left, right) or path_is_under(right, left)


def read_mounts():
    rows = []
    with open("/proc/self/mountinfo", "r", encoding="utf-8") as handle:
        for line in handle:
            left, right = line.rstrip("\n").split(" - ", 1)
            fields = left.split()
            filesystem = right.split()
            mountpoint = decode_mount_path(fields[4]).rstrip("/") or "/"
            rows.append({
                "mountpoint": mountpoint,
                "device": fields[2],
                "filesystem": filesystem[0] if filesystem else "",
                "source": decode_mount_path(filesystem[1]) if len(filesystem) > 1 else "",
            })
    return rows

MOUNTS = read_mounts()

def resolve_mount(path):
    matches = [item for item in MOUNTS if path_is_under(path, item["mountpoint"])]
    if not matches:
        raise RuntimeError(f"No host mount resolves path: {path}")
    return max(matches, key=lambda item: len(item["mountpoint"]))


def hash_file(path):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            advance_work(len(chunk))
    return digest.hexdigest(), size


def entry_signature(path, relative_path, root_device, allow_volatile=False):
    before = os.lstat(path)
    common = {
        "relative_path": relative_path,
        "mode": stat.S_IMODE(before.st_mode),
        "uid": before.st_uid,
        "gid": before.st_gid,
        "mtime_ns": before.st_mtime_ns,
    }

    # A symlink is archive metadata, not a request to scan its target.  Check
    # it before canonical mount resolution so broken links and links whose
    # targets are on another filesystem remain safe, non-followed entries.
    if stat.S_ISLNK(before.st_mode):
        common["type"] = "symlink"
        common["link_target"] = os.readlink(path)
        return common, "symlink"

    entry_mount = resolve_mount(os.path.realpath(path))
    if entry_mount["device"] != root_device:
        return None, "boundary"

    if stat.S_ISDIR(before.st_mode):
        common["type"] = "directory"
        return common, "directory"
    if stat.S_ISREG(before.st_mode):
        checksum, byte_count = hash_file(path)
        after = os.lstat(path)
        stable_fields = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_mode,
            before.st_uid,
            before.st_gid,
        )
        after_fields = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_mode,
            after.st_uid,
            after.st_gid,
        )
        if stable_fields != after_fields or byte_count != before.st_size:
            raise RuntimeError(f"Source changed while hashing: {relative_path}")
        common.update({
            "type": "file",
            "size": before.st_size,
            "sha256": checksum,
        })
        return common, "file"

    if allow_volatile and (stat.S_ISFIFO(before.st_mode) or stat.S_ISSOCK(before.st_mode)):
        return None, "volatile"

    common["type"] = "special"
    return common, "special"


def scan_source(path, allow_volatile=False):
    root_stat = os.lstat(path)
    if not stat.S_ISDIR(root_stat.st_mode):
        raise RuntimeError("The restricted Lab source is not a directory.")

    root_device = resolve_mount(os.path.realpath(path))["device"]
    entries = []
    pending = [(path, ".")]
    boundaries = 0
    special_entries = 0
    volatile_entries_skipped = 0
    volatile_paths = []

    while pending:
        current, relative = pending.pop()
        signature, entry_type = entry_signature(current, relative, root_device, allow_volatile=allow_volatile)
        if entry_type == "boundary":
            boundaries += 1
            continue
        if entry_type == "volatile":
            volatile_entries_skipped += 1
            if len(volatile_paths) < 50:
                volatile_paths.append(relative)
            continue
        entries.append(signature)
        if entry_type == "file":
            record_processed_file()
        if entry_type == "special":
            special_entries += 1
        if entry_type == "directory":
            with os.scandir(current) as children:
                ordered = sorted(children, key=lambda item: item.name, reverse=True)
                for child in ordered:
                    child_relative = child.name if relative == "." else relative + "/" + child.name
                    pending.append((child.path, child_relative))

    entries.sort(key=lambda item: item["relative_path"])
    files = [item for item in entries if item["type"] == "file"]
    return {
        "entries": entries,
        "regular_file_bytes": sum(item["size"] for item in files),
        "regular_files": len(files),
        "directories": sum(item["type"] == "directory" for item in entries),
        "symlinks": sum(item["type"] == "symlink" for item in entries),
        "special_entries": special_entries,
        "mount_boundaries_skipped": boundaries,
        "volatile_entries_skipped": volatile_entries_skipped,
        "volatile_paths": volatile_paths,
    }


def archive_source(path, scan, archive_path, archive_root="data"):
    with tarfile.open(
        archive_path,
        mode="w",
        format=tarfile.PAX_FORMAT,
        dereference=False,
    ) as archive:
        for item in scan["entries"]:
            relative = item["relative_path"]
            source_path = path if relative == "." else os.path.join(path, *relative.split("/"))
            archive_name = archive_root if relative == "." else archive_root + "/" + relative
            archive.add(source_path, arcname=archive_name, recursive=False)
            if item["type"] == "file":
                advance_work(item["size"], captured_bytes=item["size"])
                record_processed_file()


def archive_entry_signature(archive, member, archive_root="data"):
    name = member.name.rstrip("/")
    relative = "." if name == archive_root else name[len(archive_root + "/"):]
    common = {
        "relative_path": relative,
        "mode": member.mode,
        "uid": member.uid,
        "gid": member.gid,
        "mtime_ns": int(float(member.mtime) * 1_000_000_000),
    }
    if member.isdir():
        common["type"] = "directory"
    elif member.issym():
        common["type"] = "symlink"
        common["link_target"] = member.linkname
    elif member.isfile() or member.islnk():
        extracted = archive.extractfile(member)
        if extracted is None:
            raise RuntimeError(f"Archive file cannot be read: {relative}")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = extracted.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            advance_work(len(chunk))
        common.update({
            "type": "file",
            "size": size,
            "sha256": digest.hexdigest(),
        })
        record_processed_file()
    else:
        common["type"] = "special"
    return common


def verify_archive(archive_path, expected_entries, archive_root="data"):
    expected = {item["relative_path"]: item for item in expected_entries}
    actual = {}
    with tarfile.open(archive_path, mode="r") as archive:
        for member in archive.getmembers():
            name = member.name.rstrip("/")
            if name != archive_root and not name.startswith(archive_root + "/"):
                raise RuntimeError(f"Archive contains an unexpected root: {member.name}")
            signature = archive_entry_signature(archive, member, archive_root=archive_root)
            relative = signature["relative_path"]
            if relative in actual:
                raise RuntimeError(f"Archive contains a duplicate entry: {relative}")
            actual[relative] = signature

    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        raise RuntimeError(f"Archive entry mismatch; missing={missing[:5]} extra={extra[:5]}")

    for relative, source_entry in expected.items():
        archive_entry = actual[relative]
        for key in ("type", "mode", "uid", "gid"):
            if archive_entry.get(key) != source_entry.get(key):
                raise RuntimeError(f"Archive metadata mismatch for {relative}: {key}")
        if source_entry["type"] == "file":
            for key in ("size", "sha256"):
                if archive_entry.get(key) != source_entry.get(key):
                    raise RuntimeError(f"Archive file mismatch for {relative}: {key}")
        elif source_entry["type"] == "symlink":
            if archive_entry.get("link_target") != source_entry.get("link_target"):
                raise RuntimeError(f"Archive symlink mismatch for {relative}")
        source_second = source_entry.get("mtime_ns", 0) // 1_000_000_000
        archive_second = archive_entry.get("mtime_ns", 0) // 1_000_000_000
        if source_second != archive_second:
            raise RuntimeError(f"Archive timestamp mismatch for {relative}")
    return True


def fsync_file(path):
    with open(path, "rb") as handle:
        os.fsync(handle.fileno())


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def verify_database_quiescence(evidence):
    completion = (evidence or {}).get("recovery_completion_plan") or {}
    gate = completion.get("database_gate") or {}
    records = gate.get("containers") or []
    if gate.get("status") != "VERIFIED":
        raise RuntimeError("Database quiescence evidence is not verified.")
    identifiers = [str(item.get("container_id") or "") for item in records]
    if not identifiers:
        return
    if any(not value for value in identifiers) or len(identifiers) != len(set(identifiers)):
        raise RuntimeError("Database quiescence identities are invalid or duplicated.")
    inspected = json.loads(subprocess.check_output(
        ["docker", "inspect", *identifiers],
        text=True,
        timeout=60,
    ))
    by_id = {str(item.get("Id") or ""): item for item in inspected}
    for expected in records:
        identifier = str(expected.get("container_id") or "")
        current = by_id.get(identifier)
        if not current:
            raise RuntimeError("A database container disappeared during capture.")
        state = current.get("State") or {}
        if (
            str(state.get("Status") or "") not in {"exited", "created"}
            or bool(state.get("Running"))
            or bool(state.get("Paused"))
            or int(state.get("ExitCode", 0) or 0) != 0
            or str(state.get("StartedAt") or "") != str(expected.get("started_at") or "")
            or str(state.get("FinishedAt") or "") != str(expected.get("finished_at") or "")
        ):
            raise RuntimeError(
                "Database container changed state during capture: "
                + str(expected.get("container") or identifier[:12])
            )


def collect_xattr_metadata(root, entries):
    records = []
    for entry in entries:
        relative = str(entry.get("relative_path") or "")
        if not relative:
            raise RuntimeError("Filesystem metadata entry has no relative path.")
        path = root if relative == "." else os.path.join(root, relative)
        attributes = {}
        try:
            names = os.listxattr(path, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError(
                "Extended attributes could not be read: " + relative + ": " + str(exc)
            ) from exc
        for name in sorted(names):
            try:
                value = os.getxattr(path, name, follow_symlinks=False)
            except OSError as exc:
                raise RuntimeError(
                    "Extended attribute changed or became unreadable: "
                    + relative + ": " + name + ": " + str(exc)
                ) from exc
            attributes[name] = base64.b64encode(value).decode("ascii")
        if attributes:
            records.append({
                "relative_path": relative,
                "attributes": attributes,
            })
    return records


try:
    if reconstruction_handoff_path:
        handoff_parent = "/DATA/AppData/zimabrain-snapshot-lab"
        if (
            not reconstruction_handoff_path.startswith(
                handoff_parent + "/.reconstruction-handoff-"
            )
            or os.path.dirname(reconstruction_handoff_path) != handoff_parent
        ):
            raise RuntimeError("Private reconstruction handoff path is unauthorized.")
        handoff_info = os.lstat(reconstruction_handoff_path)
        if (
            not stat.S_ISREG(handoff_info.st_mode)
            or stat.S_ISLNK(handoff_info.st_mode)
            or stat.S_IMODE(handoff_info.st_mode) & 0o077
            or handoff_info.st_size > 16 * 1024 * 1024
        ):
            raise RuntimeError("Private reconstruction handoff is not a safe regular file.")
        with open(reconstruction_handoff_path, "r", encoding="utf-8") as handle:
            reconstruction_evidence = json.load(handle)
        os.unlink(reconstruction_handoff_path)
    if source != expected_source:
        raise RuntimeError("Snapshot source differs from the server-authorized source.")
    if snapshot_directory_name not in ("zimabrain-snapshots", "zimabrain-full-snapshots"):
        raise RuntimeError("Snapshot directory class is not authorized.")
    if not os.path.isabs(source) or not os.path.isabs(destination):
        raise RuntimeError("Source and destination must be absolute host paths.")
    if not snapshot_id or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in snapshot_id):
        raise RuntimeError("Snapshot identifier is invalid.")

    source_resolved = os.path.realpath(source)
    destination_resolved = os.path.realpath(destination)
    source_mount = resolve_mount(source_resolved)
    destination_mount = resolve_mount(destination_resolved)
    component_resolved = os.path.realpath(component_source) if component_source else ""
    component_mount = resolve_mount(component_resolved) if component_resolved else None
    if not isinstance(named_volume_plan, list) or len(named_volume_plan) > 512:
        raise RuntimeError("Docker named-volume preflight plan is invalid.")
    if reconstruction_evidence:
        if not isinstance(reconstruction_evidence, dict):
            raise RuntimeError("Reconstruction evidence is not an object.")
        if reconstruction_evidence.get("schema") != "zimabrain.reconstruction-evidence.v1":
            raise RuntimeError("Reconstruction evidence schema is invalid.")
        if reconstruction_evidence.get("capture_status") != "VERIFIED":
            raise RuntimeError("Reconstruction evidence was not fully verified.")
        verify_database_quiescence(reconstruction_evidence)
    named_volume_contexts = []
    seen_volume_names = set()
    seen_volume_paths = set()
    for volume in named_volume_plan:
        if not isinstance(volume, dict):
            raise RuntimeError("Docker named-volume preflight contains a non-object record.")
        volume_name = str(volume.get("name") or "")
        requested_path = str(volume.get("requested_path") or "")
        expected_resolved_path = str(volume.get("resolved_path") or "")
        if (
            not volume_name
            or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for character in volume_name)
            or volume_name in seen_volume_names
        ):
            raise RuntimeError("Docker named-volume identity is invalid or duplicated.")
        if not os.path.isabs(requested_path) or not expected_resolved_path:
            raise RuntimeError(f"Docker named volume {volume_name} has an invalid source path.")
        resolved_path = os.path.realpath(requested_path)
        if resolved_path != expected_resolved_path or any(
            paths_overlap(resolved_path, existing_path)
            for existing_path in seen_volume_paths
        ):
            raise RuntimeError(f"Docker named volume {volume_name} changed path or duplicates another source.")
        volume_mount = resolve_mount(resolved_path)
        if volume_mount["device"] != str(volume.get("device") or ""):
            raise RuntimeError(f"Docker named volume {volume_name} changed filesystem device after preflight.")
        if volume_mount["device"] == destination_mount["device"]:
            raise RuntimeError(f"Docker named volume {volume_name} and destination use the same filesystem device.")
        seen_volume_names.add(volume_name)
        seen_volume_paths.add(resolved_path)
        named_volume_contexts.append({
            "plan": volume,
            "name": volume_name,
            "requested_path": requested_path,
            "resolved_path": resolved_path,
            "mount": volume_mount,
        })

    if not isinstance(external_bind_plan, list) or len(external_bind_plan) > 256:
        raise RuntimeError("External bind preflight plan is invalid.")
    external_bind_contexts = []
    seen_external_paths = set()
    for index, external in enumerate(external_bind_plan):
        if not isinstance(external, dict):
            raise RuntimeError("External bind preflight contains a non-object record.")
        requested_path = str(external.get("requested_path") or "")
        expected_resolved_path = str(external.get("resolved_path") or "")
        if not os.path.isabs(requested_path) or not expected_resolved_path:
            raise RuntimeError("External bind source path is invalid.")
        resolved_path = os.path.realpath(requested_path)
        if (
            resolved_path != expected_resolved_path
            or resolved_path == "/"
            or not resolved_path.startswith(("/DATA/", "/media/", "/mnt/"))
            or paths_overlap(resolved_path, source_resolved)
            or (component_resolved and paths_overlap(resolved_path, component_resolved))
            or any(paths_overlap(resolved_path, value) for value in seen_external_paths)
        ):
            raise RuntimeError("External bind source changed, overlaps protected scope or is unsafe.")
        external_mount = resolve_mount(resolved_path)
        if external_mount["device"] != str(external.get("device") or ""):
            raise RuntimeError("External bind filesystem device changed after preflight.")
        if external_mount["device"] == destination_mount["device"]:
            raise RuntimeError("External bind and snapshot destination use the same filesystem device.")
        seen_external_paths.add(resolved_path)
        external_bind_contexts.append({
            "plan": external,
            "index": index,
            "requested_path": requested_path,
            "resolved_path": resolved_path,
            "mount": external_mount,
        })

    if destination_resolved != destination_mount["mountpoint"]:
        raise RuntimeError("Destination no longer resolves to the selected mountpoint.")
    if source_mount["device"] != expected_source_device:
        raise RuntimeError("Source filesystem device changed after preflight.")
    if destination_mount["device"] != expected_destination_device:
        raise RuntimeError("Destination filesystem device changed after preflight.")
    if source_mount["device"] == destination_mount["device"]:
        raise RuntimeError("Source and destination use the same filesystem device.")
    if component_source:
        if component_source != "/var/lib/casaos/apps" or component_resolved != component_source:
            raise RuntimeError("Recovery component source is not authorized or canonical.")
        if component_mount["device"] != expected_component_device:
            raise RuntimeError("App-definition filesystem device changed after preflight.")
        if component_mount["device"] == destination_mount["device"]:
            raise RuntimeError("App definitions and destination use the same filesystem device.")

    base_path = os.path.join(destination_resolved, snapshot_directory_name)
    final_path = os.path.join(base_path, snapshot_id)
    pending_path = os.path.join(base_path, ".pending-" + snapshot_id)
    if paths_overlap(source_resolved, base_path):
        raise RuntimeError("Snapshot target overlaps the resolved source path.")
    if component_resolved and paths_overlap(component_resolved, base_path):
        raise RuntimeError("Snapshot target overlaps the app-definition source path.")
    for volume in named_volume_contexts:
        if paths_overlap(volume["resolved_path"], source_resolved):
            raise RuntimeError(f"Docker named volume {volume['name']} overlaps the AppData source.")
        if component_resolved and paths_overlap(volume["resolved_path"], component_resolved):
            raise RuntimeError(f"Docker named volume {volume['name']} overlaps the app-definition source.")
        if paths_overlap(volume["resolved_path"], base_path):
            raise RuntimeError(f"Snapshot target overlaps Docker named volume {volume['name']}.")
    for external in external_bind_contexts:
        if paths_overlap(external["resolved_path"], base_path):
            raise RuntimeError("Snapshot target overlaps a selected external bind source.")

    if os.path.lexists(base_path):
        if os.path.islink(base_path) or not os.path.isdir(base_path):
            raise RuntimeError("Snapshot base path is not a safe directory.")
    else:
        os.mkdir(base_path, 0o700)
        base_created = True
    progress_path = os.path.join(base_path, ".progress-" + snapshot_id + ".json")
    if os.path.lexists(progress_path):
        raise RuntimeError("Snapshot progress identity already exists on the destination.")
    total_logical_bytes = (
        expected_logical_bytes
        + expected_component_bytes
        + sum(int(item["plan"].get("regular_file_bytes", 0) or 0) for item in named_volume_contexts)
        + sum(int(item["plan"].get("regular_file_bytes", 0) or 0) for item in external_bind_contexts)
    )
    total_regular_files = (
        expected_source_files
        + expected_component_files
        + sum(int(item["plan"].get("regular_files", 0) or 0) for item in named_volume_contexts)
        + sum(int(item["plan"].get("regular_files", 0) or 0) for item in external_bind_contexts)
    )
    initialize_progress(progress_path, snapshot_id, total_logical_bytes, total_regular_files)

    allow_volatile = snapshot_directory_name == "zimabrain-full-snapshots"
    set_progress_phase("Revalidating AppData")
    source_before = scan_source(source_resolved, allow_volatile=allow_volatile)
    set_progress_phase("Revalidating Custom App definitions")
    component_before = scan_source(component_resolved) if component_resolved else None
    named_volume_before = []
    for volume in named_volume_contexts:
        set_progress_phase("Revalidating Docker volume " + volume["name"])
        volume_scan = scan_source(volume["resolved_path"], allow_volatile=True)
        expected_bytes = int(volume["plan"].get("regular_file_bytes", -1))
        expected_files = int(volume["plan"].get("regular_files", -1))
        expected_volatile = int(volume["plan"].get("volatile_entries_skipped", -1))
        if volume_scan["regular_file_bytes"] != expected_bytes or volume_scan["regular_files"] != expected_files:
            raise RuntimeError(f"Docker named volume {volume['name']} changed after server preflight.")
        if volume_scan["volatile_entries_skipped"] != expected_volatile:
            raise RuntimeError(f"Docker named volume {volume['name']} runtime-entry set changed after server preflight.")
        if volume_scan["special_entries"] or volume_scan["mount_boundaries_skipped"]:
            raise RuntimeError(f"Docker named volume {volume['name']} contains unsupported entries or filesystem boundaries.")
        named_volume_before.append({**volume, "scan": volume_scan})
    external_bind_before = []
    for external in external_bind_contexts:
        set_progress_phase("Revalidating selected external bind")
        external_scan = scan_source(external["resolved_path"], allow_volatile=True)
        if (
            external_scan["regular_file_bytes"]
            != int(external["plan"].get("regular_file_bytes", -1))
            or external_scan["regular_files"]
            != int(external["plan"].get("regular_files", -1))
            or external_scan["volatile_entries_skipped"]
            != int(external["plan"].get("volatile_entries_skipped", -1))
        ):
            raise RuntimeError("Selected external bind changed after server preflight.")
        if external_scan["special_entries"] or external_scan["mount_boundaries_skipped"]:
            raise RuntimeError("Selected external bind contains unsupported entries or filesystem boundaries.")
        external_bind_before.append({**external, "scan": external_scan})
    def capture_filesystem_metadata():
        return {
            "schema": "zimabrain.filesystem-metadata.v1",
            "sensitivity": "PRIVATE_FILESYSTEM_METADATA",
            "components": {
                "appdata": collect_xattr_metadata(source_resolved, source_before["entries"]),
                "casaos_apps": (
                    collect_xattr_metadata(component_resolved, component_before["entries"])
                    if component_before
                    else []
                ),
                "docker_named_volumes": [
                    {
                        "name": volume["name"],
                        "records": collect_xattr_metadata(
                            volume["resolved_path"], volume["scan"]["entries"]
                        ),
                    }
                    for volume in named_volume_before
                ],
                "selected_external_binds": [
                    {
                        "requested_path": external["requested_path"],
                        "records": collect_xattr_metadata(
                            external["resolved_path"], external["scan"]["entries"]
                        ),
                    }
                    for external in external_bind_before
                ],
            },
        }
    set_progress_phase("Recording initial ACL and extended-attribute metadata")
    filesystem_metadata_before = capture_filesystem_metadata()
    if source_before["regular_file_bytes"] != expected_logical_bytes:
        raise RuntimeError("Source logical bytes changed after server preflight.")
    if source_before["special_entries"]:
        raise RuntimeError("Unsupported special filesystem entries remain in the source.")
    if source_before["mount_boundaries_skipped"]:
        raise RuntimeError("Nested mount boundaries are not supported by the All AppData snapshot.")
    if component_before:
        if component_before["regular_file_bytes"] != expected_component_bytes:
            raise RuntimeError("App-definition bytes changed after server preflight.")
        if component_before["special_entries"] or component_before["mount_boundaries_skipped"]:
            raise RuntimeError("App definitions contain unsupported entries or filesystem boundaries.")

    stats_before = os.statvfs(destination_resolved)
    free_before = stats_before.f_bavail * stats_before.f_frsize
    required_free = (
        source_before["regular_file_bytes"]
        + (component_before or {}).get("regular_file_bytes", 0)
        + sum(item["scan"]["regular_file_bytes"] for item in named_volume_before)
        + sum(item["scan"]["regular_file_bytes"] for item in external_bind_before)
        + MINIMUM_OVERHEAD_BYTES
    )
    if free_before < required_free:
        raise RuntimeError("Destination free capacity no longer satisfies the execution reserve.")

    if os.path.lexists(final_path) or os.path.lexists(pending_path):
        raise RuntimeError("Snapshot identifier already exists on the destination.")
    os.mkdir(pending_path, 0o700)

    reconstruction_path = ""
    reconstruction_sha256 = ""
    reconstruction_bytes = 0
    if reconstruction_evidence:
        reconstruction_path = os.path.join(
            pending_path,
            "reconstruction-evidence.private.json",
        )
        set_progress_phase("Recording private reconstruction evidence")
        with open(reconstruction_path, "x", encoding="utf-8") as handle:
            json.dump(reconstruction_evidence, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(reconstruction_path, 0o600)
        reconstruction_sha256, reconstruction_bytes = hash_file(
            reconstruction_path
        )
        if reconstruction_bytes > 16 * 1024 * 1024:
            raise RuntimeError("Private reconstruction evidence exceeds 16 MiB.")
        record_processed_file()

    archive_path = os.path.join(pending_path, "snapshot.tar")
    set_progress_phase("Capturing AppData archive")
    archive_source(source_resolved, source_before, archive_path)
    fsync_file(archive_path)
    component_archive_path = ""
    if component_before:
        component_archive_path = os.path.join(pending_path, "casaos-apps.tar")
        set_progress_phase("Capturing Custom App definitions")
        archive_source(component_resolved, component_before, component_archive_path, archive_root="casaos-apps")
        fsync_file(component_archive_path)
    named_volume_archives = []
    for index, volume in enumerate(named_volume_before):
        filename = f"docker-volume-{index:04d}.tar"
        volume_archive_path = os.path.join(pending_path, filename)
        set_progress_phase("Capturing Docker volume " + volume["name"])
        archive_source(
            volume["resolved_path"],
            volume["scan"],
            volume_archive_path,
            archive_root="volume-data",
        )
        fsync_file(volume_archive_path)
        named_volume_archives.append({**volume, "archive_filename": filename, "archive_path": volume_archive_path})
    external_bind_archives = []
    for index, external in enumerate(external_bind_before):
        filename = f"external-bind-{index:04d}.tar"
        archive_path_external = os.path.join(pending_path, filename)
        set_progress_phase("Capturing selected external bind")
        archive_source(
            external["resolved_path"],
            external["scan"],
            archive_path_external,
            archive_root="external-data",
        )
        fsync_file(archive_path_external)
        external_bind_archives.append({
            **external,
            "archive_filename": filename,
            "archive_path": archive_path_external,
        })

    set_progress_phase("Checking AppData stability")
    source_after = scan_source(source_resolved, allow_volatile=allow_volatile)
    set_progress_phase("Checking Custom App definition stability")
    component_after = scan_source(component_resolved) if component_resolved else None
    named_volume_after = {}
    for volume in named_volume_before:
        set_progress_phase("Checking Docker volume stability: " + volume["name"])
        named_volume_after[volume["name"]] = scan_source(
            volume["resolved_path"], allow_volatile=True
        )
    external_bind_after = {}
    for external in external_bind_before:
        set_progress_phase("Checking selected external bind stability")
        external_bind_after[external["resolved_path"]] = scan_source(
            external["resolved_path"], allow_volatile=True
        )
    if source_before != source_after:
        raise RuntimeError("Source content changed during snapshot creation.")
    if component_before != component_after:
        raise RuntimeError("App definitions changed during snapshot creation.")
    for volume in named_volume_before:
        if volume["scan"] != named_volume_after.get(volume["name"]):
            raise RuntimeError(f"Docker named volume {volume['name']} changed during snapshot creation.")
    for external in external_bind_before:
        if external["scan"] != external_bind_after.get(external["resolved_path"]):
            raise RuntimeError("Selected external bind changed during snapshot creation.")
    if reconstruction_evidence:
        set_progress_phase("Rechecking database quiescence")
        verify_database_quiescence(reconstruction_evidence)
    set_progress_phase("Rechecking ACL and extended-attribute stability")
    filesystem_metadata = capture_filesystem_metadata()
    if filesystem_metadata != filesystem_metadata_before:
        raise RuntimeError(
            "ACL or extended-attribute metadata changed during snapshot creation."
        )
    metadata_path = os.path.join(pending_path, "filesystem-metadata.private.json")
    with open(metadata_path, "x", encoding="utf-8") as handle:
        json.dump(filesystem_metadata, handle, separators=(",", ":"), sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(metadata_path, 0o600)
    if os.path.getsize(metadata_path) > 64 * 1024 * 1024:
        raise RuntimeError("Filesystem metadata sidecar exceeds 64 MiB.")
    set_progress_phase("Verifying AppData archive")
    verify_archive(archive_path, source_before["entries"])
    if component_before:
        set_progress_phase("Verifying Custom App definition archive")
        verify_archive(component_archive_path, component_before["entries"], archive_root="casaos-apps")
    for volume in named_volume_archives:
        set_progress_phase("Verifying Docker volume archive: " + volume["name"])
        verify_archive(volume["archive_path"], volume["scan"]["entries"], archive_root="volume-data")
    for external in external_bind_archives:
        set_progress_phase("Verifying selected external bind archive")
        verify_archive(
            external["archive_path"],
            external["scan"]["entries"],
            archive_root="external-data",
        )

    set_progress_phase("Recording archive checksums")
    metadata_sha256, metadata_bytes = hash_file(metadata_path)
    record_processed_file()
    archive_sha256, archive_bytes = hash_file(archive_path)
    record_processed_file()
    component_archive_sha256, component_archive_bytes = hash_file(component_archive_path) if component_archive_path else ("", 0)
    if component_archive_path:
        record_processed_file()
    named_volume_records = []
    for volume in named_volume_archives:
        volume_sha256, volume_archive_bytes = hash_file(volume["archive_path"])
        record_processed_file()
        plan = volume["plan"]
        scan = volume["scan"]
        named_volume_records.append({
            "name": volume["name"],
            "driver": str(plan.get("driver") or ""),
            "scope": str(plan.get("scope") or ""),
            "labels": plan.get("labels") if isinstance(plan.get("labels"), dict) else {},
            "options": plan.get("options") if isinstance(plan.get("options"), dict) else {},
            "requested_path": volume["requested_path"],
            "resolved_path": volume["resolved_path"],
            "device": volume["mount"]["device"],
            "filesystem": volume["mount"]["filesystem"],
            "mountpoint": volume["mount"]["mountpoint"],
            "archive_filename": volume["archive_filename"],
            "stored_bytes": volume_archive_bytes,
            "sha256": volume_sha256,
            "regular_file_bytes": scan["regular_file_bytes"],
            "regular_files": scan["regular_files"],
            "directories": scan["directories"],
            "symlinks": scan["symlinks"],
            "volatile_entries_skipped": scan["volatile_entries_skipped"],
            "volatile_paths": scan["volatile_paths"],
            "entries": scan["entries"],
        })
    external_bind_records = []
    for external in external_bind_archives:
        external_sha256, external_archive_bytes = hash_file(external["archive_path"])
        record_processed_file()
        scan = external["scan"]
        external_bind_records.append({
            "requested_path": external["requested_path"],
            "resolved_path": external["resolved_path"],
            "device": external["mount"]["device"],
            "filesystem": external["mount"]["filesystem"],
            "mountpoint": external["mount"]["mountpoint"],
            "archive_filename": external["archive_filename"],
            "stored_bytes": external_archive_bytes,
            "sha256": external_sha256,
            "regular_file_bytes": scan["regular_file_bytes"],
            "regular_files": scan["regular_files"],
            "directories": scan["directories"],
            "symlinks": scan["symlinks"],
            "volatile_entries_skipped": scan["volatile_entries_skipped"],
            "volatile_paths": scan["volatile_paths"],
            "entries": scan["entries"],
        })
    stats_after = os.statvfs(destination_resolved)
    free_after = stats_after.f_bavail * stats_after.f_frsize
    created_at = datetime.now(timezone.utc).isoformat()

    manifest = {
        "schema": "zimabrain.snapshot.v1",
        "snapshot_id": snapshot_id,
        "snapshot_status": "VERIFIED",
        "verification_status": "VERIFIED",
        "restore_status": "NOT TESTED",
        "mode": snapshot_mode,
        "created_at": created_at,
        "source": {
            "requested_path": source,
            "resolved_path": source_resolved,
            "device": source_mount["device"],
            "filesystem": source_mount["filesystem"],
            "mountpoint": source_mount["mountpoint"],
            "mount_source": source_mount["source"],
            "regular_file_bytes": source_before["regular_file_bytes"],
            "regular_files": source_before["regular_files"],
            "directories": source_before["directories"],
            "symlinks": source_before["symlinks"],
            "special_entries": source_before["special_entries"],
            "mount_boundaries_skipped": source_before["mount_boundaries_skipped"],
            "volatile_entries_skipped": source_before["volatile_entries_skipped"],
            "volatile_paths": source_before["volatile_paths"],
        },
        "destination": {
            "mountpoint": destination_resolved,
            "device": destination_mount["device"],
            "filesystem": destination_mount["filesystem"],
            "mount_source": destination_mount["source"],
            "snapshot_directory": final_path,
            "free_bytes_before": free_before,
            "free_bytes_after": free_after,
        },
        "archive": {
            "filename": "snapshot.tar",
            "stored_bytes": archive_bytes,
            "sha256": archive_sha256,
            "format": "PAX TAR (uncompressed)",
        },
        "recovery_bundle": {
            "status": "VERIFIED" if component_before else "NOT INCLUDED",
            "recovery_type": "ZIMAOS_APP_RECOVERY",
            "system_restore_ready": False,
            "scope_contract": {
                "status": "CURRENT_SCOPE_VERIFIED" if component_before else "NOT VERIFIED",
                "included": [
                    {
                        "component": "appdata",
                        "label": "Application persistent data",
                        "requested_path": source,
                        "purpose": "Custom App configuration, databases and persistent application state stored under AppData.",
                    },
                    {
                        "component": "casaos_apps",
                        "label": "Saved Custom App definitions",
                        "requested_path": component_source,
                        "purpose": "CasaOS Compose definitions and Custom App metadata used to recreate applications.",
                    },
                    {
                        "component": "docker_named_volumes",
                        "label": "Docker named volumes",
                        "requested_path": "Docker Engine verified volume mountpoints",
                        "purpose": "Persistent application state stored in Docker-managed named volumes.",
                    },
                    {
                        "component": "reconstruction_evidence",
                        "label": "Private container reconstruction evidence",
                        "requested_path": "Docker Engine verified configuration",
                        "purpose": "Container configuration, networks, image identities and host metadata for controlled future reconstruction.",
                    },
                    {
                        "component": "selected_external_binds",
                        "label": "Selected external bind mounts",
                        "requested_path": "Explicitly selected Docker bind sources",
                        "purpose": "User-selected persistent data outside the default AppData scope.",
                    },
                ] if component_before else [],
                "not_included": [
                    {
                        "component": "casaos_system_state",
                        "label": "CasaOS and ZimaOS system state",
                        "reason": "Core CasaOS databases, extensions, firewall rules and scheduled-task state are not captured yet.",
                    },
                    {
                        "component": "live_runtime_reconstruction",
                        "label": "Automatic live container reconstruction",
                        "reason": "Container and network definitions are recorded privately, but automatic recreation is not implemented yet.",
                    },
                    {
                        "component": "docker_writable_layers",
                        "label": "Container writable layers",
                        "reason": "Writable image layers are excluded and must not be treated as persistent application data.",
                    },
                    {
                        "component": "user_files",
                        "label": "User files outside AppData",
                        "reason": "Media, documents, downloads, VM disks, models and backup repositories are outside this recovery scope.",
                    },
                ],
            },
            "components": {
                "appdata": {
                    "requested_path": source,
                    "archive_filename": "snapshot.tar",
                    "stored_bytes": archive_bytes,
                    "sha256": archive_sha256,
                    "regular_file_bytes": source_before["regular_file_bytes"],
                    "regular_files": source_before["regular_files"],
                },
                "casaos_apps": {
                    "requested_path": component_source,
                    "resolved_path": component_resolved,
                    "device": component_mount["device"] if component_mount else "",
                    "filesystem": component_mount["filesystem"] if component_mount else "",
                    "mountpoint": component_mount["mountpoint"] if component_mount else "",
                    "archive_filename": "casaos-apps.tar" if component_before else "",
                    "stored_bytes": component_archive_bytes,
                    "sha256": component_archive_sha256,
                    "regular_file_bytes": (component_before or {}).get("regular_file_bytes", 0),
                    "regular_files": (component_before or {}).get("regular_files", 0),
                    "directories": (component_before or {}).get("directories", 0),
                    "symlinks": (component_before or {}).get("symlinks", 0),
                    "entries": (component_before or {}).get("entries", []),
                },
                "docker_named_volumes": {
                    "status": "VERIFIED",
                    "volume_count": len(named_volume_records),
                    "regular_file_bytes": sum(item["regular_file_bytes"] for item in named_volume_records),
                    "regular_files": sum(item["regular_files"] for item in named_volume_records),
                    "stored_bytes": sum(item["stored_bytes"] for item in named_volume_records),
                    "volatile_entries_skipped": sum(
                        item["volatile_entries_skipped"] for item in named_volume_records
                    ),
                    "volumes": named_volume_records,
                },
                "selected_external_binds": {
                    "status": "VERIFIED" if external_bind_records else "NOT SELECTED",
                    "path_count": len(external_bind_records),
                    "regular_file_bytes": sum(item["regular_file_bytes"] for item in external_bind_records),
                    "regular_files": sum(item["regular_files"] for item in external_bind_records),
                    "stored_bytes": sum(item["stored_bytes"] for item in external_bind_records),
                    "volatile_entries_skipped": sum(
                        item["volatile_entries_skipped"] for item in external_bind_records
                    ),
                    "paths": external_bind_records,
                },
                "reconstruction_evidence": {
                    "status": "VERIFIED" if reconstruction_evidence else "NOT INCLUDED",
                    "sensitivity": "PRIVATE_CONTAINS_CONFIGURATION_SECRETS",
                    "filename": "reconstruction-evidence.private.json" if reconstruction_evidence else "",
                    "stored_bytes": reconstruction_bytes,
                    "sha256": reconstruction_sha256,
                    "container_count": int(
                        (reconstruction_evidence.get("summary") or {}).get(
                            "containers", 0
                        )
                    ),
                    "network_count": int(
                        (reconstruction_evidence.get("summary") or {}).get(
                            "networks", 0
                        )
                    ),
                    "custom_network_count": int(
                        (reconstruction_evidence.get("summary") or {}).get(
                            "custom_networks", 0
                        )
                    ),
                    "images_with_registry_digest": int(
                        (reconstruction_evidence.get("summary") or {}).get(
                            "images_with_registry_digest", 0
                        )
                    ),
                },
                "database_consistency": {
                    "status": str(
                        ((reconstruction_evidence.get("recovery_completion_plan") or {}).get("database_gate") or {}).get("status")
                        or "NOT VERIFIED"
                    ),
                    "method": "VERIFIED_CLEAN_CONTAINER_QUIESCE",
                    "database_count": int(
                        ((reconstruction_evidence.get("recovery_completion_plan") or {}).get("summary") or {}).get("database_containers", 0)
                        or 0
                    ),
                    "verified_quiesced_count": int(
                        ((reconstruction_evidence.get("recovery_completion_plan") or {}).get("summary") or {}).get("databases_quiesced", 0)
                        or 0
                    ),
                    "note": "Database containers were verified cleanly stopped before capture; application-native logical dumps are not included.",
                },
                "image_recovery_strategy": {
                    "status": "RECORDED",
                    "images": int(
                        ((reconstruction_evidence.get("recovery_completion_plan") or {}).get("summary") or {}).get("images", 0)
                        or 0
                    ),
                    "registry_digest_images": int(
                        ((reconstruction_evidence.get("recovery_completion_plan") or {}).get("summary") or {}).get("images_with_registry_digest", 0)
                        or 0
                    ),
                    "local_exports_required": int(
                        ((reconstruction_evidence.get("recovery_completion_plan") or {}).get("summary") or {}).get("images_requiring_export", 0)
                        or 0
                    ),
                },
                "filesystem_metadata": {
                    "status": "VERIFIED",
                    "filename": "filesystem-metadata.private.json",
                    "stored_bytes": metadata_bytes,
                    "sha256": metadata_sha256,
                    "mode_uid_gid": "RECORDED_IN_COMPONENT_ENTRY_MAPS",
                    "extended_attributes": "RECORDED_IN_PRIVATE_SIDECAR",
                    "posix_acl": "RECORDED_AS_SYSTEM_POSIX_ACL_XATTR_WHEN_PRESENT",
                },
            },
        },
        "checks": {
            "server_preflight_revalidated": True,
            "source_destination_separate_filesystems": True,
            "source_stable_during_capture": True,
            "source_entry_set_matches_archive": True,
            "regular_file_bytes_match": True,
            "per_file_sha256_match": True,
            "mode_uid_gid_match": True,
            "archive_sha256_recorded": True,
            "volatile_fifo_socket_entries_excluded": True,
            "casaos_app_definitions_captured": bool(component_before),
            "casaos_app_definitions_archive_verified": bool(component_before),
            "docker_named_volume_inventory_recorded": True,
            "docker_named_volume_archives_verified": True,
            "docker_named_volume_fifo_socket_entries_excluded": True,
            "selected_external_bind_archives_verified": all(
                bool(item.get("sha256")) for item in external_bind_records
            ),
            "recovery_scope_contract_recorded": bool(component_before),
            "private_reconstruction_evidence_recorded": bool(reconstruction_evidence),
            "private_reconstruction_evidence_checksum_recorded": bool(
                reconstruction_evidence and reconstruction_sha256
            ),
            "database_quiescence_verified": (
                str(
                    ((reconstruction_evidence.get("recovery_completion_plan") or {}).get("database_gate") or {}).get("status")
                )
                == "VERIFIED"
            ),
            "filesystem_metadata_sidecar_verified": bool(
                metadata_sha256 and metadata_bytes > 0
            ),
        },
        "entries": source_before["entries"],
        "limitations": [
            "Only the server-authorized source was captured.",
            "FIFO and Unix socket runtime entries are excluded and recorded in the manifest.",
            "Database consistency uses verified clean container quiescence; application-native logical dumps are not included.",
            "Extended attributes and POSIX ACL xattrs are captured in a private checksummed sidecar and are applied only to isolated restore output during verification.",
            "The manifest is checksummed evidence, not a cryptographically signed authenticity record.",
            "Restore status remains NOT TESTED until the isolated recovery test completes and verifies every captured entry.",
            "Docker image layers and container writable layers are not captured; saved Custom App definitions are used to recreate containers.",
            "Docker named volumes are captured from Docker Engine verified host mountpoints.",
            "Private reconstruction evidence can contain credentials and must not be shared publicly.",
            "Container and network reconstruction is recorded but is not automatically applied.",
            "This v0.8.3 recovery point is not yet a complete ZimaOS system recovery point.",
        ],
    }

    manifest_path = os.path.join(pending_path, "manifest.json")
    temporary_manifest = manifest_path + ".tmp"
    with open(temporary_manifest, "x", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    if os.path.getsize(temporary_manifest) > MAX_MANIFEST_BYTES:
        raise RuntimeError("Recovery manifest exceeds the 64 MiB verification limit.")
    os.replace(temporary_manifest, manifest_path)
    fsync_directory(pending_path)
    os.rename(pending_path, final_path)
    pending_path = ""
    fsync_directory(base_path)
    finish_progress("VERIFIED", "Verified recovery bundle complete")

    result.update({
        "execution_status": "COMPLETED",
        "snapshot_status": "VERIFIED",
        "verification_status": "VERIFIED",
        "manifest": manifest,
        "manifest_path": os.path.join(final_path, "manifest.json"),
        "archive_path": os.path.join(final_path, "snapshot.tar"),
    })
except Exception as exc:
    result["errors"].append(str(exc))
    finish_progress("FAILED", "Snapshot creation failed", str(exc))
    if pending_path and os.path.isdir(pending_path) and path_is_under(pending_path, base_path):
        shutil.rmtree(pending_path)
    if base_created and base_path and os.path.isdir(base_path):
        try:
            os.rmdir(base_path)
        except OSError:
            pass

print(json.dumps(result, sort_keys=True))
'''


READ_FULL_SNAPSHOT_PROGRESS_SCRIPT = r'''import json
import os
import sys

mountpoints = json.loads(sys.argv[1])
snapshot_id = sys.argv[2]
result = {
    "schema": "zimabrain.snapshot-progress.v1",
    "snapshot_id": snapshot_id,
    "status": "STARTING",
    "phase": "Revalidating capture preflight",
    "percent": 0.0,
    "work_bytes_processed": 0,
    "work_bytes_total": 0,
    "captured_bytes": 0,
    "logical_bytes_total": 0,
    "files_processed": 0,
    "files_total": 0,
    "elapsed_seconds": 0.0,
    "updated_at": "",
    "error": "",
}

if not snapshot_id or any(
    character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    for character in snapshot_id
):
    raise SystemExit("Invalid snapshot identifier")

records = []
for mountpoint in mountpoints:
    if not isinstance(mountpoint, str) or not any(
        mountpoint == root or mountpoint.startswith(root + "/")
        for root in ("/DATA", "/media", "/mnt")
    ):
        continue
    path = os.path.join(
        mountpoint,
        "zimabrain-full-snapshots",
        ".progress-" + snapshot_id + ".json",
    )
    try:
        info = os.lstat(path)
        if not os.path.isfile(path) or os.path.islink(path) or info.st_size > 1024 * 1024:
            continue
        with open(path, "r", encoding="utf-8") as handle:
            record = json.load(handle)
        if (
            isinstance(record, dict)
            and record.get("schema") == "zimabrain.snapshot-progress.v1"
            and record.get("snapshot_id") == snapshot_id
        ):
            records.append((info.st_mtime_ns, record))
    except (OSError, ValueError):
        continue

if records:
    result = max(records, key=lambda item: item[0])[1]

print(json.dumps(result, sort_keys=True))
'''


CANCEL_FULL_SNAPSHOT_SCRIPT = r'''import json
import os
import shutil
import signal
import stat
import sys
import time
from datetime import datetime, timezone

mountpoints = json.loads(sys.argv[1])
snapshot_id = sys.argv[2]

if not snapshot_id or any(
    character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    for character in snapshot_id
):
    raise SystemExit("Invalid snapshot identifier")

workers = []
for entry in os.scandir("/proc"):
    if not entry.name.isdigit() or int(entry.name) == os.getpid():
        continue
    try:
        with open("/proc/" + entry.name + "/cmdline", "rb") as handle:
            command = handle.read()
        executable = os.path.basename(os.readlink("/proc/" + entry.name + "/exe"))
    except OSError:
        continue
    if (
        executable.startswith("python3")
        and snapshot_id.encode() in command
        and b"zimabrain-full-snapshots" in command
        and b"ALL APPDATA SNAPSHOT" in command
    ):
        workers.append(int(entry.name))

if len(workers) > 1:
    raise SystemExit("More than one matching snapshot worker exists")

if workers:
    os.kill(workers[0], signal.SIGTERM)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and os.path.exists("/proc/" + str(workers[0])):
        time.sleep(0.25)
    if os.path.exists("/proc/" + str(workers[0])):
        raise SystemExit("Snapshot worker did not stop after SIGTERM")

cancelled_path = ""
progress_path = ""
for mountpoint in mountpoints:
    if not isinstance(mountpoint, str) or not any(
        mountpoint == root or mountpoint.startswith(root + "/")
        for root in ("/DATA", "/media", "/mnt")
    ):
        continue
    base = os.path.join(mountpoint, "zimabrain-full-snapshots")
    pending = os.path.join(base, ".pending-" + snapshot_id)
    final = os.path.join(base, snapshot_id)
    candidate_progress = os.path.join(base, ".progress-" + snapshot_id + ".json")
    if os.path.isdir(final) and not os.path.islink(final):
        raise SystemExit("Verified snapshot already completed; cancellation refused")
    if os.path.lexists(pending):
        info = os.lstat(pending)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SystemExit("Pending snapshot output is not a safe directory")
        if not os.path.realpath(pending).startswith(os.path.realpath(base).rstrip("/") + "/"):
            raise SystemExit("Pending snapshot output escapes its approved base")
        shutil.rmtree(pending)
        cancelled_path = pending
    if os.path.isfile(candidate_progress) and not os.path.islink(candidate_progress):
        progress_path = candidate_progress

record = {
    "schema": "zimabrain.snapshot-progress.v1",
    "snapshot_id": snapshot_id,
    "status": "CANCELLED",
    "phase": "Cancelled by user",
    "percent": 0.0,
    "work_bytes_processed": 0,
    "work_bytes_total": 0,
    "captured_bytes": 0,
    "logical_bytes_total": 0,
    "files_processed": 0,
    "files_total": 0,
    "elapsed_seconds": 0.0,
    "updated_at": datetime.now(timezone.utc).isoformat(),
    "error": "",
}
if progress_path:
    try:
        with open(progress_path, "r", encoding="utf-8") as handle:
            existing = json.load(handle)
        if isinstance(existing, dict):
            record.update(existing)
    except (OSError, ValueError):
        pass
    record.update({
        "status": "CANCELLED",
        "phase": "Cancelled by user",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "error": "",
    })
    temporary = progress_path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(record, handle, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, progress_path)

print(json.dumps({
    "execution_status": "CANCELLED",
    "snapshot_status": "CANCELLED",
    "verification_status": "NOT VERIFIED",
    "snapshot_id": snapshot_id,
    "worker_stopped": not workers or not os.path.exists("/proc/" + str(workers[0])),
    "partial_output_removed": bool(cancelled_path),
    "errors": [],
}, sort_keys=True))
'''


DISCOVER_SNAPSHOT_SCRIPT = r'''import hashlib
import json
import os
import stat
import sys
import time
from datetime import datetime, timezone

mountpoints = json.loads(sys.argv[1])
snapshot_directory_name = sys.argv[2]
expected_source = sys.argv[3]
progress_path = sys.argv[4] if len(sys.argv) > 4 else ""
progress_stage_start = float(sys.argv[5]) if len(sys.argv) > 5 else 0.0
progress_stage_end = float(sys.argv[6]) if len(sys.argv) > 6 else 100.0
progress_started_at = float(sys.argv[7]) if len(sys.argv) > 7 else time.time()
result = {
    "mode": "verified-snapshot-discovery",
    "verification_status": "NOT CREATED",
    "snapshot_status": "NOT CREATED",
    "manifest": None,
    "errors": [],
}
progress = {
    "schema": "zimabrain.page-verification-progress.v1",
    "status": "RUNNING",
    "phase": "Locating latest verified recovery point",
    "percent": progress_stage_start,
    "bytes_checked": 0,
    "bytes_total": 0,
    "files_checked": 0,
    "files_total": 0,
    "elapsed_seconds": 0.0,
    "updated_at": "",
    "error": "",
}
last_progress_write = 0.0


def publish_progress(force=False):
    global last_progress_write
    if not progress_path:
        return
    now = time.monotonic()
    if not force and now - last_progress_write < 0.5:
        return
    total = max(0, int(progress.get("bytes_total", 0) or 0))
    checked = max(0, int(progress.get("bytes_checked", 0) or 0))
    ratio = min(1.0, checked / total) if total else 0.0
    progress["percent"] = round(
        progress_stage_start
        + (progress_stage_end - progress_stage_start) * ratio,
        1,
    )
    progress["elapsed_seconds"] = round(
        max(0.0, time.time() - progress_started_at),
        1,
    )
    progress["updated_at"] = datetime.now(timezone.utc).isoformat()
    temporary = progress_path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(progress, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, progress_path)
    last_progress_write = now


def set_progress(phase, bytes_total=None, files_total=None):
    progress["phase"] = str(phase)
    if bytes_total is not None:
        progress["bytes_total"] = max(0, int(bytes_total))
    if files_total is not None:
        progress["files_total"] = max(0, int(files_total))
    publish_progress(force=True)


def advance_progress(byte_count):
    progress["bytes_checked"] = min(
        int(progress.get("bytes_total", 0) or 0),
        int(progress.get("bytes_checked", 0) or 0) + max(0, int(byte_count)),
    )
    publish_progress()


def record_progress_file():
    progress["files_checked"] = min(
        int(progress.get("files_total", 0) or 0),
        int(progress.get("files_checked", 0) or 0) + 1,
    )
    publish_progress(force=True)


def approved_mountpoint(value):
    return any(value == root or value.startswith(root + "/") for root in ("/DATA", "/media", "/mnt"))


def hash_file(path, phase):
    progress["phase"] = str(phase)
    publish_progress(force=True)
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            advance_progress(len(chunk))
    record_progress_file()
    return digest.hexdigest(), size


try:
    candidates = []
    for mountpoint in mountpoints:
        if not isinstance(mountpoint, str) or not approved_mountpoint(mountpoint):
            continue
        if snapshot_directory_name not in ("zimabrain-snapshots", "zimabrain-full-snapshots"):
            raise RuntimeError("Snapshot directory class is not authorized.")
        base = os.path.join(mountpoint, snapshot_directory_name)
        if not os.path.isdir(base) or os.path.islink(base):
            continue
        with os.scandir(base) as directories:
            for directory in directories:
                if not directory.is_dir(follow_symlinks=False) or directory.name.startswith("."):
                    continue
                manifest_path = os.path.join(directory.path, "manifest.json")
                try:
                    info = os.lstat(manifest_path)
                    if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
                        continue
                    with open(manifest_path, "r", encoding="utf-8") as handle:
                        manifest = json.load(handle)
                    if manifest.get("schema") != "zimabrain.snapshot.v1":
                        continue
                    if (manifest.get("source") or {}).get("requested_path") != expected_source:
                        continue
                    candidates.append((str(manifest.get("created_at") or ""), directory.path, manifest))
                except Exception as exc:
                    result["errors"].append(f"{manifest_path}: {exc}")

    if candidates:
        _, snapshot_path, manifest = max(candidates, key=lambda item: item[0])
        archive = manifest.get("archive") or {}
        recovery_bundle = manifest.get("recovery_bundle") or {}
        app_component = (recovery_bundle.get("components") or {}).get("casaos_apps") or {}
        volume_component = (recovery_bundle.get("components") or {}).get("docker_named_volumes") or {}
        reconstruction_component = (
            (recovery_bundle.get("components") or {}).get("reconstruction_evidence")
            or {}
        )
        external_component = (
            (recovery_bundle.get("components") or {}).get("selected_external_binds")
            or {}
        )
        metadata_component = (
            (recovery_bundle.get("components") or {}).get("filesystem_metadata")
            or {}
        )
        volume_records = volume_component.get("volumes") or []
        external_records = external_component.get("paths") or []
        stored_components = [archive]
        if expected_source == "/DATA/AppData":
            stored_components.append(app_component)
            if isinstance(volume_records, list):
                stored_components.extend(
                    item for item in volume_records if isinstance(item, dict)
                )
            if reconstruction_component:
                stored_components.append(reconstruction_component)
            if isinstance(external_records, list):
                stored_components.extend(
                    item for item in external_records if isinstance(item, dict)
                )
            if metadata_component:
                stored_components.append(metadata_component)
        set_progress(
            "Checking stored AppData archive checksum",
            bytes_total=sum(
                max(0, int(item.get("stored_bytes", 0) or 0))
                for item in stored_components
            ),
            files_total=len(stored_components),
        )
        filename = str(archive.get("filename") or "")
        if not filename or os.path.basename(filename) != filename:
            raise RuntimeError("Latest snapshot manifest contains an invalid archive filename.")
        archive_path = os.path.join(snapshot_path, filename)
        archive_info = os.lstat(archive_path)
        if not stat.S_ISREG(archive_info.st_mode) or os.path.islink(archive_path):
            raise RuntimeError("Latest snapshot archive is not a safe regular file.")
        checksum, byte_count = hash_file(
            archive_path,
            "Checking stored AppData archive checksum",
        )
        if checksum != archive.get("sha256"):
            raise RuntimeError("Latest snapshot archive checksum does not match its manifest.")
        if byte_count != int(archive.get("stored_bytes", -1)):
            raise RuntimeError("Latest snapshot archive byte size does not match its manifest.")
        if manifest.get("snapshot_status") != "VERIFIED" or manifest.get("verification_status") != "VERIFIED":
            raise RuntimeError("Latest snapshot manifest is not verified.")
        if expected_source == "/DATA/AppData":
            if recovery_bundle.get("status") != "VERIFIED":
                raise RuntimeError("Latest All AppData snapshot is not a verified recovery bundle.")
            if app_component.get("requested_path") != "/var/lib/casaos/apps":
                raise RuntimeError("Recovery bundle app-definition source is invalid.")
            app_filename = str(app_component.get("archive_filename") or "")
            if not app_filename or os.path.basename(app_filename) != app_filename:
                raise RuntimeError("Recovery bundle app-definition archive name is invalid.")
            app_archive_path = os.path.join(snapshot_path, app_filename)
            app_info = os.lstat(app_archive_path)
            if not stat.S_ISREG(app_info.st_mode) or os.path.islink(app_archive_path):
                raise RuntimeError("Recovery bundle app-definition archive is unsafe.")
            app_checksum, app_bytes = hash_file(
                app_archive_path,
                "Checking saved Custom App definitions",
            )
            if app_checksum != app_component.get("sha256") or app_bytes != int(app_component.get("stored_bytes", -1)):
                raise RuntimeError("Recovery bundle app-definition archive no longer verifies.")
            if volume_component:
                if volume_component.get("status") != "VERIFIED":
                    raise RuntimeError("Recovery bundle Docker named-volume component is not verified.")
                if not isinstance(volume_records, list) or len(volume_records) != int(volume_component.get("volume_count", -1)):
                    raise RuntimeError("Recovery bundle Docker named-volume inventory is inconsistent.")
                seen_volume_names = set()
                for volume in volume_records:
                    if not isinstance(volume, dict):
                        raise RuntimeError("Recovery bundle Docker named-volume record is invalid.")
                    volume_name = str(volume.get("name") or "")
                    volume_filename = str(volume.get("archive_filename") or "")
                    if not volume_name or volume_name in seen_volume_names:
                        raise RuntimeError("Recovery bundle Docker named-volume identity is invalid or duplicated.")
                    if not volume_filename or os.path.basename(volume_filename) != volume_filename:
                        raise RuntimeError(f"Docker named-volume archive name is unsafe: {volume_name}")
                    volume_archive_path = os.path.join(snapshot_path, volume_filename)
                    volume_info = os.lstat(volume_archive_path)
                    if not stat.S_ISREG(volume_info.st_mode) or os.path.islink(volume_archive_path):
                        raise RuntimeError(f"Docker named-volume archive is unsafe: {volume_name}")
                    volume_checksum, volume_bytes = hash_file(
                        volume_archive_path,
                        "Checking Docker named volume " + volume_name,
                    )
                    if volume_checksum != volume.get("sha256") or volume_bytes != int(volume.get("stored_bytes", -1)):
                        raise RuntimeError(f"Docker named-volume archive no longer verifies: {volume_name}")
                    seen_volume_names.add(volume_name)
            if reconstruction_component:
                if reconstruction_component.get("status") != "VERIFIED":
                    raise RuntimeError("Private reconstruction evidence is not verified.")
                reconstruction_filename = str(
                    reconstruction_component.get("filename") or ""
                )
                if (
                    reconstruction_filename
                    != "reconstruction-evidence.private.json"
                ):
                    raise RuntimeError("Private reconstruction evidence filename is invalid.")
                reconstruction_path = os.path.join(
                    snapshot_path,
                    reconstruction_filename,
                )
                reconstruction_info = os.lstat(reconstruction_path)
                if (
                    not stat.S_ISREG(reconstruction_info.st_mode)
                    or os.path.islink(reconstruction_path)
                ):
                    raise RuntimeError("Private reconstruction evidence file is unsafe.")
                reconstruction_checksum, reconstruction_size = hash_file(
                    reconstruction_path,
                    "Checking private reconstruction evidence",
                )
                if (
                    reconstruction_checksum != reconstruction_component.get("sha256")
                    or reconstruction_size
                    != int(reconstruction_component.get("stored_bytes", -1))
                ):
                    raise RuntimeError("Private reconstruction evidence no longer verifies.")
                with open(reconstruction_path, "r", encoding="utf-8") as handle:
                    reconstruction_payload = json.load(handle)
                if (
                    not isinstance(reconstruction_payload, dict)
                    or reconstruction_payload.get("schema")
                    != "zimabrain.reconstruction-evidence.v1"
                    or reconstruction_payload.get("capture_status") != "VERIFIED"
                ):
                    raise RuntimeError("Private reconstruction evidence content is invalid.")
            if external_component:
                if external_component.get("status") not in {"VERIFIED", "NOT SELECTED"}:
                    raise RuntimeError("Selected external bind component is not verified.")
                if not isinstance(external_records, list) or len(external_records) != int(
                    external_component.get("path_count", -1)
                ):
                    raise RuntimeError("Selected external bind inventory is inconsistent.")
                for external in external_records:
                    filename_external = str((external or {}).get("archive_filename") or "")
                    if not filename_external or os.path.basename(filename_external) != filename_external:
                        raise RuntimeError("Selected external bind archive name is unsafe.")
                    path_external = os.path.join(snapshot_path, filename_external)
                    info_external = os.lstat(path_external)
                    if not stat.S_ISREG(info_external.st_mode) or os.path.islink(path_external):
                        raise RuntimeError("Selected external bind archive is unsafe.")
                    checksum_external, bytes_external = hash_file(
                        path_external,
                        "Checking selected external bind archive",
                    )
                    if (
                        checksum_external != external.get("sha256")
                        or bytes_external != int(external.get("stored_bytes", -1))
                    ):
                        raise RuntimeError("Selected external bind archive no longer verifies.")
            if metadata_component:
                if metadata_component.get("status") != "VERIFIED":
                    raise RuntimeError("Filesystem metadata component is not verified.")
                metadata_filename = str(metadata_component.get("filename") or "")
                if metadata_filename != "filesystem-metadata.private.json":
                    raise RuntimeError("Filesystem metadata filename is invalid.")
                metadata_path = os.path.join(snapshot_path, metadata_filename)
                metadata_info = os.lstat(metadata_path)
                if not stat.S_ISREG(metadata_info.st_mode) or os.path.islink(metadata_path):
                    raise RuntimeError("Filesystem metadata sidecar is unsafe.")
                metadata_checksum, metadata_size = hash_file(
                    metadata_path,
                    "Checking ACL and extended-attribute metadata",
                )
                if (
                    metadata_checksum != metadata_component.get("sha256")
                    or metadata_size != int(metadata_component.get("stored_bytes", -1))
                ):
                    raise RuntimeError("Filesystem metadata sidecar no longer verifies.")
                with open(metadata_path, "r", encoding="utf-8") as handle:
                    metadata_payload = json.load(handle)
                if metadata_payload.get("schema") != "zimabrain.filesystem-metadata.v1":
                    raise RuntimeError("Filesystem metadata sidecar schema is invalid.")
        result.update({
            "verification_status": "VERIFIED",
            "snapshot_status": "VERIFIED",
            "manifest": manifest,
            "manifest_path": os.path.join(snapshot_path, "manifest.json"),
            "archive_path": archive_path,
        })
        progress["bytes_checked"] = progress["bytes_total"]
        progress["files_checked"] = progress["files_total"]
        progress["phase"] = "Stored recovery bundle checksums verified"
        publish_progress(force=True)
except Exception as exc:
    result["verification_status"] = "NOT VERIFIED"
    result["snapshot_status"] = "NOT VERIFIED"
    result["errors"].append(str(exc))

print(json.dumps(result, sort_keys=True))
'''


def _failed(message, status="NOT CREATED"):
    return {
        "mode": "restricted-lab-snapshot-execution",
        "execution_status": "FAILED",
        "snapshot_status": status,
        "verification_status": "NOT VERIFIED",
        "errors": [str(message)],
    }


def execute_lab_snapshot(docker_get, command_runner, source_id, destination_id, timeout=300):
    inventory = snapshot_inventory.collect_inventory(docker_get)
    if inventory.get("verification_status") != "VERIFIED":
        return _failed("Docker source inventory is not fully verified.")

    source = snapshot_inventory.find_candidate_source(inventory, source_id)
    if source is None or source.get("source") != LAB_TEST_SOURCE:
        return _failed("v0.5 permits only the Snapshot Lab data source.")

    destinations = snapshot_inventory.collect_destinations(command_runner)
    if destinations.get("verification_status") != "VERIFIED":
        return _failed("Destination inventory is not fully verified.")
    destination = snapshot_inventory.find_destination(destinations, destination_id)
    if destination is None or destination.get("decision") != "candidate":
        return _failed("The requested destination is not an eligible native Linux destination.")

    measurement = snapshot_inventory.measure_source(source, command_runner)
    if measurement.get("measurement_status") != "MEASURED":
        return _failed("Source measurement is not fully verified.")
    if measurement.get("device") == destination.get("device"):
        return _failed("Source and destination use the same canonical filesystem device.")
    if measurement.get("mount_boundaries_skipped"):
        return _failed("Nested mount boundaries are not supported by this snapshot mode.")
    if measurement.get("special_entries"):
        return _failed("Special filesystem entries are not supported in v0.5.")

    logical_bytes = int(measurement.get("regular_file_bytes", 0) or 0)
    if logical_bytes > MAX_LAB_SOURCE_BYTES:
        return _failed(f"The Lab source exceeds the v0.5 limit of {MAX_LAB_SOURCE_BYTES} bytes.")
    required_free = logical_bytes + MINIMUM_OVERHEAD_BYTES
    if int(destination.get("free_bytes", 0) or 0) < required_free:
        return _failed("Destination capacity no longer satisfies the execution reserve.")

    snapshot_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    try:
        completed = command_runner([
            "python3",
            "-c",
            CREATE_SNAPSHOT_SCRIPT,
            LAB_TEST_SOURCE,
            str(destination["mountpoint"]),
            snapshot_id,
            str(measurement["device"]),
            str(destination["device"]),
            str(logical_bytes),
            LAB_TEST_SOURCE,
            SNAPSHOT_DIRECTORY_NAME,
            "RESTRICTED LAB SNAPSHOT",
        ], timeout=timeout)
    except Exception as exc:
        return _failed(f"Snapshot executor runner failed: {exc}")

    if not isinstance(completed, dict):
        return _failed("Snapshot executor returned an invalid runner result.")
    stdout = str(completed.get("stdout") or "")
    if not completed.get("ok"):
        detail = str(completed.get("stderr") or stdout or "Snapshot executor failed.").strip()
        return _failed(detail)
    try:
        result = json.loads(stdout)
    except Exception as exc:
        return _failed(f"Snapshot executor returned invalid JSON: {exc}")
    if not isinstance(result, dict) or result.get("snapshot_id") != snapshot_id:
        return _failed("Snapshot executor response did not match the requested execution.")
    if result.get("snapshot_status") != "VERIFIED":
        return result

    manifest = result.get("manifest") or {}
    if manifest.get("schema") != "zimabrain.snapshot.v1":
        return _failed("Completed snapshot manifest schema is invalid.", status="NOT VERIFIED")
    if (manifest.get("source") or {}).get("device") != measurement.get("device"):
        return _failed("Completed snapshot source device differs from server preflight.", status="NOT VERIFIED")
    if (manifest.get("destination") or {}).get("device") != destination.get("device"):
        return _failed("Completed snapshot destination device differs from server preflight.", status="NOT VERIFIED")
    return result


def collect_latest_verified_snapshot(destination_inventory, command_runner, timeout=120):
    mountpoints = [
        str(item.get("mountpoint"))
        for item in (destination_inventory.get("destinations") or [])
        if item.get("decision") == "candidate" and item.get("mountpoint")
    ]
    if not mountpoints:
        return {
            "verification_status": "NOT CREATED",
            "snapshot_status": "NOT CREATED",
            "manifest": None,
            "errors": [],
        }
    try:
        completed = command_runner(
            ["python3", "-c", DISCOVER_SNAPSHOT_SCRIPT, json.dumps(mountpoints), SNAPSHOT_DIRECTORY_NAME, LAB_TEST_SOURCE],
            timeout=timeout,
        )
    except Exception as exc:
        return _failed(f"Verified snapshot discovery failed: {exc}")
    if not isinstance(completed, dict):
        return _failed("Verified snapshot discovery returned an invalid result.")
    stdout = str(completed.get("stdout") or "")
    if not completed.get("ok"):
        return _failed(str(completed.get("stderr") or stdout or "Verified snapshot discovery failed."))
    try:
        result = json.loads(stdout)
    except Exception as exc:
        return _failed(f"Verified snapshot discovery returned invalid JSON: {exc}")
    return result if isinstance(result, dict) else _failed("Verified snapshot discovery returned a non-object result.")


def full_appdata_source():
    return {
        "source_id": snapshot_inventory.source_identifier(FULL_APPDATA_SOURCE),
        "source": FULL_APPDATA_SOURCE,
        "measurement_status": "NOT MEASURED",
    }


def measure_full_appdata(command_runner, timeout=300):
    return snapshot_inventory.measure_source(full_appdata_source(), command_runner, timeout=timeout)


def measure_casaos_apps(command_runner, timeout=300):
    source = {
        "source_id": snapshot_inventory.source_identifier(CASAOS_APPS_SOURCE),
        "source": CASAOS_APPS_SOURCE,
        "measurement_status": "NOT MEASURED",
    }
    return snapshot_inventory.measure_source(source, command_runner, timeout=timeout)


def collect_named_volume_measurements(docker_get, command_runner, timeout=300):
    if docker_get is None:
        return {
            "measurement_status": "NOT MEASURED",
            "volumes": [],
            "regular_file_bytes": 0,
            "regular_files": 0,
            "volatile_entries_skipped": 0,
            "devices": [],
            "errors": ["Docker named-volume inventory is unavailable."],
        }
    try:
        payload = docker_get("/volumes") or {}
    except Exception as exc:
        return {
            "measurement_status": "NOT MEASURED",
            "volumes": [],
            "regular_file_bytes": 0,
            "regular_files": 0,
            "volatile_entries_skipped": 0,
            "devices": [],
            "errors": [f"Docker named-volume inventory failed: {exc}"],
        }
    raw_volumes = payload.get("Volumes") if isinstance(payload, dict) else None
    if raw_volumes is None:
        raw_volumes = []
    if not isinstance(raw_volumes, list):
        return {
            "measurement_status": "NOT MEASURED",
            "volumes": [],
            "regular_file_bytes": 0,
            "regular_files": 0,
            "volatile_entries_skipped": 0,
            "devices": [],
            "errors": ["Docker named-volume inventory returned an invalid volume list."],
        }

    measured_volumes = []
    errors = []
    seen_names = set()
    for item in sorted(raw_volumes, key=lambda value: str((value or {}).get("Name") or "")):
        if not isinstance(item, dict):
            errors.append("Docker named-volume inventory contains a non-object record.")
            continue
        name = str(item.get("Name") or "")
        mountpoint = str(item.get("Mountpoint") or "")
        if not name or name in seen_names:
            errors.append(f"Docker named-volume identity is missing or duplicated: {name!r}.")
            continue
        if not mountpoint.startswith("/"):
            errors.append(f"Docker named volume {name} has no absolute host mountpoint.")
            continue
        seen_names.add(name)
        source = {
            "source_id": snapshot_inventory.source_identifier(mountpoint),
            "source": mountpoint,
            "measurement_status": "NOT MEASURED",
        }
        measurement = snapshot_inventory.measure_source(source, command_runner, timeout=timeout)
        volume_errors = list(measurement.get("errors") or [])
        if measurement.get("measurement_status") != "MEASURED":
            errors.extend(f"{name}: {message}" for message in (volume_errors or ["measurement failed"]))
            continue
        if measurement.get("special_entries") or measurement.get("mount_boundaries_skipped"):
            errors.append(f"{name}: unsupported special entries or nested filesystem boundaries were found.")
            continue
        measured_volumes.append({
            "name": name,
            "driver": str(item.get("Driver") or ""),
            "scope": str(item.get("Scope") or ""),
            "labels": item.get("Labels") if isinstance(item.get("Labels"), dict) else {},
            "options": item.get("Options") if isinstance(item.get("Options"), dict) else {},
            "requested_path": mountpoint,
            "resolved_path": str(measurement.get("resolved_path") or ""),
            "device": str(measurement.get("device") or ""),
            "filesystem": str(measurement.get("filesystem") or ""),
            "mountpoint": str(measurement.get("mountpoint") or ""),
            "regular_file_bytes": int(measurement.get("regular_file_bytes", 0) or 0),
            "regular_files": int(measurement.get("regular_files", 0) or 0),
            "directories": int(measurement.get("directories", 0) or 0),
            "symlinks": int(measurement.get("symlinks", 0) or 0),
            "volatile_entries_skipped": int(
                measurement.get("volatile_entries_skipped", 0) or 0
            ),
            "volatile_paths": list(measurement.get("volatile_paths") or []),
        })
    return {
        "measurement_status": "MEASURED" if not errors else "NOT MEASURED",
        "volumes": measured_volumes,
        "volume_count": len(measured_volumes),
        "regular_file_bytes": sum(item["regular_file_bytes"] for item in measured_volumes),
        "regular_files": sum(item["regular_files"] for item in measured_volumes),
        "volatile_entries_skipped": sum(
            item["volatile_entries_skipped"] for item in measured_volumes
        ),
        "devices": sorted({item["device"] for item in measured_volumes if item["device"]}),
        "errors": errors,
    }


def collect_selected_external_bind_measurements(paths, command_runner, timeout=300):
    requested = []
    seen = set()
    errors = []
    records = []
    for raw_path in paths or []:
        path = os.path.normpath(str(raw_path or ""))
        if (
            not os.path.isabs(path)
            or path == "/"
            or not path.startswith(("/DATA/", "/media/", "/mnt/"))
            or path == FULL_APPDATA_SOURCE
            or path.startswith(FULL_APPDATA_SOURCE + os.sep)
            or path == CASAOS_APPS_SOURCE
            or path.startswith(CASAOS_APPS_SOURCE + os.sep)
            or path in seen
        ):
            errors.append("Selected external bind path is invalid, duplicated or already protected: " + path)
            continue
        seen.add(path)
        requested.append(path)
    for index, path in enumerate(requested):
        source = {
            "source_id": "external-bind-" + str(index),
            "source": path,
            "measurement_status": "NOT MEASURED",
        }
        measured = snapshot_inventory.measure_source(
            source,
            command_runner,
            timeout=timeout,
        )
        if measured.get("measurement_status") != "MEASURED":
            errors.extend(measured.get("errors") or ["External bind measurement failed: " + path])
            continue
        if measured.get("mount_boundaries_skipped") or measured.get("special_entries"):
            errors.append("External bind contains unsupported entries or filesystem boundaries: " + path)
            continue
        records.append({
            "requested_path": path,
            "resolved_path": str(measured.get("resolved_path") or ""),
            "device": str(measured.get("device") or ""),
            "filesystem": str(measured.get("filesystem") or ""),
            "mountpoint": str(measured.get("mountpoint") or ""),
            "regular_file_bytes": int(measured.get("regular_file_bytes", 0) or 0),
            "regular_files": int(measured.get("regular_files", 0) or 0),
            "volatile_entries_skipped": int(measured.get("volatile_entries_skipped", 0) or 0),
        })
    return {
        "measurement_status": "MEASURED" if not errors else "NOT MEASURED",
        "paths": records,
        "regular_file_bytes": sum(item["regular_file_bytes"] for item in records),
        "regular_files": sum(item["regular_files"] for item in records),
        "devices": sorted({item["device"] for item in records if item["device"]}),
        "errors": errors,
    }


def measure_recovery_bundle(command_runner, docker_get=None, timeout=300):
    appdata = measure_full_appdata(command_runner, timeout=timeout)
    apps = measure_casaos_apps(command_runner, timeout=timeout)
    volumes = collect_named_volume_measurements(docker_get, command_runner, timeout=timeout)
    errors = (
        list(appdata.get("errors") or [])
        + list(apps.get("errors") or [])
        + list(volumes.get("errors") or [])
    )
    measured = (
        appdata.get("measurement_status") == "MEASURED"
        and apps.get("measurement_status") == "MEASURED"
        and volumes.get("measurement_status") == "MEASURED"
    )
    source_devices = sorted({
        str(appdata.get("device") or ""),
        str(apps.get("device") or ""),
        *(str(value) for value in (volumes.get("devices") or [])),
    } - {""})
    return {
        **appdata,
        "measurement_status": "MEASURED" if measured else "NOT MEASURED",
        "recovery_bundle": True,
        "app_definition_source": CASAOS_APPS_SOURCE,
        "app_definition_device": str(apps.get("device") or ""),
        "app_definition_bytes": int(apps.get("regular_file_bytes", 0) or 0),
        "app_definition_files": int(apps.get("regular_files", 0) or 0),
        "named_volume_count": int(volumes.get("volume_count", 0) or 0),
        "named_volume_bytes": int(volumes.get("regular_file_bytes", 0) or 0),
        "named_volume_files": int(volumes.get("regular_files", 0) or 0),
        "named_volume_volatile_entries_skipped": int(
            volumes.get("volatile_entries_skipped", 0) or 0
        ),
        "named_volumes": volumes.get("volumes") or [],
        "source_devices": source_devices,
        "total_logical_bytes": (
            int(appdata.get("regular_file_bytes", 0) or 0)
            + int(apps.get("regular_file_bytes", 0) or 0)
            + int(volumes.get("regular_file_bytes", 0) or 0)
        ),
        "errors": errors,
        "error_count": len(errors),
    }


def _write_reconstruction_handoff(snapshot_id, payload):
    filename = ".reconstruction-handoff-" + snapshot_id + ".json"
    container_path = os.path.join(
        RECONSTRUCTION_HANDOFF_CONTAINER_DIRECTORY,
        filename,
    )
    host_path = os.path.join(
        RECONSTRUCTION_HANDOFF_HOST_DIRECTORY,
        filename,
    )
    os.makedirs(RECONSTRUCTION_HANDOFF_CONTAINER_DIRECTORY, exist_ok=True)
    descriptor = os.open(
        container_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(container_path)
        except OSError:
            pass
        raise
    return container_path, host_path


READ_RECONSTRUCTION_EVIDENCE_SCRIPT = r'''import hashlib
import json
import os
import stat
import sys

path = sys.argv[1]
expected_sha256 = sys.argv[2]
expected_bytes = int(sys.argv[3])

if not path.startswith(("/DATA/", "/media/", "/mnt/")):
    raise SystemExit("Private reconstruction evidence path is not authorized.")
info = os.lstat(path)
if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
    raise SystemExit("Private reconstruction evidence is not a safe regular file.")
if info.st_size != expected_bytes or expected_bytes > 16 * 1024 * 1024:
    raise SystemExit("Private reconstruction evidence byte count is invalid.")
digest = hashlib.sha256()
with open(path, "rb") as handle:
    while True:
        chunk = handle.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
if digest.hexdigest() != expected_sha256:
    raise SystemExit("Private reconstruction evidence checksum no longer verifies.")
with open(path, "r", encoding="utf-8") as handle:
    evidence = json.load(handle)
if (
    not isinstance(evidence, dict)
    or evidence.get("schema") != "zimabrain.reconstruction-evidence.v1"
    or evidence.get("capture_status") != "VERIFIED"
):
    raise SystemExit("Private reconstruction evidence content is invalid.")
print(json.dumps(evidence, separators=(",", ":"), sort_keys=True))
'''


def load_verified_reconstruction_evidence(manifest, command_runner, timeout=120):
    """Read a checksummed private artifact without exposing it to the browser."""
    manifest = manifest if isinstance(manifest, dict) else {}
    recovery = manifest.get("recovery_bundle") or {}
    component = (recovery.get("components") or {}).get("reconstruction_evidence") or {}
    snapshot_id = str(manifest.get("snapshot_id") or "")
    destination = manifest.get("destination") or {}
    mountpoint = str(destination.get("mountpoint") or "")
    filename = str(component.get("filename") or "")
    if (
        manifest.get("snapshot_status") != "VERIFIED"
        or manifest.get("verification_status") != "VERIFIED"
        or recovery.get("status") != "VERIFIED"
        or component.get("status") != "VERIFIED"
        or filename != "reconstruction-evidence.private.json"
        or not snapshot_id
        or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            for character in snapshot_id
        )
        or not mountpoint.startswith(("/DATA/", "/media/", "/mnt/"))
    ):
        return {
            "capture_status": "NOT VERIFIED",
            "errors": ["No authorized verified private reconstruction artifact is available."],
        }
    path = os.path.join(
        mountpoint,
        FULL_SNAPSHOT_DIRECTORY_NAME,
        snapshot_id,
        filename,
    )
    completed = command_runner(
        [
            "python3",
            "-c",
            READ_RECONSTRUCTION_EVIDENCE_SCRIPT,
            path,
            str(component.get("sha256") or ""),
            str(int(component.get("stored_bytes", 0) or 0)),
        ],
        timeout=timeout,
    )
    stdout = str(completed.get("stdout") or "").strip()
    if not completed.get("ok"):
        return {
            "capture_status": "NOT VERIFIED",
            "errors": [str(completed.get("stderr") or stdout or "Private evidence read failed.")],
        }
    try:
        result = json.loads(stdout)
    except Exception as exc:
        return {
            "capture_status": "NOT VERIFIED",
            "errors": [f"Private reconstruction evidence returned invalid JSON: {exc}"],
        }
    return result if isinstance(result, dict) else {
        "capture_status": "NOT VERIFIED",
        "errors": ["Private reconstruction evidence returned a non-object result."],
    }


def execute_full_appdata_snapshot(
    command_runner,
    destination_id,
    docker_get=None,
    timeout=1800,
    snapshot_id=None,
    selected_external_paths=None,
):
    destinations = snapshot_inventory.collect_destinations(command_runner)
    if destinations.get("verification_status") != "VERIFIED":
        return _failed("Destination inventory is not fully verified.")
    destination = snapshot_inventory.find_destination(destinations, destination_id)
    if destination is None or destination.get("decision") != "candidate":
        return _failed("The requested destination is not an eligible native Linux destination.")

    reconstruction_evidence = recovery_readiness.collect_reconstruction_evidence(
        docker_get,
        command_runner,
    )
    if reconstruction_evidence.get("capture_status") != "VERIFIED":
        return _failed(
            "Private reconstruction evidence was not fully verified: "
            + "; ".join(reconstruction_evidence.get("errors") or [])
        )
    completion_plan = recovery_completion.build_capture_plan(
        reconstruction_evidence,
        selected_external_paths or [],
    )
    if completion_plan.get("plan_status") != "VERIFIED":
        return _failed(
            "Recovery completion planning failed: "
            + "; ".join(completion_plan.get("errors") or [])
        )
    database_gate = completion_plan.get("database_gate") or {}
    if database_gate.get("status") != "VERIFIED":
        affected = [
            str(item.get("container") or "")
            for item in (database_gate.get("containers") or [])
            if item.get("quiescence_status") != "VERIFIED"
        ]
        return _failed(
            "Database consistency gate requires a clean stop before capture: "
            + ", ".join(value for value in affected if value)
        )
    requested_external_paths = [
        os.path.normpath(str(value or ""))
        for value in (selected_external_paths or [])
    ]
    allowed_external_paths = {
        str(item.get("path") or "")
        for item in (completion_plan.get("external_bind_mounts") or [])
        if item.get("selected")
    }
    if (
        len(requested_external_paths) != len(set(requested_external_paths))
        or set(requested_external_paths) != allowed_external_paths
    ):
        return _failed(
            "Selected external bind scope is not an exact current Docker bind source."
        )

    measurement = measure_full_appdata(command_runner)
    if measurement.get("measurement_status") != "MEASURED":
        return _failed("All AppData measurement is not fully verified.")
    if measurement.get("device") == destination.get("device"):
        return _failed("All AppData and the destination use the same canonical filesystem device.")
    if measurement.get("mount_boundaries_skipped"):
        return _failed("All AppData contains nested filesystem boundaries; v0.8 will not silently skip them.")
    if measurement.get("special_entries"):
        return _failed("All AppData contains unsupported special filesystem entries.")
    app_definitions = measure_casaos_apps(command_runner)
    if app_definitions.get("measurement_status") != "MEASURED":
        return _failed("Custom App definition measurement is not fully verified.")
    if app_definitions.get("mount_boundaries_skipped") or app_definitions.get("special_entries"):
        return _failed("Custom App definitions contain unsupported entries or filesystem boundaries.")
    if app_definitions.get("device") == destination.get("device"):
        return _failed("Custom App definitions and the destination use the same canonical filesystem device.")
    named_volumes = collect_named_volume_measurements(docker_get, command_runner)
    if named_volumes.get("measurement_status") != "MEASURED":
        return _failed("Docker named-volume measurement is not fully verified: " + "; ".join(named_volumes.get("errors") or []))
    if destination.get("device") in set(named_volumes.get("devices") or []):
        return _failed("Docker named volumes and the destination use the same canonical filesystem device.")
    external_binds = collect_selected_external_bind_measurements(
        selected_external_paths or [],
        command_runner,
    )
    if external_binds.get("measurement_status") != "MEASURED":
        return _failed(
            "Selected external bind measurement failed: "
            + "; ".join(external_binds.get("errors") or [])
        )
    if destination.get("device") in set(external_binds.get("devices") or []):
        return _failed("A selected external bind and the destination use the same canonical filesystem device.")

    logical_bytes = int(measurement.get("regular_file_bytes", 0) or 0)
    if logical_bytes > MAX_FULL_SOURCE_BYTES:
        return _failed(f"All AppData exceeds the v0.8 safety limit of {MAX_FULL_SOURCE_BYTES} bytes.")
    app_definition_bytes = int(app_definitions.get("regular_file_bytes", 0) or 0)
    if app_definition_bytes > MAX_APP_DEFINITION_BYTES:
        return _failed(f"Custom App definitions exceed the safety limit of {MAX_APP_DEFINITION_BYTES} bytes.")
    named_volume_bytes = int(named_volumes.get("regular_file_bytes", 0) or 0)
    if named_volume_bytes > MAX_NAMED_VOLUME_BYTES:
        return _failed(f"Docker named volumes exceed the safety limit of {MAX_NAMED_VOLUME_BYTES} bytes.")
    external_bind_bytes = int(external_binds.get("regular_file_bytes", 0) or 0)
    if external_bind_bytes > MAX_FULL_SOURCE_BYTES:
        return _failed(f"Selected external binds exceed the safety limit of {MAX_FULL_SOURCE_BYTES} bytes.")
    if int(destination.get("free_bytes", 0) or 0) < logical_bytes + app_definition_bytes + named_volume_bytes + external_bind_bytes + MINIMUM_OVERHEAD_BYTES:
        return _failed("Destination capacity no longer satisfies the execution reserve.")

    measured_external_paths = {
        str(item.get("requested_path") or "")
        for item in (external_binds.get("paths") or [])
    }
    if measured_external_paths != allowed_external_paths:
        return _failed("Selected external bind scope differs from Docker reconstruction evidence.")
    reconstruction_evidence["recovery_completion_plan"] = completion_plan
    reconstruction_size = len(
        json.dumps(
            reconstruction_evidence,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    if reconstruction_size > 16 * 1024 * 1024:
        return _failed("Private reconstruction evidence exceeds the 16 MiB safety limit.")

    snapshot_id = str(snapshot_id or generate_snapshot_id())
    if not snapshot_id or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        for character in snapshot_id
    ):
        return _failed("Snapshot identifier is invalid.")
    handoff_container_path = ""
    try:
        handoff_container_path, handoff_host_path = _write_reconstruction_handoff(
            snapshot_id,
            reconstruction_evidence,
        )
        completed = command_runner([
            "python3", "-c", CREATE_SNAPSHOT_SCRIPT,
            FULL_APPDATA_SOURCE,
            str(destination["mountpoint"]),
            snapshot_id,
            str(measurement["device"]),
            str(destination["device"]),
            str(logical_bytes),
            FULL_APPDATA_SOURCE,
            FULL_SNAPSHOT_DIRECTORY_NAME,
            "ALL APPDATA SNAPSHOT",
            CASAOS_APPS_SOURCE,
            str(app_definitions["device"]),
            str(app_definition_bytes),
            json.dumps(named_volumes.get("volumes") or [], sort_keys=True),
            str(int(measurement.get("regular_files", 0) or 0)),
            str(int(app_definitions.get("regular_files", 0) or 0)),
            handoff_host_path,
            json.dumps(external_binds.get("paths") or [], sort_keys=True),
        ], timeout=timeout)
    except Exception as exc:
        return _failed(f"All AppData snapshot runner failed: {exc}")
    finally:
        if handoff_container_path:
            try:
                os.unlink(handoff_container_path)
            except FileNotFoundError:
                pass
            except OSError:
                pass
    if not isinstance(completed, dict):
        return _failed("All AppData snapshot returned an invalid runner result.")
    stdout = str(completed.get("stdout") or "")
    if not completed.get("ok"):
        return _failed(str(completed.get("stderr") or stdout or "All AppData snapshot failed.").strip())
    try:
        result = json.loads(stdout)
    except Exception as exc:
        return _failed(f"All AppData snapshot returned invalid JSON: {exc}")
    if not isinstance(result, dict) or result.get("snapshot_id") != snapshot_id:
        return _failed("All AppData snapshot response did not match the requested execution.")
    manifest = result.get("manifest") or {}
    if result.get("snapshot_status") != "VERIFIED":
        return result
    if manifest.get("schema") != "zimabrain.snapshot.v1" or (manifest.get("source") or {}).get("requested_path") != FULL_APPDATA_SOURCE:
        return _failed("Completed All AppData manifest identity is invalid.", status="NOT VERIFIED")
    recovery_bundle = manifest.get("recovery_bundle") or {}
    app_component = (recovery_bundle.get("components") or {}).get("casaos_apps") or {}
    volume_component = (recovery_bundle.get("components") or {}).get("docker_named_volumes") or {}
    reconstruction_component = (
        (recovery_bundle.get("components") or {}).get("reconstruction_evidence")
        or {}
    )
    if recovery_bundle.get("status") != "VERIFIED" or app_component.get("requested_path") != CASAOS_APPS_SOURCE:
        return _failed("Completed snapshot is not a verified Custom App recovery bundle.", status="NOT VERIFIED")
    if app_component.get("device") != app_definitions.get("device"):
        return _failed("Completed Custom App definition device differs from preflight.", status="NOT VERIFIED")
    if volume_component.get("status") != "VERIFIED":
        return _failed("Completed Docker named-volume component is not verified.", status="NOT VERIFIED")
    if reconstruction_component.get("status") != "VERIFIED":
        return _failed("Completed private reconstruction evidence is not verified.", status="NOT VERIFIED")
    if int(reconstruction_component.get("container_count", -1)) != len(
        reconstruction_evidence.get("containers") or []
    ):
        return _failed("Completed container reconstruction count differs from preflight.", status="NOT VERIFIED")
    if int(volume_component.get("volume_count", -1)) != int(named_volumes.get("volume_count", 0) or 0):
        return _failed("Completed Docker named-volume count differs from preflight.", status="NOT VERIFIED")
    if int(volume_component.get("volatile_entries_skipped", -1)) != int(
        named_volumes.get("volatile_entries_skipped", 0) or 0
    ):
        return _failed("Completed Docker named-volume runtime-entry exclusions differ from preflight.", status="NOT VERIFIED")
    if (manifest.get("source") or {}).get("device") != measurement.get("device"):
        return _failed("Completed All AppData source device differs from preflight.", status="NOT VERIFIED")
    if (manifest.get("destination") or {}).get("device") != destination.get("device"):
        return _failed("Completed All AppData destination device differs from preflight.", status="NOT VERIFIED")
    return result


def _candidate_mountpoints(destination_inventory):
    return [
        str(item.get("mountpoint"))
        for item in (destination_inventory.get("destinations") or [])
        if item.get("decision") == "candidate" and item.get("mountpoint")
    ]


def collect_full_snapshot_progress(
    destination_inventory,
    command_runner,
    snapshot_id,
    timeout=60,
):
    snapshot_id = str(snapshot_id or "")
    if not snapshot_id:
        return {
            "schema": "zimabrain.snapshot-progress.v1",
            "snapshot_id": "",
            "status": "NOT STARTED",
            "phase": "No snapshot operation is active",
            "percent": 0.0,
            "errors": [],
        }
    mountpoints = _candidate_mountpoints(destination_inventory)
    if not mountpoints:
        return _failed("No verified destination is available for snapshot progress.")
    try:
        completed = command_runner(
            [
                "python3",
                "-c",
                READ_FULL_SNAPSHOT_PROGRESS_SCRIPT,
                json.dumps(mountpoints),
                snapshot_id,
            ],
            timeout=timeout,
        )
    except Exception as exc:
        return _failed(f"Snapshot progress collection failed: {exc}")
    if not isinstance(completed, dict):
        return _failed("Snapshot progress collection returned an invalid result.")
    stdout = str(completed.get("stdout") or "")
    if not completed.get("ok"):
        return _failed(str(completed.get("stderr") or stdout or "Snapshot progress collection failed.").strip())
    try:
        result = json.loads(stdout)
    except Exception as exc:
        return _failed(f"Snapshot progress collection returned invalid JSON: {exc}")
    if not isinstance(result, dict) or result.get("snapshot_id") != snapshot_id:
        return _failed("Snapshot progress identity does not match the active operation.")
    result.setdefault("errors", [])
    return result


def cancel_full_appdata_snapshot(
    destination_inventory,
    command_runner,
    snapshot_id,
    timeout=60,
):
    snapshot_id = str(snapshot_id or "")
    mountpoints = _candidate_mountpoints(destination_inventory)
    if not snapshot_id or not mountpoints:
        return _failed("Snapshot cancellation identity or destination inventory is unavailable.")
    try:
        completed = command_runner(
            [
                "python3",
                "-c",
                CANCEL_FULL_SNAPSHOT_SCRIPT,
                json.dumps(mountpoints),
                snapshot_id,
            ],
            timeout=timeout,
        )
    except Exception as exc:
        return _failed(f"Snapshot cancellation failed: {exc}")
    if not isinstance(completed, dict):
        return _failed("Snapshot cancellation returned an invalid result.")
    stdout = str(completed.get("stdout") or "")
    if not completed.get("ok"):
        return _failed(str(completed.get("stderr") or stdout or "Snapshot cancellation failed.").strip())
    try:
        result = json.loads(stdout)
    except Exception as exc:
        return _failed(f"Snapshot cancellation returned invalid JSON: {exc}")
    return result if isinstance(result, dict) else _failed("Snapshot cancellation returned a non-object result.")


def collect_latest_verified_full_snapshot(
    destination_inventory,
    command_runner,
    timeout=600,
    page_progress_path="",
    page_progress_stage=(0.0, 100.0),
    page_progress_started_at=0.0,
):
    mountpoints = [
        str(item.get("mountpoint"))
        for item in (destination_inventory.get("destinations") or [])
        if item.get("decision") == "candidate" and item.get("mountpoint")
    ]
    if not mountpoints:
        return {"verification_status": "NOT CREATED", "snapshot_status": "NOT CREATED", "manifest": None, "errors": []}
    try:
        completed = command_runner([
            "python3", "-c", DISCOVER_SNAPSHOT_SCRIPT, json.dumps(mountpoints),
            FULL_SNAPSHOT_DIRECTORY_NAME, FULL_APPDATA_SOURCE,
            str(page_progress_path or ""),
            str(float(page_progress_stage[0])),
            str(float(page_progress_stage[1])),
            str(float(page_progress_started_at or 0.0)),
        ], timeout=timeout)
    except Exception as exc:
        return _failed(f"All AppData snapshot discovery failed: {exc}")
    if not isinstance(completed, dict):
        return _failed("All AppData snapshot discovery returned an invalid result.")
    stdout = str(completed.get("stdout") or "")
    if not completed.get("ok"):
        return _failed(str(completed.get("stderr") or stdout or "All AppData snapshot discovery failed."))
    try:
        result = json.loads(stdout)
    except Exception as exc:
        return _failed(f"All AppData snapshot discovery returned invalid JSON: {exc}")
    return result if isinstance(result, dict) else _failed("All AppData snapshot discovery returned a non-object result.")
