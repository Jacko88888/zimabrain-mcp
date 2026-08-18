"""Restricted, verifier-first restore testing for Snapshot Lab archives."""

import json

from brain import snapshot_executor
from brain import snapshot_inventory


LAB_TEST_SOURCE = snapshot_executor.LAB_TEST_SOURCE
SNAPSHOT_DIRECTORY_NAME = snapshot_executor.SNAPSHOT_DIRECTORY_NAME
RESTORE_DIRECTORY_NAME = "zimabrain-restore-tests"
FULL_RESTORE_DIRECTORY_NAME = "zimabrain-full-restore-tests"
LAB_RESTORE_MOUNTPOINT = "/DATA"
RESTORE_RESERVE_BYTES = 64 * 1024 * 1024
FULL_RECOVERY_OPERATION_TIMEOUT_SECONDS = 6 * 60 * 60


RESTORE_SCRIPT_COMMON = r'''import base64
import hashlib
import json
import os
import posixpath
import shutil
import stat
import sys
import tarfile
import time
from datetime import datetime, timezone

LAB_TEST_SOURCE = "/DATA/AppData/zimabrain-snapshot-lab"
FULL_APPDATA_SOURCE = "/DATA/AppData"
SNAPSHOT_DIRECTORY_NAME = "zimabrain-snapshots"
RESTORE_DIRECTORY_NAME = "zimabrain-restore-tests"
LAB_RESTORE_MOUNTPOINT = "/DATA"
RESTORE_RESERVE_BYTES = 64 * 1024 * 1024
ALLOW_EXTERNAL_SYMLINKS = False


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


def resolve_mount(path):
    matches = []
    with open("/proc/self/mountinfo", "r", encoding="utf-8") as handle:
        for line in handle:
            left, right = line.rstrip("\n").split(" - ", 1)
            fields = left.split()
            filesystem = right.split()
            mountpoint = decode_mount_path(fields[4]).rstrip("/") or "/"
            if path_is_under(path, mountpoint):
                matches.append({
                    "mountpoint": mountpoint,
                    "device": fields[2],
                    "filesystem": filesystem[0] if filesystem else "",
                    "source": decode_mount_path(filesystem[1]) if len(filesystem) > 1 else "",
                })
    if not matches:
        raise RuntimeError(f"No host mount resolves path: {path}")
    return max(matches, key=lambda item: len(item["mountpoint"]))


def hash_file(path, progress_callback=None):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if progress_callback is not None:
                progress_callback(len(chunk))
    return digest.hexdigest(), size


def require_regular_file(path, label, maximum_bytes=None):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"{label} is not a safe regular file.")
    if maximum_bytes is not None and info.st_size > maximum_bytes:
        raise RuntimeError(f"{label} exceeds its permitted size.")
    return info


def read_json_file(path, label, maximum_bytes=64 * 1024 * 1024):
    require_regular_file(path, label, maximum_bytes)
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} is not a JSON object.")
    return value


def relative_parts(relative):
    if relative == ".":
        return []
    if not isinstance(relative, str) or not relative or relative.startswith("/") or "\\" in relative:
        raise RuntimeError(f"Unsafe manifest path: {relative!r}")
    if any(ord(character) < 32 for character in relative):
        raise RuntimeError(f"Control character in manifest path: {relative!r}")
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise RuntimeError(f"Unsafe manifest path: {relative!r}")
    return parts


def validate_symlink_target(relative, target):
    if not isinstance(target, str) or not target or "\\" in target:
        raise RuntimeError(f"Unsafe symlink target for {relative}.")
    if any(ord(character) < 32 for character in target):
        raise RuntimeError(f"Control character in symlink target for {relative}.")
    if ALLOW_EXTERNAL_SYMLINKS:
        return
    if target.startswith("/"):
        raise RuntimeError(f"Unsafe symlink target for {relative}.")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), target))
    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
        raise RuntimeError(f"Symlink escapes the isolated restore tree: {relative}")


def manifest_entry_map(entries):
    if not isinstance(entries, list) or not entries:
        raise RuntimeError("Snapshot manifest contains no source entries.")
    mapped = {}
    for raw in entries:
        if not isinstance(raw, dict):
            raise RuntimeError("Snapshot manifest contains a non-object entry.")
        item = dict(raw)
        relative = item.get("relative_path")
        relative_parts(relative)
        if relative in mapped:
            raise RuntimeError(f"Duplicate manifest entry: {relative}")
        entry_type = item.get("type")
        if entry_type not in ("directory", "file", "symlink"):
            raise RuntimeError(f"Unsupported restore entry type for {relative}: {entry_type}")
        for key in ("mode", "uid", "gid", "mtime_ns"):
            try:
                item[key] = int(item[key])
            except Exception:
                raise RuntimeError(f"Invalid manifest {key} for {relative}.")
        if item["mode"] < 0 or item["mode"] > 0o7777 or item["uid"] < 0 or item["gid"] < 0:
            raise RuntimeError(f"Invalid manifest ownership or mode for {relative}.")
        if entry_type == "file":
            try:
                item["size"] = int(item["size"])
            except Exception:
                raise RuntimeError(f"Invalid manifest file size for {relative}.")
            checksum = str(item.get("sha256") or "")
            if item["size"] < 0 or len(checksum) != 64 or any(c not in "0123456789abcdef" for c in checksum):
                raise RuntimeError(f"Invalid manifest file evidence for {relative}.")
            item["sha256"] = checksum
        elif entry_type == "symlink":
            validate_symlink_target(relative, item.get("link_target"))
        mapped[relative] = item

    if "." not in mapped or mapped["."].get("type") != "directory":
        raise RuntimeError("Snapshot manifest does not contain its root directory.")
    for relative, item in mapped.items():
        if relative == ".":
            continue
        parts = relative_parts(relative)
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            if parent not in mapped or mapped[parent].get("type") != "directory":
                raise RuntimeError(f"Manifest parent is not a directory: {parent}")
    return mapped


def archive_entry_map(
    archive,
    archive_root="data",
    progress_callback=None,
    progress_file_callback=None,
):
    mapped = {}
    members = {}
    for member in archive.getmembers():
        name = member.name.rstrip("/")
        if name == archive_root:
            relative = "."
        elif name.startswith(archive_root + "/"):
            relative = name[len(archive_root + "/"):]
        else:
            raise RuntimeError(f"Archive contains an unexpected root: {member.name}")
        relative_parts(relative)
        if relative in mapped:
            raise RuntimeError(f"Archive contains a duplicate entry: {relative}")

        item = {
            "relative_path": relative,
            "mode": int(member.mode),
            "uid": int(member.uid),
            "gid": int(member.gid),
            "mtime_ns": int(float(member.mtime) * 1_000_000_000),
        }
        if member.isdir():
            item["type"] = "directory"
        elif member.issym():
            item["type"] = "symlink"
            item["link_target"] = member.linkname
            validate_symlink_target(relative, member.linkname)
        elif member.isfile() or member.islnk():
            item["type"] = "file"
            extracted = archive.extractfile(member)
            if extracted is None:
                raise RuntimeError(f"Archive file cannot be read: {relative}")
            digest = hashlib.sha256()
            size = 0
            with extracted:
                while True:
                    chunk = extracted.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
                    if progress_callback is not None:
                        progress_callback(len(chunk))
            item["size"] = size
            item["sha256"] = digest.hexdigest()
            if progress_file_callback is not None:
                progress_file_callback()
        else:
            raise RuntimeError(f"Archive contains an unsupported entry type: {relative}")
        mapped[relative] = item
        members[relative] = member
    return mapped, members


def compare_entry_maps(expected, actual, strict_mtime_ns=False):
    if set(expected) != set(actual):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        raise RuntimeError(f"Entry mismatch; missing={missing[:5]} extra={extra[:5]}")
    for relative, wanted in expected.items():
        found = actual[relative]
        for key in ("type", "mode", "uid", "gid"):
            if found.get(key) != wanted.get(key):
                raise RuntimeError(f"Entry metadata mismatch for {relative}: {key}")
        if wanted["type"] == "file":
            for key in ("size", "sha256"):
                if found.get(key) != wanted.get(key):
                    raise RuntimeError(f"File evidence mismatch for {relative}: {key}")
        elif wanted["type"] == "symlink":
            if found.get("link_target") != wanted.get("link_target"):
                raise RuntimeError(f"Symlink target mismatch for {relative}")
        if strict_mtime_ns:
            if found.get("mtime_ns") != wanted.get("mtime_ns"):
                raise RuntimeError(f"Restored timestamp mismatch for {relative}")
        elif found.get("mtime_ns", 0) // 1_000_000_000 != wanted.get("mtime_ns", 0) // 1_000_000_000:
            raise RuntimeError(f"Archive timestamp mismatch for {relative}")


def tree_entry_signature(
    path,
    relative,
    root_device,
    progress_callback=None,
    progress_file_callback=None,
):
    info = os.lstat(path)
    if info.st_dev != root_device:
        raise RuntimeError(f"Restored tree crosses a filesystem boundary: {relative}")
    item = {
        "relative_path": relative,
        "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mtime_ns": info.st_mtime_ns,
    }
    if stat.S_ISDIR(info.st_mode):
        item["type"] = "directory"
    elif stat.S_ISLNK(info.st_mode):
        item["type"] = "symlink"
        item["link_target"] = os.readlink(path)
    elif stat.S_ISREG(info.st_mode):
        item["type"] = "file"
        item["sha256"], item["size"] = hash_file(
            path,
            progress_callback=progress_callback,
        )
        if progress_file_callback is not None:
            progress_file_callback()
    else:
        raise RuntimeError(f"Restored tree contains a special entry: {relative}")
    return item


def scan_tree(
    root,
    progress_callback=None,
    progress_file_callback=None,
):
    root_info = os.lstat(root)
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise RuntimeError("Restored data root is not a safe directory.")
    root_device = root_info.st_dev
    mapped = {}
    pending = [(root, ".")]
    while pending:
        path, relative = pending.pop()
        item = tree_entry_signature(
            path,
            relative,
            root_device,
            progress_callback=progress_callback,
            progress_file_callback=progress_file_callback,
        )
        mapped[relative] = item
        if item["type"] == "directory":
            with os.scandir(path) as children:
                ordered = sorted(children, key=lambda child: child.name, reverse=True)
                for child in ordered:
                    child_relative = child.name if relative == "." else relative + "/" + child.name
                    relative_parts(child_relative)
                    pending.append((child.path, child_relative))
    return mapped


def fsync_file(path):
    with open(path, "rb") as handle:
        os.fsync(handle.fileno())


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def apply_xattr_metadata(root, records):
    applied = 0
    for record in records or []:
        if not isinstance(record, dict):
            raise RuntimeError("Filesystem metadata record is invalid.")
        relative = str(record.get("relative_path") or "")
        if not relative or relative.startswith("/") or ".." in relative.split("/"):
            raise RuntimeError("Filesystem metadata path is unsafe.")
        path = root if relative == "." else os.path.join(root, relative)
        if not os.path.lexists(path):
            raise RuntimeError("Filesystem metadata target is missing: " + relative)
        attributes = record.get("attributes") or {}
        if not isinstance(attributes, dict):
            raise RuntimeError("Filesystem metadata attributes are invalid.")
        for name, encoded in attributes.items():
            value = base64.b64decode(str(encoded), validate=True)
            os.setxattr(path, str(name), value, follow_symlinks=False)
            actual = os.getxattr(path, str(name), follow_symlinks=False)
            if actual != value:
                raise RuntimeError("Restored extended attribute differs: " + relative)
            applied += 1
    return applied


def safe_target(root, relative):
    parts = relative_parts(relative)
    path = root if not parts else os.path.join(root, *parts)
    if not path_is_under(path, root):
        raise RuntimeError(f"Restore path escapes its isolated root: {relative}")
    return path


def apply_metadata(path, item):
    if item["type"] == "symlink":
        os.lchown(path, item["uid"], item["gid"])
        os.utime(path, ns=(item["mtime_ns"], item["mtime_ns"]), follow_symlinks=False)
        return
    os.chown(path, item["uid"], item["gid"], follow_symlinks=False)
    os.chmod(path, item["mode"], follow_symlinks=False)
    os.utime(path, ns=(item["mtime_ns"], item["mtime_ns"]), follow_symlinks=False)


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


def initialize_progress(path, identifier, work_total, logical_total, files_total):
    global progress_path, progress_state, progress_started, progress_last_write
    progress_path = path
    progress_started = time.monotonic()
    progress_last_write = 0.0
    progress_state = {
        "schema": "zimabrain.restore-progress.v1",
        "snapshot_id": identifier,
        "status": "RUNNING",
        "phase": "Starting isolated recovery",
        "work_bytes_processed": 0,
        "work_bytes_total": max(1, int(work_total)),
        "restored_bytes": 0,
        "logical_bytes_total": max(0, int(logical_total)),
        "restored_files": 0,
        "files_total": max(0, int(files_total)),
        "error": "",
    }
    publish_progress(force=True)


def set_progress_phase(phase):
    if progress_state is not None:
        progress_state["phase"] = str(phase)
        publish_progress(force=True)


def advance_work(byte_count, restored_bytes=0):
    if progress_state is not None:
        progress_state["work_bytes_processed"] += max(0, int(byte_count))
        progress_state["restored_bytes"] += max(0, int(restored_bytes))
        publish_progress()


def record_restored_file():
    if progress_state is not None:
        progress_state["restored_files"] += 1
        publish_progress()


def finish_progress(status, phase, error=""):
    if progress_state is not None:
        progress_state["status"] = str(status)
        progress_state["phase"] = str(phase)
        progress_state["error"] = str(error)
        if status == "VERIFIED":
            progress_state["work_bytes_processed"] = progress_state["work_bytes_total"]
            progress_state["restored_bytes"] = progress_state["logical_bytes_total"]
            progress_state["restored_files"] = progress_state["files_total"]
        publish_progress(force=True)


def restore_archive_component(
    archive_path,
    expected_entries,
    restored_root,
    archive_root,
    component_label="data",
):
    os.mkdir(restored_root, 0o700)
    with tarfile.open(archive_path, mode="r") as archive_handle:
        set_progress_phase("Validating " + component_label + " archive")
        archive_entries, archive_members = archive_entry_map(
            archive_handle,
            archive_root=archive_root,
            progress_callback=advance_work,
        )
        compare_entry_maps(expected_entries, archive_entries)
        directories = sorted(
            (item for item in expected_entries.values() if item["type"] == "directory" and item["relative_path"] != "."),
            key=lambda item: len(relative_parts(item["relative_path"])),
        )
        for item in directories:
            os.mkdir(safe_target(restored_root, item["relative_path"]), 0o700)
        set_progress_phase("Restoring " + component_label)
        for relative in sorted(expected_entries):
            item = expected_entries[relative]
            if item["type"] == "directory":
                continue
            target = safe_target(restored_root, relative)
            if os.path.lexists(target):
                raise RuntimeError(f"Restore target unexpectedly exists: {relative}")
            if item["type"] == "file":
                extracted = archive_handle.extractfile(archive_members[relative])
                if extracted is None:
                    raise RuntimeError(f"Archive file cannot be restored: {relative}")
                with extracted, open(target, "xb") as output:
                    while True:
                        chunk = extracted.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)
                        advance_work(
                            len(chunk),
                            restored_bytes=len(chunk),
                        )
                    output.flush()
                    os.fsync(output.fileno())
                record_restored_file()
            elif item["type"] == "symlink":
                os.symlink(item["link_target"], target)
            apply_metadata(target, item)
    for item in sorted(
        (entry for entry in expected_entries.values() if entry["type"] == "directory"),
        key=lambda entry: len(relative_parts(entry["relative_path"])),
        reverse=True,
    ):
        directory_path = safe_target(restored_root, item["relative_path"])
        apply_metadata(directory_path, item)
        fsync_directory(directory_path)
    set_progress_phase("Verifying restored " + component_label)
    restored_entries = scan_tree(
        restored_root,
        progress_callback=advance_work,
    )
    compare_entry_maps(expected_entries, restored_entries, strict_mtime_ns=True)
    return restored_entries
'''


RESTORE_TEST_SCRIPT = RESTORE_SCRIPT_COMMON + r'''
manifest_path = sys.argv[1]
archive_path = sys.argv[2]
destination = sys.argv[3]
snapshot_id = sys.argv[4]
expected_destination_device = sys.argv[5]
expected_archive_sha256 = sys.argv[6]
expected_archive_bytes = int(sys.argv[7])
expected_logical_bytes = int(sys.argv[8])
expected_source = sys.argv[9] if len(sys.argv) > 9 else LAB_TEST_SOURCE
snapshot_directory_name = sys.argv[10] if len(sys.argv) > 10 else SNAPSHOT_DIRECTORY_NAME
restore_directory_name = sys.argv[11] if len(sys.argv) > 11 else RESTORE_DIRECTORY_NAME
restore_mode = sys.argv[12] if len(sys.argv) > 12 else "ISOLATED RESTRICTED LAB RESTORE TEST"

result = {
    "mode": "restricted-lab-restore-test",
    "execution_status": "FAILED",
    "restore_status": "NOT TESTED",
    "verification_status": "NOT VERIFIED",
    "snapshot_id": snapshot_id,
    "errors": [],
}
pending_path = ""
base_path = ""
base_created = False

try:
    if not snapshot_id or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in snapshot_id):
        raise RuntimeError("Snapshot identifier is invalid.")
    destination_resolved = os.path.realpath(destination)
    lab_restore = (
        expected_source == LAB_TEST_SOURCE
        and snapshot_directory_name == SNAPSHOT_DIRECTORY_NAME
        and restore_directory_name == RESTORE_DIRECTORY_NAME
    )
    full_restore = (
        expected_source == FULL_APPDATA_SOURCE
        and snapshot_directory_name == "zimabrain-full-snapshots"
        and restore_directory_name == "zimabrain-full-restore-tests"
    )
    if not lab_restore and not full_restore:
        raise RuntimeError("Restore source and directory class are not authorized.")
    if os.path.normpath(destination) != destination_resolved:
        raise RuntimeError("Restore destination is not a canonical host path.")
    if lab_restore and destination_resolved != LAB_RESTORE_MOUNTPOINT:
        raise RuntimeError("Restricted Lab restore testing is limited to /DATA.")
    if full_restore and not any(
        destination_resolved == root
        or destination_resolved.startswith(root + "/")
        for root in ("/DATA", "/media", "/mnt")
    ):
        raise RuntimeError("All AppData restore destination is outside an approved mount root.")
    destination_mount = resolve_mount(destination_resolved)
    if destination_resolved != destination_mount["mountpoint"]:
        raise RuntimeError("Restore destination no longer resolves to its selected mountpoint.")
    if destination_mount["device"] != expected_destination_device:
        raise RuntimeError("Restore destination filesystem device changed after preflight.")

    ALLOW_EXTERNAL_SYMLINKS = full_restore

    if snapshot_directory_name not in ("zimabrain-snapshots", "zimabrain-full-snapshots"):
        raise RuntimeError("Snapshot directory class is not authorized.")
    if restore_directory_name not in ("zimabrain-restore-tests", "zimabrain-full-restore-tests"):
        raise RuntimeError("Restore directory class is not authorized.")
    snapshot_path = os.path.join(destination_resolved, snapshot_directory_name, snapshot_id)
    expected_manifest_path = os.path.join(snapshot_path, "manifest.json")
    if os.path.normpath(manifest_path) != expected_manifest_path or os.path.realpath(manifest_path) != expected_manifest_path:
        raise RuntimeError("Snapshot manifest path is outside the verified snapshot directory.")
    manifest = read_json_file(manifest_path, "Snapshot manifest")
    if manifest.get("schema") != "zimabrain.snapshot.v1":
        raise RuntimeError("Snapshot manifest schema is invalid.")
    if manifest.get("snapshot_id") != snapshot_id:
        raise RuntimeError("Snapshot manifest identifier changed after preflight.")
    if manifest.get("snapshot_status") != "VERIFIED" or manifest.get("verification_status") != "VERIFIED":
        raise RuntimeError("Snapshot manifest is not verified.")
    source = manifest.get("source") or {}
    if source.get("requested_path") != expected_source:
        raise RuntimeError("Snapshot source differs from the server-authorized restore source.")
    manifest_destination = manifest.get("destination") or {}
    if manifest_destination.get("mountpoint") != destination_resolved:
        raise RuntimeError("Snapshot manifest destination mountpoint differs from restore preflight.")
    if manifest_destination.get("device") != expected_destination_device:
        raise RuntimeError("Snapshot manifest destination device differs from restore preflight.")

    base_path = os.path.join(destination_resolved, restore_directory_name)
    final_path = os.path.join(base_path, snapshot_id)
    pending_path = os.path.join(base_path, ".pending-" + snapshot_id)
    live_source_resolved = os.path.realpath(expected_source)
    if paths_overlap(live_source_resolved, base_path) or paths_overlap(snapshot_path, base_path):
        raise RuntimeError("Isolated restore target overlaps live source or snapshot storage.")
    if os.path.lexists(final_path) or os.path.lexists(pending_path):
        raise RuntimeError("Restore-test identifier already exists; existing data will not be overwritten.")
    if os.path.lexists(base_path):
        info = os.lstat(base_path)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RuntimeError("Restore-test base path is not a safe directory.")
    else:
        os.mkdir(base_path, 0o700)
        base_created = True

    raw_recovery = manifest.get("recovery_bundle") or {}
    raw_components = raw_recovery.get("components") or {}
    raw_app = raw_components.get("casaos_apps") or {}
    raw_volumes = raw_components.get("docker_named_volumes") or {}
    raw_reconstruction = raw_components.get("reconstruction_evidence") or {}
    raw_external = raw_components.get("selected_external_binds") or {}
    raw_metadata = raw_components.get("filesystem_metadata") or {}
    raw_volume_records = raw_volumes.get("volumes") or []
    raw_external_records = raw_external.get("paths") or []
    logical_total = int(source.get("regular_file_bytes", 0) or 0)
    logical_total += int(raw_app.get("regular_file_bytes", 0) or 0)
    logical_total += sum(
        int(item.get("regular_file_bytes", 0) or 0)
        for item in raw_volume_records
        if isinstance(item, dict)
    )
    logical_total += sum(
        int(item.get("regular_file_bytes", 0) or 0)
        for item in raw_external_records
        if isinstance(item, dict)
    )
    files_total = int(source.get("regular_files", 0) or 0)
    files_total += int(raw_app.get("regular_files", 0) or 0)
    files_total += sum(
        int(item.get("regular_files", 0) or 0)
        for item in raw_volume_records
        if isinstance(item, dict)
    )
    files_total += sum(
        int(item.get("regular_files", 0) or 0)
        for item in raw_external_records
        if isinstance(item, dict)
    )
    stored_total = int((manifest.get("archive") or {}).get("stored_bytes", 0) or 0)
    stored_total += int(raw_app.get("stored_bytes", 0) or 0)
    stored_total += sum(
        int(item.get("stored_bytes", 0) or 0)
        for item in raw_volume_records
        if isinstance(item, dict)
    )
    stored_total += int(raw_reconstruction.get("stored_bytes", 0) or 0)
    stored_total += sum(
        int(item.get("stored_bytes", 0) or 0)
        for item in raw_external_records
        if isinstance(item, dict)
    )
    stored_total += int(raw_metadata.get("stored_bytes", 0) or 0)
    initialize_progress(
        os.path.join(base_path, ".progress-" + snapshot_id + ".json"),
        snapshot_id,
        stored_total + (logical_total * 3),
        logical_total,
        files_total,
    )

    archive = manifest.get("archive") or {}
    filename = str(archive.get("filename") or "")
    if not filename or os.path.basename(filename) != filename:
        raise RuntimeError("Snapshot manifest contains an unsafe archive filename.")
    expected_archive_path = os.path.join(snapshot_path, filename)
    if os.path.normpath(archive_path) != expected_archive_path or os.path.realpath(archive_path) != expected_archive_path:
        raise RuntimeError("Snapshot archive path is outside the verified snapshot directory.")
    require_regular_file(archive_path, "Snapshot archive")
    set_progress_phase("Checking AppData archive checksum")
    archive_sha256, archive_bytes = hash_file(
        archive_path,
        progress_callback=advance_work,
    )
    if archive_sha256 != str(archive.get("sha256") or "") or archive_sha256 != expected_archive_sha256:
        raise RuntimeError("Snapshot archive SHA-256 changed after preflight.")
    if archive_bytes != int(archive.get("stored_bytes", -1)) or archive_bytes != expected_archive_bytes:
        raise RuntimeError("Snapshot archive byte count changed after preflight.")

    app_component = None
    app_archive_path = ""
    app_expected_entries = None
    app_logical_bytes = 0
    named_volume_components = []
    named_volume_logical_bytes = 0
    reconstruction_component = None
    reconstruction_source_path = ""
    external_bind_components = []
    external_bind_logical_bytes = 0
    metadata_component = None
    metadata_source_path = ""
    metadata_payload = {}
    if full_restore:
        recovery_bundle = manifest.get("recovery_bundle") or {}
        if recovery_bundle.get("status") != "VERIFIED":
            raise RuntimeError("All AppData snapshot is not a verified recovery bundle.")
        app_component = (recovery_bundle.get("components") or {}).get("casaos_apps") or {}
        if app_component.get("requested_path") != "/var/lib/casaos/apps":
            raise RuntimeError("Recovery bundle app-definition source is invalid.")
        app_filename = str(app_component.get("archive_filename") or "")
        if not app_filename or os.path.basename(app_filename) != app_filename:
            raise RuntimeError("Recovery bundle app-definition archive filename is unsafe.")
        app_archive_path = os.path.join(snapshot_path, app_filename)
        require_regular_file(app_archive_path, "Custom App definition archive")
        set_progress_phase("Checking Custom App definitions checksum")
        app_sha256, app_archive_bytes = hash_file(
            app_archive_path,
            progress_callback=advance_work,
        )
        if app_sha256 != app_component.get("sha256") or app_archive_bytes != int(app_component.get("stored_bytes", -1)):
            raise RuntimeError("Custom App definition archive no longer verifies.")
        app_expected_entries = manifest_entry_map(app_component.get("entries") or [])
        app_files = [item for item in app_expected_entries.values() if item["type"] == "file"]
        app_logical_bytes = sum(item["size"] for item in app_files)
        if app_logical_bytes != int(app_component.get("regular_file_bytes", -1)) or len(app_files) != int(app_component.get("regular_files", -1)):
            raise RuntimeError("Custom App definition manifest totals are inconsistent.")
        volume_component = (recovery_bundle.get("components") or {}).get("docker_named_volumes") or {}
        if volume_component:
            if volume_component.get("status") != "VERIFIED":
                raise RuntimeError("Docker named-volume component is not verified.")
            volume_records = volume_component.get("volumes") or []
            if not isinstance(volume_records, list) or len(volume_records) != int(volume_component.get("volume_count", -1)):
                raise RuntimeError("Docker named-volume inventory is inconsistent.")
            seen_volume_names = set()
            for volume in volume_records:
                if not isinstance(volume, dict):
                    raise RuntimeError("Docker named-volume record is invalid.")
                volume_name = str(volume.get("name") or "")
                if (
                    not volume_name
                    or volume_name in seen_volume_names
                    or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for character in volume_name)
                ):
                    raise RuntimeError("Docker named-volume identity is invalid or duplicated.")
                volume_filename = str(volume.get("archive_filename") or "")
                if not volume_filename or os.path.basename(volume_filename) != volume_filename:
                    raise RuntimeError(f"Docker named-volume archive filename is unsafe: {volume_name}")
                volume_archive_path = os.path.join(snapshot_path, volume_filename)
                require_regular_file(volume_archive_path, f"Docker named-volume archive {volume_name}")
                set_progress_phase("Checking Docker volume " + volume_name + " checksum")
                volume_sha256, volume_archive_bytes = hash_file(
                    volume_archive_path,
                    progress_callback=advance_work,
                )
                if volume_sha256 != volume.get("sha256") or volume_archive_bytes != int(volume.get("stored_bytes", -1)):
                    raise RuntimeError(f"Docker named-volume archive no longer verifies: {volume_name}")
                volume_entries = manifest_entry_map(volume.get("entries") or [])
                volume_files = [item for item in volume_entries.values() if item["type"] == "file"]
                volume_bytes = sum(item["size"] for item in volume_files)
                if volume_bytes != int(volume.get("regular_file_bytes", -1)) or len(volume_files) != int(volume.get("regular_files", -1)):
                    raise RuntimeError(f"Docker named-volume manifest totals are inconsistent: {volume_name}")
                named_volume_components.append({
                    "name": volume_name,
                    "archive_path": volume_archive_path,
                    "entries": volume_entries,
                    "logical_bytes": volume_bytes,
                })
                named_volume_logical_bytes += volume_bytes
                seen_volume_names.add(volume_name)
        external_component = (
            (recovery_bundle.get("components") or {}).get("selected_external_binds")
            or {}
        )
        if external_component:
            if external_component.get("status") not in {"VERIFIED", "NOT SELECTED"}:
                raise RuntimeError("Selected external bind component is not verified.")
            external_records = external_component.get("paths") or []
            if not isinstance(external_records, list) or len(external_records) != int(
                external_component.get("path_count", -1)
            ):
                raise RuntimeError("Selected external bind inventory is inconsistent.")
            seen_external_paths = set()
            for index, external in enumerate(external_records):
                if not isinstance(external, dict):
                    raise RuntimeError("Selected external bind record is invalid.")
                requested_path = str(external.get("requested_path") or "")
                if not requested_path or requested_path in seen_external_paths:
                    raise RuntimeError("Selected external bind identity is invalid or duplicated.")
                filename_external = str(external.get("archive_filename") or "")
                if not filename_external or os.path.basename(filename_external) != filename_external:
                    raise RuntimeError("Selected external bind archive filename is unsafe.")
                archive_path_external = os.path.join(snapshot_path, filename_external)
                require_regular_file(archive_path_external, "Selected external bind archive")
                set_progress_phase("Checking selected external bind checksum")
                sha_external, stored_external = hash_file(
                    archive_path_external,
                    progress_callback=advance_work,
                )
                if (
                    sha_external != external.get("sha256")
                    or stored_external != int(external.get("stored_bytes", -1))
                ):
                    raise RuntimeError("Selected external bind archive no longer verifies.")
                entries_external = manifest_entry_map(external.get("entries") or [])
                files_external = [item for item in entries_external.values() if item["type"] == "file"]
                bytes_external = sum(item["size"] for item in files_external)
                if (
                    bytes_external != int(external.get("regular_file_bytes", -1))
                    or len(files_external) != int(external.get("regular_files", -1))
                ):
                    raise RuntimeError("Selected external bind manifest totals are inconsistent.")
                external_bind_components.append({
                    "index": index,
                    "requested_path": requested_path,
                    "archive_path": archive_path_external,
                    "entries": entries_external,
                    "logical_bytes": bytes_external,
                })
                external_bind_logical_bytes += bytes_external
                seen_external_paths.add(requested_path)
        candidate_metadata = (
            (recovery_bundle.get("components") or {}).get("filesystem_metadata")
            or {}
        )
        if candidate_metadata:
            if candidate_metadata.get("status") != "VERIFIED":
                raise RuntimeError("Filesystem metadata sidecar is not verified.")
            metadata_filename = str(candidate_metadata.get("filename") or "")
            if metadata_filename != "filesystem-metadata.private.json":
                raise RuntimeError("Filesystem metadata sidecar filename is unsafe.")
            metadata_source_path = os.path.join(snapshot_path, metadata_filename)
            require_regular_file(metadata_source_path, "Filesystem metadata sidecar")
            set_progress_phase("Checking ACL and extended-attribute metadata")
            metadata_sha256, metadata_bytes = hash_file(
                metadata_source_path,
                progress_callback=advance_work,
            )
            if (
                metadata_sha256 != candidate_metadata.get("sha256")
                or metadata_bytes != int(candidate_metadata.get("stored_bytes", -1))
            ):
                raise RuntimeError("Filesystem metadata sidecar no longer verifies.")
            with open(metadata_source_path, "r", encoding="utf-8") as handle:
                metadata_payload = json.load(handle)
            if metadata_payload.get("schema") != "zimabrain.filesystem-metadata.v1":
                raise RuntimeError("Filesystem metadata sidecar schema is invalid.")
            metadata_component = candidate_metadata
        candidate_reconstruction = (
            (recovery_bundle.get("components") or {}).get(
                "reconstruction_evidence"
            )
            or {}
        )
        if candidate_reconstruction:
            if candidate_reconstruction.get("status") != "VERIFIED":
                raise RuntimeError("Private reconstruction evidence is not verified.")
            reconstruction_filename = str(
                candidate_reconstruction.get("filename") or ""
            )
            if reconstruction_filename != "reconstruction-evidence.private.json":
                raise RuntimeError("Private reconstruction evidence filename is unsafe.")
            reconstruction_source_path = os.path.join(
                snapshot_path,
                reconstruction_filename,
            )
            require_regular_file(
                reconstruction_source_path,
                "Private reconstruction evidence",
            )
            set_progress_phase("Checking private reconstruction evidence")
            reconstruction_sha256, reconstruction_bytes = hash_file(
                reconstruction_source_path,
                progress_callback=advance_work,
            )
            if (
                reconstruction_sha256 != candidate_reconstruction.get("sha256")
                or reconstruction_bytes
                != int(candidate_reconstruction.get("stored_bytes", -1))
            ):
                raise RuntimeError("Private reconstruction evidence no longer verifies.")
            with open(reconstruction_source_path, "r", encoding="utf-8") as handle:
                reconstruction_payload = json.load(handle)
            if (
                not isinstance(reconstruction_payload, dict)
                or reconstruction_payload.get("schema")
                != "zimabrain.reconstruction-evidence.v1"
                or reconstruction_payload.get("capture_status") != "VERIFIED"
            ):
                raise RuntimeError("Private reconstruction evidence content is invalid.")
            reconstruction_component = candidate_reconstruction

    expected_entries = manifest_entry_map(manifest.get("entries") or [])
    regular_files = [item for item in expected_entries.values() if item["type"] == "file"]
    logical_bytes = sum(item["size"] for item in regular_files)
    if logical_bytes != int(source.get("regular_file_bytes", -1)) or logical_bytes != expected_logical_bytes:
        raise RuntimeError("Snapshot logical byte evidence changed after preflight.")
    if len(regular_files) != int(source.get("regular_files", -1)):
        raise RuntimeError("Snapshot regular-file count is inconsistent.")

    stats_before = os.statvfs(destination_resolved)
    free_before = stats_before.f_bavail * stats_before.f_frsize
    if free_before < (
        logical_bytes
        + app_logical_bytes
        + named_volume_logical_bytes
        + external_bind_logical_bytes
        + RESTORE_RESERVE_BYTES
    ):
        raise RuntimeError("Restore destination capacity no longer satisfies the execution reserve.")

    os.mkdir(pending_path, 0o700)
    restored_reconstruction_path = ""
    restored_metadata_path = ""
    if reconstruction_component:
        set_progress_phase("Restoring private reconstruction evidence")
        restored_reconstruction_path = os.path.join(
            pending_path,
            "reconstruction-evidence.private.json",
        )
        shutil.copyfile(
            reconstruction_source_path,
            restored_reconstruction_path,
        )
        os.chmod(restored_reconstruction_path, 0o600)
        fsync_file(restored_reconstruction_path)
        restored_reconstruction_sha256, restored_reconstruction_bytes = hash_file(
            restored_reconstruction_path,
            progress_callback=advance_work,
        )
        if (
            restored_reconstruction_sha256
            != reconstruction_component.get("sha256")
            or restored_reconstruction_bytes
            != int(reconstruction_component.get("stored_bytes", -1))
        ):
            raise RuntimeError("Restored private reconstruction evidence differs from the snapshot.")
    if metadata_component:
        set_progress_phase("Restoring filesystem metadata sidecar")
        restored_metadata_path = os.path.join(
            pending_path,
            "filesystem-metadata.private.json",
        )
        shutil.copyfile(metadata_source_path, restored_metadata_path)
        os.chmod(restored_metadata_path, 0o600)
        fsync_file(restored_metadata_path)
        restored_metadata_sha256, restored_metadata_bytes = hash_file(
            restored_metadata_path,
            progress_callback=advance_work,
        )
        if (
            restored_metadata_sha256 != metadata_component.get("sha256")
            or restored_metadata_bytes != int(metadata_component.get("stored_bytes", -1))
        ):
            raise RuntimeError("Restored filesystem metadata sidecar differs from the snapshot.")
    restored_root = os.path.join(pending_path, "data")
    restored_entries = restore_archive_component(
        archive_path,
        expected_entries,
        restored_root,
        "data",
        "AppData",
    )
    restored_apps_root = ""
    restored_app_entries = {}
    if app_expected_entries is not None:
        restored_apps_root = os.path.join(pending_path, "casaos-apps")
        restored_app_entries = restore_archive_component(
            app_archive_path,
            app_expected_entries,
            restored_apps_root,
            "casaos-apps",
            "Custom App definitions",
        )
    restored_named_volumes = []
    restored_volumes_root = ""
    if named_volume_components:
        restored_volumes_root = os.path.join(pending_path, "docker-volumes")
        os.mkdir(restored_volumes_root, 0o700)
    for volume in named_volume_components:
        restored_volume_root = os.path.join(restored_volumes_root, volume["name"])
        restored_volume_entries = restore_archive_component(
            volume["archive_path"],
            volume["entries"],
            restored_volume_root,
            "volume-data",
            "Docker volume " + volume["name"],
        )
        restored_named_volumes.append({
            "name": volume["name"],
            "path": restored_volume_root,
            "regular_file_bytes": sum(
                item.get("size", 0)
                for item in restored_volume_entries.values()
                if item.get("type") == "file"
            ),
            "regular_files": sum(
                item.get("type") == "file"
                for item in restored_volume_entries.values()
            ),
            "directories": sum(
                item.get("type") == "directory"
                for item in restored_volume_entries.values()
            ),
            "symlinks": sum(
                item.get("type") == "symlink"
                for item in restored_volume_entries.values()
            ),
        })
    if restored_volumes_root:
        fsync_directory(restored_volumes_root)
    restored_external_binds = []
    restored_external_root = ""
    if external_bind_components:
        restored_external_root = os.path.join(pending_path, "external-binds")
        os.mkdir(restored_external_root, 0o700)
    for external in external_bind_components:
        restored_external_path = os.path.join(
            restored_external_root,
            f"bind-{external['index']:04d}",
        )
        restored_external_entries = restore_archive_component(
            external["archive_path"],
            external["entries"],
            restored_external_path,
            "external-data",
            "Selected external bind",
        )
        restored_external_binds.append({
            "requested_path": external["requested_path"],
            "path": restored_external_path,
            "regular_file_bytes": sum(
                item.get("size", 0)
                for item in restored_external_entries.values()
                if item.get("type") == "file"
            ),
            "regular_files": sum(
                item.get("type") == "file" for item in restored_external_entries.values()
            ),
        })
    if restored_external_root:
        fsync_directory(restored_external_root)
    xattrs_applied = 0
    if metadata_component:
        metadata_components = metadata_payload.get("components") or {}
        xattrs_applied += apply_xattr_metadata(
            restored_root,
            metadata_components.get("appdata") or [],
        )
        if restored_apps_root:
            xattrs_applied += apply_xattr_metadata(
                restored_apps_root,
                metadata_components.get("casaos_apps") or [],
            )
        volume_metadata = {
            str(item.get("name") or ""): item.get("records") or []
            for item in (metadata_components.get("docker_named_volumes") or [])
            if isinstance(item, dict)
        }
        for volume in restored_named_volumes:
            xattrs_applied += apply_xattr_metadata(
                volume["path"],
                volume_metadata.get(volume["name"]) or [],
            )
        external_metadata = {
            str(item.get("requested_path") or ""): item.get("records") or []
            for item in (metadata_components.get("selected_external_binds") or [])
            if isinstance(item, dict)
        }
        for external in restored_external_binds:
            xattrs_applied += apply_xattr_metadata(
                external["path"],
                external_metadata.get(external["requested_path"]) or [],
            )
    restored_files = [item for item in restored_entries.values() if item["type"] == "file"]
    restored_bytes = sum(item["size"] for item in restored_files)
    if restored_bytes != logical_bytes or len(restored_files) != len(regular_files):
        raise RuntimeError("Restored totals differ from the captured source manifest.")

    manifest_sha256, manifest_bytes = hash_file(manifest_path)
    stats_after = os.statvfs(destination_resolved)
    free_after = stats_after.f_bavail * stats_after.f_frsize
    created_at = datetime.now(timezone.utc).isoformat()
    restore_manifest = {
        "schema": "zimabrain.restore-test.v1",
        "snapshot_id": snapshot_id,
        "restore_status": "VERIFIED",
        "verification_status": "VERIFIED",
        "mode": restore_mode,
        "created_at": created_at,
        "snapshot": {
            "manifest_path": manifest_path,
            "manifest_sha256": manifest_sha256,
            "manifest_bytes": manifest_bytes,
            "archive_path": archive_path,
            "archive_sha256": archive_sha256,
            "archive_bytes": archive_bytes,
        },
        "restore": {
            "path": final_path,
            "data_path": os.path.join(final_path, "data"),
            "device": destination_mount["device"],
            "filesystem": destination_mount["filesystem"],
            "mountpoint": destination_mount["mountpoint"],
            "regular_file_bytes": restored_bytes,
            "regular_files": len(restored_files),
            "directories": sum(item["type"] == "directory" for item in restored_entries.values()),
            "symlinks": sum(item["type"] == "symlink" for item in restored_entries.values()),
            "difference_bytes": restored_bytes - logical_bytes,
            "free_bytes_before": free_before,
            "free_bytes_after": free_after,
        },
        "components": {
            "appdata": {
                "path": os.path.join(final_path, "data"),
                "regular_file_bytes": restored_bytes,
                "regular_files": len(restored_files),
            },
            "casaos_apps": {
                "path": os.path.join(final_path, "casaos-apps") if restored_apps_root else "",
                "regular_file_bytes": sum(item.get("size", 0) for item in restored_app_entries.values() if item.get("type") == "file"),
                "regular_files": sum(item.get("type") == "file" for item in restored_app_entries.values()),
                "directories": sum(item.get("type") == "directory" for item in restored_app_entries.values()),
                "symlinks": sum(item.get("type") == "symlink" for item in restored_app_entries.values()),
            },
            "docker_named_volumes": {
                "status": "VERIFIED" if named_volume_components else "NOT INCLUDED",
                "path": os.path.join(final_path, "docker-volumes") if named_volume_components else "",
                "volume_count": len(restored_named_volumes),
                "regular_file_bytes": sum(item["regular_file_bytes"] for item in restored_named_volumes),
                "regular_files": sum(item["regular_files"] for item in restored_named_volumes),
                "volumes": [
                    {**item, "path": os.path.join(final_path, "docker-volumes", item["name"])}
                    for item in restored_named_volumes
                ],
            },
            "selected_external_binds": {
                "status": "VERIFIED" if external_bind_components else "NOT SELECTED",
                "path": os.path.join(final_path, "external-binds") if external_bind_components else "",
                "path_count": len(restored_external_binds),
                "regular_file_bytes": sum(item["regular_file_bytes"] for item in restored_external_binds),
                "regular_files": sum(item["regular_files"] for item in restored_external_binds),
                "paths": [
                    {
                        **item,
                        "path": os.path.join(final_path, "external-binds", f"bind-{index:04d}"),
                    }
                    for index, item in enumerate(restored_external_binds)
                ],
            },
            "reconstruction_evidence": {
                "status": "VERIFIED" if reconstruction_component else "NOT INCLUDED",
                "sensitivity": "PRIVATE_CONTAINS_CONFIGURATION_SECRETS",
                "path": (
                    os.path.join(
                        final_path,
                        "reconstruction-evidence.private.json",
                    )
                    if reconstruction_component
                    else ""
                ),
                "stored_bytes": int(
                    (reconstruction_component or {}).get("stored_bytes", 0) or 0
                ),
                "sha256": str(
                    (reconstruction_component or {}).get("sha256") or ""
                ),
                "container_count": int(
                    (reconstruction_component or {}).get("container_count", 0) or 0
                ),
                "network_count": int(
                    (reconstruction_component or {}).get("network_count", 0) or 0
                ),
            },
            "filesystem_metadata": {
                "status": "VERIFIED" if metadata_component else "NOT INCLUDED",
                "path": (
                    os.path.join(final_path, "filesystem-metadata.private.json")
                    if metadata_component
                    else ""
                ),
                "stored_bytes": int((metadata_component or {}).get("stored_bytes", 0) or 0),
                "sha256": str((metadata_component or {}).get("sha256") or ""),
                "extended_attributes_applied": xattrs_applied,
            },
        },
        "checks": {
            "server_preflight_revalidated": True,
            "snapshot_manifest_revalidated": True,
            "stored_archive_sha256_revalidated": True,
            "safe_archive_paths_only": True,
            "restore_target_created_new": True,
            "restore_target_isolated_from_live_source": True,
            "restored_entry_set_matches_manifest": True,
            "restored_regular_file_bytes_match": True,
            "restored_per_file_sha256_match": True,
            "restored_mode_uid_gid_match": True,
            "restored_timestamps_match": True,
            "custom_app_definitions_restored": not full_restore or app_expected_entries is not None,
            "custom_app_definitions_match_manifest": not full_restore or app_expected_entries is not None,
            "docker_named_volumes_restored": not named_volume_components or len(restored_named_volumes) == len(named_volume_components),
            "docker_named_volumes_match_manifest": not named_volume_components or all(
                restored["regular_file_bytes"] == expected["logical_bytes"]
                and restored["regular_files"] == sum(item["type"] == "file" for item in expected["entries"].values())
                for restored, expected in zip(restored_named_volumes, named_volume_components)
            ),
            "selected_external_binds_restored": (
                not external_bind_components
                or len(restored_external_binds) == len(external_bind_components)
            ),
            "selected_external_binds_match_manifest": (
                not external_bind_components
                or all(
                    restored["regular_file_bytes"] == expected["logical_bytes"]
                    and restored["regular_files"]
                    == sum(item["type"] == "file" for item in expected["entries"].values())
                    for restored, expected in zip(restored_external_binds, external_bind_components)
                )
            ),
            "private_reconstruction_evidence_restored": (
                not reconstruction_component or bool(restored_reconstruction_path)
            ),
            "private_reconstruction_evidence_checksum_matches": (
                not reconstruction_component
                or restored_reconstruction_sha256
                == reconstruction_component.get("sha256")
            ),
            "filesystem_metadata_restored": (
                not metadata_component or bool(restored_metadata_path)
            ),
            "filesystem_metadata_checksum_matches": (
                not metadata_component
                or restored_metadata_sha256 == metadata_component.get("sha256")
            ),
        },
        "limitations": [
            "Only the server-authorized verified snapshot source was restored.",
            "The restore was written only to a new isolated restore-test directory.",
            "The live Snapshot Lab source was not overwritten or used as a restore target.",
            "The restored application was not started from the restored data.",
            "Database consistency is established by verified clean quiescence, not application-native logical dumps.",
            "Captured extended attributes and POSIX ACL xattrs were applied and re-read only in the isolated restore path.",
            "Docker image layers are not stored; verified Custom App definitions are retained for container recreation.",
            "Docker named volumes were restored only into the isolated recovery-test path and were not attached to containers.",
            "Selected external bind mounts were restored only into the isolated recovery-test path and were not mounted into containers.",
            "Private reconstruction evidence was restored only into the isolated recovery-test path and was not applied to Docker.",
            "The evidence is checksummed but is not cryptographically signed.",
        ],
    }

    restore_manifest_path = os.path.join(pending_path, "restore-manifest.json")
    temporary_manifest = restore_manifest_path + ".tmp"
    with open(temporary_manifest, "x", encoding="utf-8") as handle:
        json.dump(restore_manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary_manifest, restore_manifest_path)
    fsync_directory(restored_root)
    fsync_directory(pending_path)
    os.rename(pending_path, final_path)
    pending_path = ""
    fsync_directory(base_path)

    result.update({
        "execution_status": "COMPLETED",
        "restore_status": "VERIFIED",
        "verification_status": "VERIFIED",
        "manifest": restore_manifest,
        "manifest_path": os.path.join(final_path, "restore-manifest.json"),
        "restore_path": final_path,
    })
    finish_progress("VERIFIED", "Verified isolated recovery complete")
except Exception as exc:
    result["errors"].append(str(exc))
    finish_progress("FAILED", "Isolated recovery failed", str(exc))
    expected_pending = os.path.join(base_path, ".pending-" + snapshot_id) if base_path else ""
    if pending_path and pending_path == expected_pending and os.path.isdir(pending_path) and path_is_under(pending_path, base_path):
        shutil.rmtree(pending_path)
    if base_created and base_path and os.path.isdir(base_path):
        try:
            os.rmdir(base_path)
        except OSError:
            pass

print(json.dumps(result, sort_keys=True))
'''


DISCOVER_RESTORE_SCRIPT = RESTORE_SCRIPT_COMMON + r'''
mountpoints = json.loads(sys.argv[1])
expected_source = sys.argv[2] if len(sys.argv) > 2 else LAB_TEST_SOURCE
snapshot_directory_name = sys.argv[3] if len(sys.argv) > 3 else SNAPSHOT_DIRECTORY_NAME
restore_directory_name = sys.argv[4] if len(sys.argv) > 4 else RESTORE_DIRECTORY_NAME
progress_path = sys.argv[5] if len(sys.argv) > 5 else ""
progress_stage_start = float(sys.argv[6]) if len(sys.argv) > 6 else 0.0
progress_stage_end = float(sys.argv[7]) if len(sys.argv) > 7 else 100.0
progress_started_at = float(sys.argv[8]) if len(sys.argv) > 8 else time.time()
required_snapshot_id = sys.argv[9] if len(sys.argv) > 9 else ""
ALLOW_EXTERNAL_SYMLINKS = expected_source == FULL_APPDATA_SOURCE
result = {
    "mode": "verified-lab-restore-discovery",
    "restore_status": "NOT TESTED",
    "verification_status": "NOT TESTED",
    "manifest": None,
    "errors": [],
}
progress = {
    "schema": "zimabrain.page-verification-progress.v1",
    "status": "RUNNING",
    "phase": "Locating matching isolated recovery evidence",
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


def publish_page_progress(force=False):
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


def configure_page_progress(bytes_total, files_total):
    progress["bytes_total"] = max(0, int(bytes_total))
    progress["files_total"] = max(0, int(files_total))
    publish_page_progress(force=True)


def set_page_progress_phase(phase):
    progress["phase"] = str(phase)
    publish_page_progress(force=True)


def advance_page_progress(byte_count):
    progress["bytes_checked"] = min(
        int(progress.get("bytes_total", 0) or 0),
        int(progress.get("bytes_checked", 0) or 0) + max(0, int(byte_count)),
    )
    publish_page_progress()


def record_page_progress_file():
    progress["files_checked"] = min(
        int(progress.get("files_total", 0) or 0),
        int(progress.get("files_checked", 0) or 0) + 1,
    )
    publish_page_progress()


def approved_mountpoint(value):
    return any(value == root or value.startswith(root + "/") for root in ("/DATA", "/media", "/mnt"))


try:
    candidates = []
    pending_directories = []
    for mountpoint in mountpoints:
        if not isinstance(mountpoint, str) or not approved_mountpoint(mountpoint):
            continue
        if snapshot_directory_name not in ("zimabrain-snapshots", "zimabrain-full-snapshots"):
            raise RuntimeError("Snapshot directory class is not authorized.")
        if restore_directory_name not in ("zimabrain-restore-tests", "zimabrain-full-restore-tests"):
            raise RuntimeError("Restore directory class is not authorized.")
        base = os.path.join(mountpoint, restore_directory_name)
        if not os.path.isdir(base) or os.path.islink(base):
            continue
        with os.scandir(base) as directories:
            for directory in directories:
                if directory.name.startswith(".pending-"):
                    pending_directories.append(directory.path)
                    continue
                if not directory.is_dir(follow_symlinks=False):
                    continue
                restore_manifest_path = os.path.join(directory.path, "restore-manifest.json")
                try:
                    restore_manifest = read_json_file(restore_manifest_path, "Restore manifest")
                    if restore_manifest.get("schema") != "zimabrain.restore-test.v1":
                        continue
                    if (
                        required_snapshot_id
                        and restore_manifest.get("snapshot_id") != required_snapshot_id
                    ):
                        continue
                    candidates.append((
                        str(restore_manifest.get("created_at") or ""),
                        mountpoint,
                        directory.path,
                        restore_manifest_path,
                        restore_manifest,
                    ))
                except Exception as exc:
                    result["errors"].append(f"{restore_manifest_path}: {exc}")

    if pending_directories:
        raise RuntimeError(f"Pending restore-test directories remain: {pending_directories[:5]}")

    if candidates:
        _, mountpoint, restore_path, restore_manifest_path, restore_manifest = max(candidates, key=lambda item: item[0])
        snapshot_id = str(restore_manifest.get("snapshot_id") or "")
        if not snapshot_id or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in snapshot_id):
            raise RuntimeError("Latest restore manifest contains an invalid snapshot identifier.")
        expected_restore_path = os.path.join(mountpoint, restore_directory_name, snapshot_id)
        if restore_path != expected_restore_path or os.path.realpath(restore_path) != expected_restore_path:
            raise RuntimeError("Latest restore path is outside the isolated restore-test directory.")
        if restore_manifest.get("restore_status") != "VERIFIED" or restore_manifest.get("verification_status") != "VERIFIED":
            raise RuntimeError("Latest restore manifest is not verified.")
        if not all(value is True for value in (restore_manifest.get("checks") or {}).values()):
            raise RuntimeError("Latest restore manifest contains an unverified check.")

        snapshot_path = os.path.join(mountpoint, snapshot_directory_name, snapshot_id)
        snapshot_manifest_path = os.path.join(snapshot_path, "manifest.json")
        snapshot_manifest = read_json_file(snapshot_manifest_path, "Snapshot manifest")
        recovery_bundle = snapshot_manifest.get("recovery_bundle") or {}
        app_component = (recovery_bundle.get("components") or {}).get("casaos_apps") or {}
        volume_component = (recovery_bundle.get("components") or {}).get("docker_named_volumes") or {}
        reconstruction_component = (
            (recovery_bundle.get("components") or {}).get(
                "reconstruction_evidence"
            )
            or {}
        )
        external_component = (
            (recovery_bundle.get("components") or {}).get(
                "selected_external_binds"
            )
            or {}
        )
        metadata_component = (
            (recovery_bundle.get("components") or {}).get(
                "filesystem_metadata"
            )
            or {}
        )
        volume_records = volume_component.get("volumes") or []
        external_records = external_component.get("paths") or []
        source_record = snapshot_manifest.get("source") or {}
        stored_components = [snapshot_manifest.get("archive") or {}]
        logical_components = [source_record]
        if expected_source == FULL_APPDATA_SOURCE:
            stored_components.append(app_component)
            logical_components.append(app_component)
            if isinstance(volume_records, list):
                stored_components.extend(
                    item for item in volume_records if isinstance(item, dict)
                )
                logical_components.extend(
                    item for item in volume_records if isinstance(item, dict)
                )
            if isinstance(external_records, list):
                stored_components.extend(
                    item for item in external_records if isinstance(item, dict)
                )
                logical_components.extend(
                    item for item in external_records if isinstance(item, dict)
                )
            if reconstruction_component:
                stored_components.extend(
                    [reconstruction_component, reconstruction_component]
                )
            if metadata_component:
                stored_components.extend([metadata_component, metadata_component])
        regular_files = sum(
            max(0, int(item.get("regular_files", 0) or 0))
            for item in logical_components
        )
        configure_page_progress(
            sum(
                max(0, int(item.get("stored_bytes", 0) or 0))
                for item in stored_components
            )
            + 2 * sum(
                max(0, int(item.get("regular_file_bytes", 0) or 0))
                for item in logical_components
            ),
            len(stored_components) + 2 * regular_files,
        )
        snapshot_record = restore_manifest.get("snapshot") or {}
        if snapshot_record.get("manifest_path") != snapshot_manifest_path:
            raise RuntimeError("Restore manifest snapshot path is inconsistent.")
        manifest_sha256, manifest_bytes = hash_file(snapshot_manifest_path)
        if manifest_sha256 != snapshot_record.get("manifest_sha256") or manifest_bytes != int(snapshot_record.get("manifest_bytes", -1)):
            raise RuntimeError("Stored snapshot manifest changed after the restore test.")
        if snapshot_manifest.get("schema") != "zimabrain.snapshot.v1" or snapshot_manifest.get("snapshot_id") != snapshot_id:
            raise RuntimeError("Stored snapshot manifest identity is invalid.")
        if snapshot_manifest.get("snapshot_status") != "VERIFIED" or snapshot_manifest.get("verification_status") != "VERIFIED":
            raise RuntimeError("Stored snapshot manifest is no longer verified.")
        if (snapshot_manifest.get("source") or {}).get("requested_path") != expected_source:
            raise RuntimeError("Stored snapshot is not the server-authorized source.")

        archive = snapshot_manifest.get("archive") or {}
        filename = str(archive.get("filename") or "")
        if not filename or os.path.basename(filename) != filename:
            raise RuntimeError("Stored snapshot manifest contains an unsafe archive filename.")
        archive_path = os.path.join(snapshot_path, filename)
        if snapshot_record.get("archive_path") != archive_path:
            raise RuntimeError("Restore manifest archive path is inconsistent.")
        require_regular_file(archive_path, "Snapshot archive")
        set_page_progress_phase("Checking stored AppData archive checksum")
        archive_sha256, archive_bytes = hash_file(
            archive_path,
            progress_callback=advance_page_progress,
        )
        record_page_progress_file()
        if archive_sha256 != archive.get("sha256") or archive_sha256 != snapshot_record.get("archive_sha256"):
            raise RuntimeError("Stored snapshot archive checksum no longer verifies.")
        if archive_bytes != int(archive.get("stored_bytes", -1)) or archive_bytes != int(snapshot_record.get("archive_bytes", -1)):
            raise RuntimeError("Stored snapshot archive byte count no longer verifies.")

        expected_entries = manifest_entry_map(snapshot_manifest.get("entries") or [])
        set_page_progress_phase("Validating every stored AppData archive file")
        with tarfile.open(archive_path, mode="r") as archive_handle:
            archive_entries, _ = archive_entry_map(
                archive_handle,
                progress_callback=advance_page_progress,
                progress_file_callback=record_page_progress_file,
            )
        compare_entry_maps(expected_entries, archive_entries)

        restored_root = os.path.join(restore_path, "data")
        set_page_progress_phase("Verifying every restored AppData file")
        restored_entries = scan_tree(
            restored_root,
            progress_callback=advance_page_progress,
            progress_file_callback=record_page_progress_file,
        )
        compare_entry_maps(expected_entries, restored_entries, strict_mtime_ns=True)
        restored_files = [item for item in restored_entries.values() if item["type"] == "file"]
        restored_bytes = sum(item["size"] for item in restored_files)
        restore_record = restore_manifest.get("restore") or {}
        if restore_record.get("path") != restore_path or restore_record.get("data_path") != restored_root:
            raise RuntimeError("Restore manifest target paths are inconsistent.")
        if restored_bytes != int(restore_record.get("regular_file_bytes", -1)) or len(restored_files) != int(restore_record.get("regular_files", -1)):
            raise RuntimeError("Persistent restored totals no longer match the restore manifest.")
        if int(restore_record.get("difference_bytes", -1)) != 0:
            raise RuntimeError("Restore manifest reports a non-zero byte difference.")

        if expected_source == FULL_APPDATA_SOURCE:
            if recovery_bundle.get("status") != "VERIFIED" or app_component.get("requested_path") != "/var/lib/casaos/apps":
                raise RuntimeError("Stored snapshot is not a verified Custom App recovery bundle.")
            app_filename = str(app_component.get("archive_filename") or "")
            if not app_filename or os.path.basename(app_filename) != app_filename:
                raise RuntimeError("Stored Custom App archive filename is unsafe.")
            app_archive_path = os.path.join(snapshot_path, app_filename)
            require_regular_file(app_archive_path, "Custom App definition archive")
            set_page_progress_phase("Checking saved Custom App definitions")
            app_sha256, app_archive_bytes = hash_file(
                app_archive_path,
                progress_callback=advance_page_progress,
            )
            record_page_progress_file()
            if app_sha256 != app_component.get("sha256") or app_archive_bytes != int(app_component.get("stored_bytes", -1)):
                raise RuntimeError("Stored Custom App definition archive no longer verifies.")
            app_expected_entries = manifest_entry_map(app_component.get("entries") or [])
            with tarfile.open(app_archive_path, mode="r") as app_archive_handle:
                app_archive_entries, _ = archive_entry_map(
                    app_archive_handle,
                    archive_root="casaos-apps",
                    progress_callback=advance_page_progress,
                    progress_file_callback=record_page_progress_file,
                )
            compare_entry_maps(app_expected_entries, app_archive_entries)
            restored_apps_root = os.path.join(restore_path, "casaos-apps")
            restored_app_entries = scan_tree(
                restored_apps_root,
                progress_callback=advance_page_progress,
                progress_file_callback=record_page_progress_file,
            )
            compare_entry_maps(app_expected_entries, restored_app_entries, strict_mtime_ns=True)
            component_record = (restore_manifest.get("components") or {}).get("casaos_apps") or {}
            app_files = [item for item in restored_app_entries.values() if item["type"] == "file"]
            if component_record.get("path") != restored_apps_root:
                raise RuntimeError("Stored Custom App restore path is inconsistent.")
            if sum(item["size"] for item in app_files) != int(component_record.get("regular_file_bytes", -1)) or len(app_files) != int(component_record.get("regular_files", -1)):
                raise RuntimeError("Persistent Custom App restore totals no longer verify.")
            if volume_component:
                if volume_component.get("status") != "VERIFIED":
                    raise RuntimeError("Stored Docker named-volume component is not verified.")
                restore_volume_component = (restore_manifest.get("components") or {}).get("docker_named_volumes") or {}
                restore_volume_records = restore_volume_component.get("volumes") or []
                if (
                    not isinstance(volume_records, list)
                    or len(volume_records) != int(volume_component.get("volume_count", -1))
                    or not isinstance(restore_volume_records, list)
                    or len(restore_volume_records) != len(volume_records)
                ):
                    raise RuntimeError("Stored Docker named-volume recovery inventory is inconsistent.")
                restored_by_name = {
                    str(item.get("name") or ""): item
                    for item in restore_volume_records
                    if isinstance(item, dict)
                }
                for volume in volume_records:
                    if not isinstance(volume, dict):
                        raise RuntimeError("Stored Docker named-volume record is invalid.")
                    volume_name = str(volume.get("name") or "")
                    volume_filename = str(volume.get("archive_filename") or "")
                    if not volume_name or not volume_filename or os.path.basename(volume_filename) != volume_filename:
                        raise RuntimeError("Stored Docker named-volume identity or archive filename is invalid.")
                    volume_archive_path = os.path.join(snapshot_path, volume_filename)
                    require_regular_file(volume_archive_path, f"Docker named-volume archive {volume_name}")
                    set_page_progress_phase(
                        "Checking Docker named volume " + volume_name
                    )
                    volume_sha256, volume_archive_bytes = hash_file(
                        volume_archive_path,
                        progress_callback=advance_page_progress,
                    )
                    record_page_progress_file()
                    if volume_sha256 != volume.get("sha256") or volume_archive_bytes != int(volume.get("stored_bytes", -1)):
                        raise RuntimeError(f"Stored Docker named-volume archive no longer verifies: {volume_name}")
                    volume_expected_entries = manifest_entry_map(volume.get("entries") or [])
                    with tarfile.open(volume_archive_path, mode="r") as volume_archive_handle:
                        volume_archive_entries, _ = archive_entry_map(
                            volume_archive_handle,
                            archive_root="volume-data",
                            progress_callback=advance_page_progress,
                            progress_file_callback=record_page_progress_file,
                        )
                    compare_entry_maps(volume_expected_entries, volume_archive_entries)
                    restored_volume_root = os.path.join(restore_path, "docker-volumes", volume_name)
                    restored_volume_entries = scan_tree(
                        restored_volume_root,
                        progress_callback=advance_page_progress,
                        progress_file_callback=record_page_progress_file,
                    )
                    compare_entry_maps(volume_expected_entries, restored_volume_entries, strict_mtime_ns=True)
                    restored_volume_files = [item for item in restored_volume_entries.values() if item["type"] == "file"]
                    restored_volume_record = restored_by_name.get(volume_name) or {}
                    if restored_volume_record.get("path") != restored_volume_root:
                        raise RuntimeError(f"Stored Docker named-volume restore path is inconsistent: {volume_name}")
                    if (
                        sum(item["size"] for item in restored_volume_files) != int(restored_volume_record.get("regular_file_bytes", -1))
                        or len(restored_volume_files) != int(restored_volume_record.get("regular_files", -1))
                    ):
                        raise RuntimeError(f"Persistent Docker named-volume restore totals no longer verify: {volume_name}")
            if external_component:
                if external_component.get("status") not in {"VERIFIED", "NOT SELECTED"}:
                    raise RuntimeError("Stored selected external bind component is not verified.")
                restore_external_component = (
                    (restore_manifest.get("components") or {}).get(
                        "selected_external_binds"
                    )
                    or {}
                )
                restore_external_records = restore_external_component.get("paths") or []
                if (
                    not isinstance(external_records, list)
                    or len(external_records) != int(external_component.get("path_count", -1))
                    or not isinstance(restore_external_records, list)
                    or len(restore_external_records) != len(external_records)
                ):
                    raise RuntimeError("Stored selected external bind recovery inventory is inconsistent.")
                for index, external in enumerate(external_records):
                    if not isinstance(external, dict):
                        raise RuntimeError("Stored selected external bind record is invalid.")
                    external_filename = str(external.get("archive_filename") or "")
                    requested_path = str(external.get("requested_path") or "")
                    if (
                        not requested_path
                        or not external_filename
                        or os.path.basename(external_filename) != external_filename
                    ):
                        raise RuntimeError("Stored selected external bind identity is invalid.")
                    external_archive_path = os.path.join(snapshot_path, external_filename)
                    require_regular_file(external_archive_path, "Selected external bind archive")
                    set_page_progress_phase("Checking selected external bind " + requested_path)
                    external_sha, external_bytes = hash_file(
                        external_archive_path,
                        progress_callback=advance_page_progress,
                    )
                    record_page_progress_file()
                    if (
                        external_sha != external.get("sha256")
                        or external_bytes != int(external.get("stored_bytes", -1))
                    ):
                        raise RuntimeError("Selected external bind archive no longer verifies: " + requested_path)
                    external_expected_entries = manifest_entry_map(external.get("entries") or [])
                    with tarfile.open(external_archive_path, mode="r") as external_handle:
                        external_archive_entries, _ = archive_entry_map(
                            external_handle,
                            archive_root="external-data",
                            progress_callback=advance_page_progress,
                            progress_file_callback=record_page_progress_file,
                        )
                    compare_entry_maps(external_expected_entries, external_archive_entries)
                    restored_external_root = os.path.join(
                        restore_path,
                        "external-binds",
                        f"bind-{index:04d}",
                    )
                    restored_external_entries = scan_tree(
                        restored_external_root,
                        progress_callback=advance_page_progress,
                        progress_file_callback=record_page_progress_file,
                    )
                    compare_entry_maps(
                        external_expected_entries,
                        restored_external_entries,
                        strict_mtime_ns=True,
                    )
                    restored_external_files = [
                        item for item in restored_external_entries.values()
                        if item["type"] == "file"
                    ]
                    restored_external_record = restore_external_records[index]
                    if (
                        not isinstance(restored_external_record, dict)
                        or restored_external_record.get("requested_path") != requested_path
                        or restored_external_record.get("path") != restored_external_root
                        or sum(item["size"] for item in restored_external_files)
                        != int(restored_external_record.get("regular_file_bytes", -1))
                        or len(restored_external_files)
                        != int(restored_external_record.get("regular_files", -1))
                    ):
                        raise RuntimeError("Selected external bind restore evidence is inconsistent: " + requested_path)
            if metadata_component:
                if metadata_component.get("status") != "VERIFIED":
                    raise RuntimeError("Stored filesystem metadata evidence is not verified.")
                metadata_filename = str(metadata_component.get("filename") or "")
                if metadata_filename != "filesystem-metadata.private.json":
                    raise RuntimeError("Stored filesystem metadata filename is unsafe.")
                metadata_snapshot_path = os.path.join(snapshot_path, metadata_filename)
                metadata_restore_path = os.path.join(restore_path, metadata_filename)
                require_regular_file(metadata_snapshot_path, "Stored filesystem metadata evidence")
                require_regular_file(metadata_restore_path, "Restored filesystem metadata evidence")
                set_page_progress_phase("Checking ACL and extended-attribute evidence")
                snapshot_metadata_sha, snapshot_metadata_bytes = hash_file(
                    metadata_snapshot_path,
                    progress_callback=advance_page_progress,
                )
                record_page_progress_file()
                restored_metadata_sha, restored_metadata_bytes = hash_file(
                    metadata_restore_path,
                    progress_callback=advance_page_progress,
                )
                record_page_progress_file()
                if (
                    snapshot_metadata_sha != metadata_component.get("sha256")
                    or restored_metadata_sha != snapshot_metadata_sha
                    or snapshot_metadata_bytes != int(metadata_component.get("stored_bytes", -1))
                    or restored_metadata_bytes != snapshot_metadata_bytes
                ):
                    raise RuntimeError("Filesystem metadata evidence no longer verifies.")
                restore_metadata = (
                    (restore_manifest.get("components") or {}).get("filesystem_metadata")
                    or {}
                )
                if (
                    restore_metadata.get("status") != "VERIFIED"
                    or restore_metadata.get("path") != metadata_restore_path
                    or restore_metadata.get("sha256") != snapshot_metadata_sha
                ):
                    raise RuntimeError("Filesystem metadata restore evidence is inconsistent.")
            if reconstruction_component:
                if reconstruction_component.get("status") != "VERIFIED":
                    raise RuntimeError("Stored private reconstruction evidence is not verified.")
                reconstruction_filename = str(
                    reconstruction_component.get("filename") or ""
                )
                if reconstruction_filename != "reconstruction-evidence.private.json":
                    raise RuntimeError("Stored private reconstruction evidence filename is unsafe.")
                reconstruction_snapshot_path = os.path.join(
                    snapshot_path,
                    reconstruction_filename,
                )
                reconstruction_restore_path = os.path.join(
                    restore_path,
                    reconstruction_filename,
                )
                require_regular_file(
                    reconstruction_snapshot_path,
                    "Stored private reconstruction evidence",
                )
                require_regular_file(
                    reconstruction_restore_path,
                    "Restored private reconstruction evidence",
                )
                set_page_progress_phase(
                    "Checking private reconstruction evidence"
                )
                snapshot_reconstruction_sha, snapshot_reconstruction_bytes = hash_file(
                    reconstruction_snapshot_path,
                    progress_callback=advance_page_progress,
                )
                record_page_progress_file()
                restored_reconstruction_sha, restored_reconstruction_bytes = hash_file(
                    reconstruction_restore_path,
                    progress_callback=advance_page_progress,
                )
                record_page_progress_file()
                if (
                    snapshot_reconstruction_sha
                    != reconstruction_component.get("sha256")
                    or restored_reconstruction_sha
                    != snapshot_reconstruction_sha
                    or snapshot_reconstruction_bytes
                    != int(reconstruction_component.get("stored_bytes", -1))
                    or restored_reconstruction_bytes
                    != snapshot_reconstruction_bytes
                ):
                    raise RuntimeError("Private reconstruction evidence no longer verifies.")
                restore_reconstruction = (
                    (restore_manifest.get("components") or {}).get(
                        "reconstruction_evidence"
                    )
                    or {}
                )
                if (
                    restore_reconstruction.get("status") != "VERIFIED"
                    or restore_reconstruction.get("path")
                    != reconstruction_restore_path
                    or restore_reconstruction.get("sha256")
                    != snapshot_reconstruction_sha
                ):
                    raise RuntimeError("Private reconstruction restore evidence is inconsistent.")

        result.update({
            "restore_status": "VERIFIED",
            "verification_status": "VERIFIED",
            "manifest": restore_manifest,
            "manifest_path": restore_manifest_path,
            "restore_path": restore_path,
        })
        progress["bytes_checked"] = progress["bytes_total"]
        progress["files_checked"] = progress["files_total"]
        progress["phase"] = "Stored isolated recovery evidence verified"
        publish_page_progress(force=True)
except Exception as exc:
    result["restore_status"] = "NOT VERIFIED"
    result["verification_status"] = "NOT VERIFIED"
    result["errors"].append(str(exc))

print(json.dumps(result, sort_keys=True))
'''


READ_FULL_RESTORE_PROGRESS_SCRIPT = r'''import json
import os
import sys

mountpoints = json.loads(sys.argv[1])
snapshot_id = sys.argv[2]
result = {
    "schema": "zimabrain.restore-progress.v1",
    "snapshot_id": snapshot_id,
    "status": "NOT STARTED",
    "phase": "Waiting to start",
    "percent": 0.0,
    "work_bytes_processed": 0,
    "work_bytes_total": 0,
    "restored_bytes": 0,
    "logical_bytes_total": 0,
    "restored_files": 0,
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
        "zimabrain-full-restore-tests",
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
            and record.get("schema") == "zimabrain.restore-progress.v1"
            and record.get("snapshot_id") == snapshot_id
        ):
            records.append((info.st_mtime_ns, record))
    except (OSError, ValueError):
        continue

if records:
    result = max(records, key=lambda item: item[0])[1]

print(json.dumps(result, sort_keys=True))
'''


CANCEL_FULL_RESTORE_SCRIPT = r'''import json
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
        with open(
            "/proc/" + entry.name + "/cmdline",
            "rb",
        ) as handle:
            command = handle.read()
        executable = os.path.basename(
            os.readlink("/proc/" + entry.name + "/exe")
        )
    except OSError:
        continue
    if (
        executable.startswith("python3")
        and
        snapshot_id.encode() in command
        and b"zimabrain-full-restore-tests" in command
        and b"ISOLATED ALL APPDATA RESTORE TEST" in command
        and b"python3" in command
    ):
        workers.append(int(entry.name))

if len(workers) > 1:
    raise SystemExit("More than one matching recovery worker exists")

if workers:
    os.kill(workers[0], signal.SIGTERM)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and os.path.exists("/proc/" + str(workers[0])):
        time.sleep(0.25)
    if os.path.exists("/proc/" + str(workers[0])):
        raise SystemExit("Recovery worker did not stop after SIGTERM")

cancelled_path = ""
progress_path = ""
for mountpoint in mountpoints:
    if not isinstance(mountpoint, str) or not any(
        mountpoint == root or mountpoint.startswith(root + "/")
        for root in ("/DATA", "/media", "/mnt")
    ):
        continue
    base = os.path.join(mountpoint, "zimabrain-full-restore-tests")
    pending = os.path.join(base, ".pending-" + snapshot_id)
    candidate_progress = os.path.join(base, ".progress-" + snapshot_id + ".json")
    if os.path.lexists(pending):
        info = os.lstat(pending)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SystemExit("Pending recovery output is not a safe directory")
        if not os.path.realpath(pending).startswith(os.path.realpath(base).rstrip("/") + "/"):
            raise SystemExit("Pending recovery output escapes its isolated base")
        shutil.rmtree(pending)
        cancelled_path = pending
    if os.path.isfile(candidate_progress) and not os.path.islink(candidate_progress):
        progress_path = candidate_progress

record = {
    "schema": "zimabrain.restore-progress.v1",
    "snapshot_id": snapshot_id,
    "status": "CANCELLED",
    "phase": "Cancelled by user",
    "percent": 0.0,
    "work_bytes_processed": 0,
    "work_bytes_total": 0,
    "restored_bytes": 0,
    "logical_bytes_total": 0,
    "restored_files": 0,
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
    "restore_status": "CANCELLED",
    "verification_status": "NOT VERIFIED",
    "snapshot_id": snapshot_id,
    "worker_stopped": not workers or not os.path.exists("/proc/" + str(workers[0])),
    "partial_output_removed": bool(cancelled_path),
    "errors": [],
}, sort_keys=True))
'''


def _failed(message, status="NOT TESTED"):
    return {
        "mode": "restricted-lab-restore-test",
        "execution_status": "FAILED",
        "restore_status": status,
        "verification_status": "NOT VERIFIED",
        "errors": [str(message)],
    }


def _candidate_mountpoints(destination_inventory):
    return [
        str(item.get("mountpoint"))
        for item in (destination_inventory.get("destinations") or [])
        if item.get("decision") == "candidate" and item.get("mountpoint") == LAB_RESTORE_MOUNTPOINT
    ]


def _full_candidate_mountpoints(destination_inventory):
    return [
        str(item.get("mountpoint"))
        for item in (destination_inventory.get("destinations") or [])
        if item.get("decision") == "candidate" and item.get("mountpoint")
    ]


def collect_full_restore_progress(
    destination_inventory,
    command_runner,
    snapshot_id,
    timeout=30,
):
    mountpoints = _full_candidate_mountpoints(destination_inventory)
    if not mountpoints:
        return _failed("No eligible recovery destination is available.")
    try:
        completed = command_runner(
            [
                "python3",
                "-c",
                READ_FULL_RESTORE_PROGRESS_SCRIPT,
                json.dumps(mountpoints),
                snapshot_id,
            ],
            timeout=timeout,
        )
    except Exception as exc:
        return _failed(f"Recovery progress read failed: {exc}")
    if not isinstance(completed, dict) or not completed.get("ok"):
        return _failed(
            str(
                (completed or {}).get("stderr")
                or (completed or {}).get("stdout")
                or "Recovery progress read failed."
            ).strip()
        )
    try:
        result = json.loads(str(completed.get("stdout") or ""))
    except Exception as exc:
        return _failed(f"Recovery progress returned invalid JSON: {exc}")
    if not isinstance(result, dict) or result.get("snapshot_id") != snapshot_id:
        return _failed("Recovery progress identity is invalid.")
    return result


def cancel_full_appdata_restore_test(
    destination_inventory,
    command_runner,
    snapshot_id,
    timeout=45,
):
    mountpoints = _full_candidate_mountpoints(destination_inventory)
    if not mountpoints:
        return _failed("No eligible recovery destination is available.")
    try:
        completed = command_runner(
            [
                "python3",
                "-c",
                CANCEL_FULL_RESTORE_SCRIPT,
                json.dumps(mountpoints),
                snapshot_id,
            ],
            timeout=timeout,
        )
    except Exception as exc:
        return _failed(f"Recovery cancellation failed: {exc}")
    if not isinstance(completed, dict) or not completed.get("ok"):
        return _failed(
            str(
                (completed or {}).get("stderr")
                or (completed or {}).get("stdout")
                or "Recovery cancellation failed."
            ).strip()
        )
    try:
        result = json.loads(str(completed.get("stdout") or ""))
    except Exception as exc:
        return _failed(f"Recovery cancellation returned invalid JSON: {exc}")
    if not isinstance(result, dict) or result.get("snapshot_id") != snapshot_id:
        return _failed("Recovery cancellation identity is invalid.")
    return result


def execute_lab_restore_test(destination_inventory, command_runner, snapshot_id, timeout=300):
    if destination_inventory.get("verification_status") != "VERIFIED":
        return _failed("Destination inventory is not fully verified.")
    latest = snapshot_executor.collect_latest_verified_snapshot(destination_inventory, command_runner)
    if latest.get("snapshot_status") != "VERIFIED" or latest.get("verification_status") != "VERIFIED":
        return _failed("No fully verified Snapshot Lab archive is available.")
    manifest = latest.get("manifest") or {}
    if manifest.get("schema") != "zimabrain.snapshot.v1":
        return _failed("Latest snapshot manifest schema is invalid.")
    if manifest.get("snapshot_id") != snapshot_id:
        return _failed("Requested restore-test snapshot is not the latest verified snapshot.")
    source = manifest.get("source") or {}
    if source.get("requested_path") != LAB_TEST_SOURCE:
        return _failed("v0.6 permits only a verified restricted Snapshot Lab archive.")

    manifest_destination = manifest.get("destination") or {}
    destination = next(
        (
            item
            for item in (destination_inventory.get("destinations") or [])
            if item.get("decision") == "candidate"
            and item.get("mountpoint") == LAB_RESTORE_MOUNTPOINT
            and item.get("mountpoint") == manifest_destination.get("mountpoint")
            and item.get("device") == manifest_destination.get("device")
        ),
        None,
    )
    if destination is None:
        return _failed("Snapshot destination is no longer an eligible native Linux destination.")

    logical_bytes = int(source.get("regular_file_bytes", 0) or 0)
    archive = manifest.get("archive") or {}
    archive_bytes = int(archive.get("stored_bytes", 0) or 0)
    if logical_bytes < 0 or archive_bytes <= 0:
        return _failed("Snapshot manifest byte evidence is invalid.")
    if logical_bytes > snapshot_executor.MAX_LAB_SOURCE_BYTES:
        return _failed("Snapshot logical bytes exceed the restricted Lab limit.")
    if int(destination.get("free_bytes", 0) or 0) < logical_bytes + RESTORE_RESERVE_BYTES:
        return _failed("Restore destination capacity does not satisfy the execution reserve.")

    try:
        completed = command_runner([
            "python3",
            "-c",
            RESTORE_TEST_SCRIPT,
            str(latest.get("manifest_path") or ""),
            str(latest.get("archive_path") or ""),
            str(destination["mountpoint"]),
            snapshot_id,
            str(destination["device"]),
            str(archive.get("sha256") or ""),
            str(archive_bytes),
            str(logical_bytes),
            LAB_TEST_SOURCE,
            SNAPSHOT_DIRECTORY_NAME,
            RESTORE_DIRECTORY_NAME,
            "ISOLATED RESTRICTED LAB RESTORE TEST",
        ], timeout=timeout)
    except Exception as exc:
        return _failed(f"Restore-test runner failed: {exc}")
    if not isinstance(completed, dict):
        return _failed("Restore-test executor returned an invalid runner result.")
    stdout = str(completed.get("stdout") or "")
    if not completed.get("ok"):
        detail = str(completed.get("stderr") or stdout or "Restore-test executor failed.").strip()
        return _failed(detail)
    try:
        result = json.loads(stdout)
    except Exception as exc:
        return _failed(f"Restore-test executor returned invalid JSON: {exc}")
    if not isinstance(result, dict) or result.get("snapshot_id") != snapshot_id:
        return _failed("Restore-test response did not match the requested snapshot.")
    if result.get("restore_status") != "VERIFIED":
        return result
    restore_manifest = result.get("manifest") or {}
    if restore_manifest.get("schema") != "zimabrain.restore-test.v1":
        return _failed("Completed restore-test manifest schema is invalid.", status="NOT VERIFIED")
    restore_record = restore_manifest.get("restore") or {}
    if restore_record.get("device") != destination.get("device"):
        return _failed("Completed restore-test device differs from server preflight.", status="NOT VERIFIED")
    if int(restore_record.get("difference_bytes", -1)) != 0:
        return _failed("Completed restore-test reports a non-zero byte difference.", status="NOT VERIFIED")
    return result


def collect_latest_verified_restore(destination_inventory, command_runner, timeout=180):
    mountpoints = _candidate_mountpoints(destination_inventory)
    if not mountpoints:
        return {
            "verification_status": "NOT TESTED",
            "restore_status": "NOT TESTED",
            "manifest": None,
            "errors": [],
        }
    try:
        completed = command_runner(
            ["python3", "-c", DISCOVER_RESTORE_SCRIPT, json.dumps(mountpoints), LAB_TEST_SOURCE, SNAPSHOT_DIRECTORY_NAME, RESTORE_DIRECTORY_NAME],
            timeout=timeout,
        )
    except Exception as exc:
        return _failed(f"Verified restore discovery failed: {exc}")
    if not isinstance(completed, dict):
        return _failed("Verified restore discovery returned an invalid result.")
    stdout = str(completed.get("stdout") or "")
    if not completed.get("ok"):
        return _failed(str(completed.get("stderr") or stdout or "Verified restore discovery failed."))
    try:
        result = json.loads(stdout)
    except Exception as exc:
        return _failed(f"Verified restore discovery returned invalid JSON: {exc}")
    return result if isinstance(result, dict) else _failed("Verified restore discovery returned a non-object result.")


def execute_full_appdata_restore_test(
    destination_inventory,
    command_runner,
    snapshot_id,
    timeout=FULL_RECOVERY_OPERATION_TIMEOUT_SECONDS,
    latest_verified_snapshot=None,
):
    if destination_inventory.get("verification_status") != "VERIFIED":
        return _failed("Destination inventory is not fully verified.")
    latest = latest_verified_snapshot
    if not isinstance(latest, dict):
        latest = snapshot_executor.collect_latest_verified_full_snapshot(
            destination_inventory,
            command_runner,
        )
    if latest.get("snapshot_status") != "VERIFIED" or latest.get("verification_status") != "VERIFIED":
        return _failed("No fully verified All AppData archive is available.")
    manifest = latest.get("manifest") or {}
    if manifest.get("snapshot_id") != snapshot_id or (manifest.get("source") or {}).get("requested_path") != snapshot_executor.FULL_APPDATA_SOURCE:
        return _failed("Requested All AppData restore-test snapshot is not the latest verified snapshot.")
    manifest_destination = manifest.get("destination") or {}
    destination = next((item for item in (destination_inventory.get("destinations") or [])
                        if item.get("decision") == "candidate"
                        and item.get("mountpoint") == manifest_destination.get("mountpoint")
                        and item.get("device") == manifest_destination.get("device")), None)
    if destination is None:
        return _failed("Snapshot destination is no longer eligible.")
    source = manifest.get("source") or {}
    archive = manifest.get("archive") or {}
    logical_bytes = int(source.get("regular_file_bytes", 0) or 0)
    archive_bytes = int(archive.get("stored_bytes", 0) or 0)
    if logical_bytes > snapshot_executor.MAX_FULL_SOURCE_BYTES or archive_bytes <= 0:
        return _failed("All AppData snapshot byte evidence is invalid.")
    if int(destination.get("free_bytes", 0) or 0) < logical_bytes + RESTORE_RESERVE_BYTES:
        return _failed("Restore-test capacity no longer satisfies the execution reserve.")
    try:
        completed = command_runner([
            "python3", "-c", RESTORE_TEST_SCRIPT,
            str(latest.get("manifest_path") or ""), str(latest.get("archive_path") or ""),
            str(destination["mountpoint"]), snapshot_id, str(destination["device"]),
            str(archive.get("sha256") or ""), str(archive_bytes), str(logical_bytes),
            snapshot_executor.FULL_APPDATA_SOURCE,
            snapshot_executor.FULL_SNAPSHOT_DIRECTORY_NAME,
            FULL_RESTORE_DIRECTORY_NAME,
            "ISOLATED ALL APPDATA RESTORE TEST",
        ], timeout=timeout)
    except Exception as exc:
        return _failed(f"All AppData restore-test runner failed: {exc}")
    if not isinstance(completed, dict):
        return _failed("All AppData restore-test returned an invalid runner result.")
    stdout = str(completed.get("stdout") or "")
    if not completed.get("ok"):
        return _failed(str(completed.get("stderr") or stdout or "All AppData restore-test failed.").strip())
    try:
        result = json.loads(stdout)
    except Exception as exc:
        return _failed(f"All AppData restore-test returned invalid JSON: {exc}")
    if not isinstance(result, dict) or result.get("snapshot_id") != snapshot_id:
        return _failed("All AppData restore-test response identity is invalid.")
    return result


def collect_latest_verified_full_restore(
    destination_inventory,
    command_runner,
    timeout=600,
    page_progress_path="",
    page_progress_stage=(0.0, 100.0),
    page_progress_started_at=0.0,
    expected_snapshot_id="",
):
    mountpoints = [str(item.get("mountpoint")) for item in (destination_inventory.get("destinations") or [])
                   if item.get("decision") == "candidate" and item.get("mountpoint")]
    if not mountpoints:
        return {"verification_status": "NOT TESTED", "restore_status": "NOT TESTED", "manifest": None, "errors": []}
    try:
        completed = command_runner([
            "python3", "-c", DISCOVER_RESTORE_SCRIPT, json.dumps(mountpoints),
            snapshot_executor.FULL_APPDATA_SOURCE,
            snapshot_executor.FULL_SNAPSHOT_DIRECTORY_NAME,
            FULL_RESTORE_DIRECTORY_NAME,
            str(page_progress_path or ""),
            str(float(page_progress_stage[0])),
            str(float(page_progress_stage[1])),
            str(float(page_progress_started_at or 0.0)),
            str(expected_snapshot_id or ""),
        ], timeout=timeout)
    except Exception as exc:
        return _failed(f"All AppData restore discovery failed: {exc}")
    if not isinstance(completed, dict):
        return _failed("All AppData restore discovery returned an invalid result.")
    stdout = str(completed.get("stdout") or "")
    if not completed.get("ok"):
        return _failed(str(completed.get("stderr") or stdout or "All AppData restore discovery failed."))
    try:
        result = json.loads(stdout)
    except Exception as exc:
        return _failed(f"All AppData restore discovery returned invalid JSON: {exc}")
    return result if isinstance(result, dict) else _failed("All AppData restore discovery returned a non-object result.")
