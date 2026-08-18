"""Safety-first planning for complete ZimaOS application reconstruction.

This module never changes Docker or host files.  It converts verified private
reconstruction evidence into explicit capture and reconstruction plans that a
later, separately authorised executor can apply.
"""

from datetime import datetime, timezone
import os


CAPTURED_ROOTS = ("/DATA/AppData", "/var/lib/casaos/apps")
RUNTIME_ROOTS = ("/dev", "/proc", "/run", "/sys", "/var/run")
BUILTIN_NETWORKS = {"bridge", "host", "none"}
DATABASE_MARKERS = {
    "postgres": "PostgreSQL",
    "mariadb": "MariaDB",
    "mysql": "MySQL",
    "redis": "Redis",
}


def _under(path, roots):
    value = os.path.normpath(str(path or ""))
    return any(value == root or value.startswith(root + os.sep) for root in roots)


def _database_type(name, image):
    value = (str(name) + " " + str(image)).lower()
    for marker, label in DATABASE_MARKERS.items():
        if marker in value:
            return label
    return ""


def _safe_external_bind(path):
    value = os.path.normpath(str(path or ""))
    if not os.path.isabs(value) or value == "/":
        return False
    if _under(value, CAPTURED_ROOTS) or _under(value, RUNTIME_ROOTS):
        return False
    return value.startswith(("/DATA/", "/media/", "/mnt/"))


def build_capture_plan(reconstruction_evidence, selected_external_paths=None):
    """Return a deterministic, read-only plan for the remaining recovery data."""
    evidence = reconstruction_evidence if isinstance(reconstruction_evidence, dict) else {}
    selected = {
        os.path.normpath(str(path))
        for path in (selected_external_paths or [])
        if _safe_external_bind(path)
    }
    databases = []
    external = {}
    images = {}
    errors = []

    if evidence.get("capture_status") != "VERIFIED":
        errors.append("Private reconstruction evidence is not verified.")

    for container in evidence.get("containers") or []:
        if not isinstance(container, dict):
            errors.append("Private reconstruction evidence contains an invalid container record.")
            continue
        name = str(container.get("name") or "")
        image = container.get("image") or {}
        reference = str(image.get("reference") or "")
        database_type = _database_type(name, reference)
        state = container.get("state") or {}
        status = str(state.get("status") or container.get("state_at_capture") or "unknown")
        cleanly_quiesced = (
            status in {"exited", "created"}
            and not bool(state.get("running"))
            and not bool(state.get("paused"))
            and int(state.get("exit_code", 0) or 0) == 0
        )
        if database_type:
            databases.append({
                "container": name,
                "container_id": str(container.get("id") or ""),
                "database_type": database_type,
                "state": status,
                "started_at": str(state.get("started_at") or ""),
                "finished_at": str(state.get("finished_at") or ""),
                "quiescence_status": "VERIFIED" if cleanly_quiesced else "ACTION_REQUIRED",
                "action": (
                    "Keep this database stopped for the complete snapshot operation."
                    if cleanly_quiesced
                    else "Stop this database cleanly before creating the recovery point."
                ),
            })

        for mount in container.get("mounts") or []:
            if not isinstance(mount, dict) or mount.get("Type") != "bind" or not mount.get("RW"):
                continue
            source = os.path.normpath(str(mount.get("Source") or ""))
            if not _safe_external_bind(source):
                continue
            record = external.setdefault(source, {
                "path": source,
                "selected": source in selected,
                "containers": [],
                "targets": [],
                "capture_status": "SELECTED" if source in selected else "NOT_SELECTED",
            })
            if name and name not in record["containers"]:
                record["containers"].append(name)
            target = str(mount.get("Destination") or "")
            if target and target not in record["targets"]:
                record["targets"].append(target)

        local_id = str(image.get("local_id") or "")
        digests = sorted(str(value) for value in (image.get("repo_digests") or []) if value)
        key = local_id or reference
        if key and key not in images:
            images[key] = {
                "reference": reference,
                "local_id": local_id,
                "registry_digests": digests,
                "recovery_method": "REGISTRY_DIGEST" if digests else "TRUSTED_LOCAL_EXPORT_REQUIRED",
                "containers": [],
            }
        if key and name and name not in images[key]["containers"]:
            images[key]["containers"].append(name)

    for record in external.values():
        record["containers"].sort(key=str.lower)
        record["targets"].sort()
    for record in images.values():
        record["containers"].sort(key=str.lower)

    databases.sort(key=lambda item: item["container"].lower())
    external_records = sorted(external.values(), key=lambda item: item["path"].lower())
    image_records = sorted(images.values(), key=lambda item: (item["reference"], item["local_id"]))
    database_ready = bool(databases) and all(
        item["quiescence_status"] == "VERIFIED" for item in databases
    )
    if not databases:
        database_ready = True

    return {
        "schema": "zimabrain.recovery-completion-plan.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "READ_ONLY_PLAN",
        "plan_status": "VERIFIED" if not errors else "NOT VERIFIED",
        "database_gate": {
            "status": "VERIFIED" if database_ready else "ACTION_REQUIRED",
            "containers": databases,
        },
        "external_bind_mounts": external_records,
        "image_recovery": image_records,
        "filesystem_metadata": {
            "strategy": "MODE_UID_GID_AND_XATTR_SIDECAR",
            "acl_source": "POSIX ACL extended attributes when readable",
            "restore_mode": "ISOLATED_ONLY_UNTIL_EXPLICIT_RECONSTRUCTION",
        },
        "summary": {
            "database_containers": len(databases),
            "databases_quiesced": sum(
                item["quiescence_status"] == "VERIFIED" for item in databases
            ),
            "external_bind_candidates": len(external_records),
            "external_bind_selected": sum(item["selected"] for item in external_records),
            "images": len(image_records),
            "images_with_registry_digest": sum(
                bool(item["registry_digests"]) for item in image_records
            ),
            "images_requiring_export": sum(
                not bool(item["registry_digests"]) for item in image_records
            ),
        },
        "errors": errors,
    }

def build_reconstruction_plan(reconstruction_evidence, existing_containers, existing_networks):
    """Build conflict-aware network/container actions without applying them."""
    evidence = reconstruction_evidence if isinstance(reconstruction_evidence, dict) else {}
    container_names = {str(value).lstrip("/") for value in (existing_containers or [])}
    network_names = {str(value) for value in (existing_networks or [])}
    network_actions = []
    container_actions = []
    blockers = []

    if evidence.get("capture_status") != "VERIFIED":
        blockers.append("Private reconstruction evidence is not verified.")

    for network in evidence.get("networks") or []:
        name = str((network or {}).get("name") or "")
        if not name or name in BUILTIN_NETWORKS:
            continue
        conflict = name in network_names
        network_actions.append({
            "name": name,
            "action": "KEEP_EXISTING" if conflict else "CREATE",
            "conflict": conflict,
            "driver": str((network or {}).get("driver") or ""),
        })

    for container in evidence.get("containers") or []:
        name = str((container or {}).get("name") or "")
        if not name:
            continue
        conflict = name in container_names
        image = (container or {}).get("image") or {}
        digest_available = bool(image.get("repo_digests"))
        action = "BLOCKED_EXISTING_NAME" if conflict else (
            "CREATE_STOPPED" if digest_available else "BLOCKED_IMAGE_UNAVAILABLE"
        )
        if action.startswith("BLOCKED"):
            blockers.append(f"Container {name}: {action}.")
        container_actions.append({
            "name": name,
            "action": action,
            "conflict": conflict,
            "image_reference": str(image.get("reference") or ""),
            "registry_digests": list(image.get("repo_digests") or []),
            "start_after_create": False,
        })

    return {
        "schema": "zimabrain.controlled-reconstruction-plan.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "PREVIEW_ONLY",
        "apply_enabled": False,
        "plan_status": "READY_FOR_EXPLICIT_TEST_BOARD_REVIEW" if not blockers else "BLOCKED",
        "networks": network_actions,
        "containers": container_actions,
        "blockers": blockers,
        "safety": [
            "Existing networks and containers are never replaced.",
            "Reconstructed containers are created stopped.",
            "Live apply is disabled until test-board validation explicitly enables it.",
        ],
    }
