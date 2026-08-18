"""Deterministic planning and durable state for Guided Recovery.

Planning functions are read-only.  Docker changes remain the responsibility of
the authenticated Flask routes, after an explicit user confirmation.  The
persisted operation record contains container identities and state only; it
never stores environment or label values from private reconstruction evidence.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile

from brain import recovery_completion


SCHEMA = "zimabrain.guided-recovery-plan.v1"
STATE_SCHEMA = "zimabrain.guided-recovery-state.v1"
CAPTURED_ROOTS = ("/DATA/AppData", "/var/lib/casaos/apps")
PROTECTED_CONTAINERS = {"zimabrain-snapshot-lab", "ttydbridge"}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _normal(path):
    return os.path.normpath(str(path or ""))


def _overlap(first, second):
    left = _normal(first)
    right = _normal(second)
    return bool(left and right) and (
        left == right
        or left.startswith(right + os.sep)
        or right.startswith(left + os.sep)
    )


def _state(container):
    value = container.get("state") or {}
    return str(value.get("status") or container.get("state_at_capture") or "unknown")


def _running(container):
    state = container.get("state") or {}
    return bool(state.get("running")) or _state(container) in {"running", "restarting"}


def _canonical_selected(completion_plan, selected_external_paths):
    candidates = {
        _normal(item.get("path"))
        for item in completion_plan.get("external_bind_mounts") or []
        if _normal(item.get("path"))
    }
    selected = []
    errors = []
    for raw in selected_external_paths or []:
        value = _normal(raw)
        if value not in candidates:
            errors.append(f"Selected external path is not a verified candidate: {value}")
            continue
        if value not in selected:
            selected.append(value)
    selected.sort(key=lambda value: (value.count(os.sep), value.lower()))
    deduplicated = []
    removed = []
    for value in selected:
        parent = next((item for item in deduplicated if _overlap(item, value)), "")
        if parent:
            removed.append({"path": value, "covered_by": parent})
        else:
            deduplicated.append(value)
    return deduplicated, removed, errors


def _recommendation(path, containers):
    value = _normal(path)
    parts = [part for part in value.split(os.sep) if part]
    broad = (
        value in {"/DATA", "/media", "/mnt"}
        or (value.startswith("/media/") and len(parts) <= 2)
        or (value.startswith("/mnt/") and len(parts) <= 2)
        or value.lower().endswith(("/borg-repos", "/backup", "/backups"))
    )
    if broad:
        return {
            "status": "REVIEW_REQUIRED",
            "reason": "This is a broad disk or backup scope; size and necessity must be reviewed.",
        }
    if len(containers) == 1:
        return {
            "status": "RECOMMENDED",
            "reason": "One application writes persistent data here outside the default protected roots.",
        }
    return {
        "status": "REVIEW_REQUIRED",
        "reason": "Multiple applications use this external path; confirm that all contents are required.",
    }


def apply_external_measurement(plan, measurement, max_external_bytes):
    """Attach selected-path measurements and block unsafe downtime approval."""
    result = dict(plan if isinstance(plan, dict) else {})
    selected_paths = [
        _normal(value)
        for value in result.get("selected_external_paths") or []
        if _normal(value)
    ]
    selected_set = set(selected_paths)
    measured = measurement if isinstance(measurement, dict) else {}
    records = [
        item
        for item in measured.get("paths") or []
        if isinstance(item, dict)
    ]
    records_by_path = {
        _normal(item.get("requested_path")): item
        for item in records
        if _normal(item.get("requested_path"))
    }
    measured_paths = set(records_by_path)
    external = []

    for original in result.get("external_bind_mounts") or []:
        item = dict(original)
        path = _normal(item.get("path"))
        if path not in selected_set:
            item["measurement_status"] = "NOT_SELECTED"
            item["regular_file_bytes"] = 0
            item["regular_files"] = 0
        else:
            record = records_by_path.get(path)
            if record is None:
                item["measurement_status"] = "NOT_MEASURED"
                item["regular_file_bytes"] = 0
                item["regular_files"] = 0
            else:
                item["measurement_status"] = "MEASURED"
                item["regular_file_bytes"] = int(
                    record.get("regular_file_bytes", 0) or 0
                )
                item["regular_files"] = int(record.get("regular_files", 0) or 0)
        external.append(item)

    total_bytes = int(measured.get("regular_file_bytes", 0) or 0)
    total_files = int(measured.get("regular_files", 0) or 0)
    limit_bytes = int(max_external_bytes or 0)
    measurement_errors = [str(value) for value in measured.get("errors") or []]
    missing_paths = sorted(selected_set - measured_paths)
    measurement_ok = (
        not selected_paths
        or (
            measured.get("measurement_status") == "MEASURED"
            and not missing_paths
            and measured_paths == selected_set
        )
    )

    blockers = list(result.get("blockers") or [])
    if selected_paths and not measurement_ok:
        blockers.append(
            "Selected external paths could not be completely measured before downtime."
        )
        blockers.extend(measurement_errors)
        if missing_paths:
            blockers.append(
                "Missing selected-path measurements: " + ", ".join(missing_paths)
            )
    if selected_paths and measurement_ok and total_bytes > limit_bytes:
        blockers.append(
            "Selected external paths total "
            f"{total_bytes:,} B, exceeding the {limit_bytes:,} B "
            "(64 GiB) safety limit. Clear oversized selections before approving downtime."
        )

    result["external_bind_mounts"] = external
    result["external_selection_measurement"] = {
        "measurement_status": "MEASURED" if measurement_ok else "NOT MEASURED",
        "selected_paths": len(selected_paths),
        "regular_file_bytes": total_bytes,
        "regular_files": total_files,
        "limit_bytes": limit_bytes,
        "within_limit": bool(measurement_ok and total_bytes <= limit_bytes),
        "errors": measurement_errors,
    }
    summary = dict(result.get("summary") or {})
    summary["external_selected_bytes"] = total_bytes
    summary["external_selected_files"] = total_files
    summary["external_limit_bytes"] = limit_bytes
    result["summary"] = summary
    result["blockers"] = list(dict.fromkeys(str(value) for value in blockers if value))
    if result["blockers"]:
        result["plan_status"] = "BLOCKED"
        result["apply_enabled"] = False
    return result


def build_plan(reconstruction_evidence, selected_external_paths=None):
    """Build an explicit downtime and restart plan without changing Docker."""
    evidence = reconstruction_evidence if isinstance(reconstruction_evidence, dict) else {}
    completion = recovery_completion.build_capture_plan(
        evidence,
        selected_external_paths,
    )
    selected, removed, selected_errors = _canonical_selected(
        completion,
        selected_external_paths,
    )
    roots = list(CAPTURED_ROOTS) + selected
    writers = []
    blockers = list(completion.get("errors") or []) + selected_errors
    detected_databases = {
        str(item.get("container") or "")
        for item in ((completion.get("database_gate") or {}).get("containers") or [])
        if item.get("container")
    }

    external = []
    for item in completion.get("external_bind_mounts") or []:
        path = _normal(item.get("path"))
        containers = sorted(
            str(name) for name in (item.get("containers") or []) if name
        )
        recommendation = _recommendation(path, containers)
        external.append({
            **item,
            "selected": path in selected,
            "recommendation": recommendation["status"],
            "recommendation_reason": recommendation["reason"],
        })

    for container in evidence.get("containers") or []:
        if not isinstance(container, dict) or not _running(container):
            continue
        name = str(container.get("name") or "")
        database = name in detected_databases
        reasons = []
        for mount in container.get("mounts") or []:
            if not isinstance(mount, dict) or not bool(mount.get("RW")):
                continue
            mount_type = str(mount.get("Type") or "")
            source = _normal(mount.get("Source"))
            target = str(mount.get("Destination") or "")
            if mount_type == "volume":
                reasons.append({
                    "kind": "NAMED_VOLUME",
                    "source": str(mount.get("Name") or source),
                    "target": target,
                })
            elif mount_type == "bind" and any(_overlap(source, root) for root in roots):
                reasons.append({
                    "kind": "CAPTURED_BIND",
                    "source": source,
                    "target": target,
                })
        if database:
            reasons.append({
                "kind": "DATABASE_QUIESCENCE",
                "source": "detected-database-service",
                "target": "clean-stop-required",
            })
        if not reasons:
            continue
        if name in PROTECTED_CONTAINERS:
            if name != "zimabrain-snapshot-lab":
                blockers.append(
                    f"Protected container {name} writes to the selected recovery scope."
                )
            continue
        writers.append({
            "name": name,
            "container_id": str(container.get("id") or ""),
            "state": _state(container),
            "database": database,
            "reasons": reasons,
        })

    writers.sort(key=lambda item: (not item["database"], item["name"].lower()))
    restart_order = [item["name"] for item in writers]
    fingerprint = {
        "selected_external_paths": selected,
        "writers": [
            [item["name"], item["container_id"], item["state"]]
            for item in writers
        ],
    }
    plan_id = hashlib.sha256(
        json.dumps(fingerprint, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    automation_ready = not blockers and completion.get("plan_status") == "VERIFIED"

    return {
        "schema": SCHEMA,
        "generated_at": _now(),
        "mode": "GUIDED_RECOVERY",
        "plan_id": plan_id,
        "plan_status": "READY_FOR_APPROVAL" if automation_ready else "BLOCKED",
        "apply_enabled": automation_ready,
        "selected_external_paths": selected,
        "deduplicated_external_paths": removed,
        "external_bind_mounts": external,
        "writers_to_stop": writers,
        "restart_order": restart_order,
        "database_writers": [item["name"] for item in writers if item["database"]],
        "summary": {
            "writers_to_stop": len(writers),
            "database_writers": sum(item["database"] for item in writers),
            "external_candidates": len(external),
            "external_selected": len(selected),
            "images_requiring_export": int(
                (completion.get("summary") or {}).get("images_requiring_export", 0) or 0
            ),
        },
        "safety": [
            "The plan is recalculated immediately before any container is stopped.",
            "Snapshot Lab and the browser terminal are never stopped by Guided Recovery.",
            "Only containers recorded as active by the approved plan are restarted.",
            "Snapshot and isolated-restore verification still use the Recovery Pro verifier.",
        ],
        "blockers": blockers,
    }


def new_state(plan, destination_id="", baseline_snapshot_id=""):
    return {
        "schema": STATE_SCHEMA,
        "updated_at": _now(),
        "status": "APPROVED",
        "plan_id": str(plan.get("plan_id") or ""),
        "destination_id": str(destination_id or ""),
        "baseline_snapshot_id": str(baseline_snapshot_id or ""),
        "selected_external_paths": list(plan.get("selected_external_paths") or []),
        "writers": [
            {
                "name": str(item.get("name") or ""),
                "container_id": str(item.get("container_id") or ""),
                "database": bool(item.get("database")),
                "original_state": str(item.get("state") or ""),
            }
            for item in plan.get("writers_to_stop") or []
        ],
        "errors": [],
    }


def public_state(record):
    value = record if isinstance(record, dict) else {}
    return {
        "schema": STATE_SCHEMA,
        "updated_at": str(value.get("updated_at") or ""),
        "status": str(value.get("status") or "NOT STARTED"),
        "plan_id": str(value.get("plan_id") or ""),
        "destination_id": str(value.get("destination_id") or ""),
        "baseline_snapshot_id": str(value.get("baseline_snapshot_id") or ""),
        "selected_external_paths": list(value.get("selected_external_paths") or []),
        "writers": [
            {
                "name": str(item.get("name") or ""),
                "database": bool(item.get("database")),
                "original_state": str(item.get("original_state") or ""),
            }
            for item in value.get("writers") or []
            if isinstance(item, dict)
        ],
        "errors": list(value.get("errors") or []),
    }


def load_state(path):
    target = Path(path)
    if not target.is_file() or target.is_symlink():
        return public_state({})
    try:
        record = json.loads(target.read_text(encoding="utf-8"))
    except Exception as exc:
        return public_state({
            "status": "INVALID",
            "errors": [f"Guided recovery state is invalid: {exc}"],
        })
    if record.get("schema") != STATE_SCHEMA:
        return public_state({
            "status": "INVALID",
            "errors": ["Guided recovery state schema is invalid."],
        })
    return record


def write_state(path, record):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(record)
    payload["schema"] = STATE_SCHEMA
    payload["updated_at"] = _now()
    descriptor, temporary = tempfile.mkstemp(
        prefix=target.name + ".",
        dir=str(target.parent),
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return payload
