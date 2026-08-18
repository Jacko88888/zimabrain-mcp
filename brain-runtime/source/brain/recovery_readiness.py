"""Read-only recovery-readiness evidence for ZimaOS application recovery."""

from datetime import datetime, timezone
import json
import os
from urllib.parse import quote


CAPTURED_BIND_ROOTS = (
    "/DATA/AppData",
    "/var/lib/casaos/apps",
)

RUNTIME_BIND_ROOTS = (
    "/dev",
    "/proc",
    "/run",
    "/sys",
    "/var/run",
)

DATABASE_MARKERS = {
    "mariadb": "MariaDB",
    "mysql": "MySQL",
    "postgres": "PostgreSQL",
    "redis": "Redis",
}

WARNING_GUIDANCE = {
    "DATABASE_CONSISTENCY": ("CRITICAL", "Add an application-aware dump or a verified quiesce hook before capture."),
    "WRITABLE_LAYER_DATA": ("HIGH", "Move persistent data into a protected bind mount or named volume."),
    "EXTERNAL_WRITABLE_BIND": ("HIGH", "Review and explicitly add required external bind paths to recovery scope."),
    "MUTABLE_IMAGE_REFERENCE": ("MEDIUM", "Pin the application to an immutable image digest."),
    "IMAGE_DIGEST_MISSING": ("MEDIUM", "Record a pullable registry digest or preserve a trusted image export."),
}

HOST_METADATA_SCRIPT = r'''import json
import os
import platform
import socket

release = {}
try:
    with open("/etc/os-release", "r", encoding="utf-8") as handle:
        for line in handle:
            key, separator, value = line.rstrip("\n").partition("=")
            if separator:
                release[key] = value.strip().strip('"')
except OSError:
    pass

casaos_version = "unknown"
for candidate in (
    "/var/lib/casaos/version",
    "/etc/casaos/version",
    "/var/lib/casaos_data/version",
):
    try:
        with open(candidate, "r", encoding="utf-8") as handle:
            value = handle.readline().strip()
    except OSError:
        continue
    if value:
        casaos_version = value[:200]
        break

timezone_name = os.environ.get("TZ", "").strip()
if not timezone_name:
    try:
        timezone_name = os.path.realpath("/etc/localtime").partition("/zoneinfo/")[2]
    except OSError:
        timezone_name = ""

print(json.dumps({
    "hostname": socket.gethostname(),
    "architecture": platform.machine(),
    "kernel": platform.release(),
    "operating_system": release.get("PRETTY_NAME", platform.system()),
    "zimaos_version": release.get("VERSION_ID", "unknown"),
    "casaos_version": casaos_version,
    "timezone": timezone_name or "host default",
}, sort_keys=True))
'''


def _under(path, roots):
    clean = os.path.normpath(str(path or ""))
    return any(clean == root or clean.startswith(root + os.sep) for root in roots)


def _database_type(name, image):
    value = (str(name) + " " + str(image)).lower()
    for marker, label in DATABASE_MARKERS.items():
        if marker in value:
            return label
    return ""


def _image_is_mutable(image_ref):
    value = str(image_ref or "")
    if "@sha256:" in value:
        return False
    last = value.rsplit("/", 1)[-1]
    return ":" not in last or last.endswith(":latest") or last.endswith(":main") or last.endswith(":master")


def _host_metadata(command_runner):
    if command_runner is None:
        return {}, ["Host metadata runner is unavailable."]
    result = command_runner(["python3", "-c", HOST_METADATA_SCRIPT], timeout=20)
    if not result.get("ok"):
        return {}, ["Host metadata collection failed: " + str(result.get("stderr") or "unknown error")]
    try:
        payload = json.loads(result.get("stdout") or "{}")
    except (TypeError, ValueError) as exc:
        return {}, [f"Host metadata JSON was invalid: {exc}"]
    return payload if isinstance(payload, dict) else {}, []


def _writable_layer_sizes(command_runner, container_ids):
    wanted = [str(value) for value in container_ids if value]
    if not wanted:
        return {}, []
    if command_runner is None:
        return {}, ["Writable-layer size runner is unavailable."]
    result = command_runner(
        [
            "docker",
            "inspect",
            "--size",
            "--format",
            "{{.Id}}\t{{.SizeRw}}",
            *wanted,
        ],
        timeout=180,
    )
    if not result.get("ok"):
        return {}, [
            "Writable-layer size collection failed: "
            + str(result.get("stderr") or "unknown error")
        ]
    sizes = {}
    invalid = []
    for line in str(result.get("stdout") or "").splitlines():
        container_id, separator, raw_size = line.partition("\t")
        if not separator:
            invalid.append(line)
            continue
        try:
            sizes[container_id] = max(0, int(raw_size))
        except (TypeError, ValueError):
            invalid.append(line)
    missing = [container_id for container_id in wanted if container_id not in sizes]
    errors = []
    if invalid:
        errors.append(
            f"Writable-layer output contained {len(invalid)} invalid records."
        )
    if missing:
        errors.append(
            f"Writable-layer sizes were missing for {len(missing)} containers."
        )
    return sizes, errors


def _network_record(item):
    ipam = item.get("IPAM") or {}
    return {
        "name": str(item.get("Name") or ""),
        "id": str(item.get("Id") or "")[:12],
        "driver": str(item.get("Driver") or "unknown"),
        "scope": str(item.get("Scope") or "unknown"),
        "internal": bool(item.get("Internal")),
        "attachable": bool(item.get("Attachable")),
        "config": [
            {
                "subnet": str(row.get("Subnet") or ""),
                "gateway": str(row.get("Gateway") or ""),
                "ip_range": str(row.get("IPRange") or ""),
            }
            for row in (ipam.get("Config") or [])
            if isinstance(row, dict)
        ],
        "options": sorted(str(key) for key in (item.get("Options") or {})),
        "labels": sorted(str(key) for key in (item.get("Labels") or {})),
        "container_count": len(item.get("Containers") or {}),
        "recovery_status": "RECORDED_NOT_CAPTURED",
    }


def _copy_json(value):
    """Return a detached JSON-safe value from Docker API data."""
    return json.loads(json.dumps(value, sort_keys=True))


def collect_reconstruction_evidence(docker_get, command_runner=None):
    """Capture private, exact Docker reconstruction evidence for a snapshot.

    Unlike the public readiness report, this artifact intentionally retains
    environment and label values.  It must therefore remain private and is
    stored only inside the recovery point.
    """
    evidence = {
        "schema": "zimabrain.reconstruction-evidence.v1",
        "sensitivity": "PRIVATE_CONTAINS_CONFIGURATION_SECRETS",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "capture_status": "NOT VERIFIED",
        "host": {},
        "docker_engine": {},
        "containers": [],
        "networks": [],
        "summary": {},
        "errors": [],
        "limitations": [
            "Docker image layers and writable container layers are not copied.",
            "Network and container definitions are recorded but are not automatically recreated.",
            "Application-aware database consistency is not established by this evidence artifact.",
            "External bind-mounted data is inventoried but is not copied unless it is already inside the verified recovery scope.",
        ],
    }
    evidence["host"], host_errors = _host_metadata(command_runner)
    evidence["errors"].extend(host_errors)
    try:
        version = docker_get("/version") or {}
        summaries = docker_get("/containers/json?all=1")
        raw_networks = docker_get("/networks")
    except Exception as exc:
        evidence["errors"].append(f"Docker reconstruction inventory failed: {exc}")
        return evidence
    if not isinstance(summaries, list):
        evidence["errors"].append("Docker API did not return a container list.")
        return evidence
    if not isinstance(raw_networks, list):
        evidence["errors"].append("Docker API did not return a network list.")
        return evidence

    evidence["docker_engine"] = {
        "version": str(version.get("Version") or "unknown"),
        "api_version": str(version.get("ApiVersion") or "unknown"),
        "architecture": str(version.get("Arch") or "unknown"),
        "operating_system": str(version.get("Os") or "unknown"),
    }
    for network in raw_networks:
        if not isinstance(network, dict):
            evidence["errors"].append("Docker network inventory contains a non-object record.")
            continue
        evidence["networks"].append({
            "name": str(network.get("Name") or ""),
            "id": str(network.get("Id") or ""),
            "created": str(network.get("Created") or ""),
            "scope": str(network.get("Scope") or ""),
            "driver": str(network.get("Driver") or ""),
            "enable_ipv6": bool(network.get("EnableIPv6")),
            "internal": bool(network.get("Internal")),
            "attachable": bool(network.get("Attachable")),
            "ingress": bool(network.get("Ingress")),
            "config_only": bool(network.get("ConfigOnly")),
            "ipam": _copy_json(network.get("IPAM") or {}),
            "options": _copy_json(network.get("Options") or {}),
            "labels": _copy_json(network.get("Labels") or {}),
        })

    image_cache = {}
    for summary in summaries:
        if not isinstance(summary, dict):
            evidence["errors"].append("Docker container inventory contains a non-object record.")
            continue
        container_id = str(summary.get("Id") or "")
        if not container_id:
            evidence["errors"].append("Docker container inventory contains an empty identity.")
            continue
        try:
            inspected = docker_get(f"/containers/{quote(container_id, safe='')}/json") or {}
        except Exception as exc:
            evidence["errors"].append(f"Container {container_id[:12]} inspection failed: {exc}")
            continue
        if not isinstance(inspected, dict) or not inspected.get("Id"):
            evidence["errors"].append(f"Container {container_id[:12]} inspection was incomplete.")
            continue
        config = inspected.get("Config") or {}
        host_config = inspected.get("HostConfig") or {}
        network_settings = inspected.get("NetworkSettings") or {}
        image_id = str(inspected.get("Image") or summary.get("ImageID") or "")
        image = image_cache.get(image_id)
        if image is None:
            try:
                image = docker_get(f"/images/{quote(image_id, safe='')}/json") or {}
            except Exception as exc:
                image = {}
                evidence["errors"].append(
                    f"Image metadata for container {container_id[:12]} failed: {exc}"
                )
            image_cache[image_id] = image
        name = str(inspected.get("Name") or "").lstrip("/")
        container_state = inspected.get("State") or {}
        evidence["containers"].append({
            "name": name,
            "id": str(inspected.get("Id") or ""),
            "created": str(inspected.get("Created") or ""),
            "state_at_capture": str((inspected.get("State") or {}).get("Status") or "unknown"),
            "state": {
                "status": str(container_state.get("Status") or "unknown"),
                "running": bool(container_state.get("Running")),
                "paused": bool(container_state.get("Paused")),
                "restarting": bool(container_state.get("Restarting")),
                "oom_killed": bool(container_state.get("OOMKilled")),
                "dead": bool(container_state.get("Dead")),
                "exit_code": int(container_state.get("ExitCode", 0) or 0),
                "started_at": str(container_state.get("StartedAt") or ""),
                "finished_at": str(container_state.get("FinishedAt") or ""),
            },
            "image": {
                "reference": str(config.get("Image") or summary.get("Image") or ""),
                "local_id": image_id,
                "repo_tags": _copy_json((image or {}).get("RepoTags") or []),
                "repo_digests": _copy_json((image or {}).get("RepoDigests") or []),
            },
            "config": {
                "hostname": str(config.get("Hostname") or ""),
                "domainname": str(config.get("Domainname") or ""),
                "user": str(config.get("User") or ""),
                "attach_stdin": bool(config.get("AttachStdin")),
                "attach_stdout": bool(config.get("AttachStdout")),
                "attach_stderr": bool(config.get("AttachStderr")),
                "tty": bool(config.get("Tty")),
                "open_stdin": bool(config.get("OpenStdin")),
                "stdin_once": bool(config.get("StdinOnce")),
                "environment": _copy_json(config.get("Env") or []),
                "command": _copy_json(config.get("Cmd")),
                "healthcheck": _copy_json(config.get("Healthcheck")),
                "arguments_escaped": bool(config.get("ArgsEscaped")),
                "image": str(config.get("Image") or ""),
                "volumes": _copy_json(config.get("Volumes") or {}),
                "working_dir": str(config.get("WorkingDir") or ""),
                "entrypoint": _copy_json(config.get("Entrypoint")),
                "network_disabled": bool(config.get("NetworkDisabled")),
                "mac_address": str(config.get("MacAddress") or ""),
                "on_build": _copy_json(config.get("OnBuild")),
                "labels": _copy_json(config.get("Labels") or {}),
                "stop_signal": str(config.get("StopSignal") or ""),
                "stop_timeout": config.get("StopTimeout"),
                "shell": _copy_json(config.get("Shell")),
                "exposed_ports": _copy_json(config.get("ExposedPorts") or {}),
            },
            "host_config": _copy_json(host_config),
            "mounts": _copy_json(inspected.get("Mounts") or []),
            "network_attachments": _copy_json(network_settings.get("Networks") or {}),
        })

    evidence["containers"].sort(key=lambda item: item["name"].lower())
    evidence["networks"].sort(key=lambda item: item["name"].lower())
    evidence["summary"] = {
        "containers": len(evidence["containers"]),
        "networks": len(evidence["networks"]),
        "custom_networks": sum(
            item["name"] not in {"bridge", "host", "none"}
            for item in evidence["networks"]
        ),
        "images_with_registry_digest": sum(
            bool((item.get("image") or {}).get("repo_digests"))
            for item in evidence["containers"]
        ),
    }
    if len(evidence["containers"]) != len(summaries):
        evidence["errors"].append(
            "Not every Docker container produced verified reconstruction evidence."
        )
    evidence["capture_status"] = "VERIFIED" if not evidence["errors"] else "NOT VERIFIED"
    return evidence


def collect_readiness(docker_get, command_runner=None):
    result = {
        "schema": "zimabrain.recovery-readiness.v1",
        "mode": "read-only-assessment",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "assessment_status": "NOT VERIFIED",
        "overall_rating": "UNKNOWN",
        "host": {},
        "docker_engine": {},
        "summary": {},
        "checks": [],
        "containers": [],
        "networks": [],
        "warnings": [],
        "errors": [],
        "privacy": {
            "environment_values_exposed": False,
            "label_values_exposed": False,
            "note": "Only environment-variable and label names are included in this report.",
        },
    }

    result["host"], host_errors = _host_metadata(command_runner)
    result["errors"].extend(host_errors)

    try:
        version = docker_get("/version") or {}
        summaries = docker_get("/containers/json?all=1")
        raw_networks = docker_get("/networks")
    except Exception as exc:
        result["errors"].append(f"Docker readiness inventory failed: {exc}")
        return result

    if not isinstance(summaries, list):
        result["errors"].append("Docker API did not return a container list.")
        return result
    if not isinstance(raw_networks, list):
        raw_networks = []
        result["errors"].append("Docker API did not return a network list.")

    container_ids = [
        str(summary.get("Id") or "")
        for summary in summaries
        if isinstance(summary, dict) and summary.get("Id")
    ]
    writable_sizes, writable_size_errors = _writable_layer_sizes(
        command_runner,
        container_ids,
    )
    result["errors"].extend(writable_size_errors)

    result["docker_engine"] = {
        "version": str(version.get("Version") or "unknown"),
        "api_version": str(version.get("ApiVersion") or "unknown"),
        "architecture": str(version.get("Arch") or "unknown"),
        "operating_system": str(version.get("Os") or "unknown"),
    }
    result["networks"] = sorted(
        (_network_record(item) for item in raw_networks if isinstance(item, dict)),
        key=lambda item: item["name"].lower(),
    )

    inspection_failures = 0
    image_digest_cache = {}
    for summary in summaries:
        container_id = str(summary.get("Id") or "")
        try:
            inspected = docker_get(f"/containers/{quote(container_id, safe='')}/json") or {}
        except Exception as exc:
            inspected = {}
            result["errors"].append(f"Container {container_id[:12]} inspection failed: {exc}")
        if not isinstance(inspected, dict) or not inspected.get("Id"):
            inspection_failures += 1
            continue

        config = inspected.get("Config") or {}
        host_config = inspected.get("HostConfig") or {}
        network_settings = inspected.get("NetworkSettings") or {}
        attached_networks = network_settings.get("Networks") or {}
        image_ref = str(config.get("Image") or summary.get("Image") or "unknown")
        image_id = str(inspected.get("Image") or summary.get("ImageID") or "")
        names = summary.get("Names") or []
        name = str(inspected.get("Name") or (names[0] if names else container_id[:12])).lstrip("/")

        repo_digests = image_digest_cache.get(image_id)
        if repo_digests is None and image_id:
            try:
                image = docker_get(f"/images/{quote(image_id, safe='')}/json") or {}
                repo_digests = sorted(str(value) for value in (image.get("RepoDigests") or []) if value)
            except Exception as exc:
                repo_digests = []
                result["errors"].append(f"Image metadata for {name} failed: {exc}")
            image_digest_cache[image_id] = repo_digests
        repo_digests = repo_digests or []

        external_binds = []
        captured_binds = []
        named_volumes = []
        runtime_mounts = []
        for mount in inspected.get("Mounts") or []:
            mount_type = str(mount.get("Type") or "unknown")
            source = str(mount.get("Source") or "")
            record = {
                "type": mount_type,
                "name": str(mount.get("Name") or ""),
                "source": source,
                "destination": str(mount.get("Destination") or ""),
                "read_write": bool(mount.get("RW")),
            }
            if mount_type == "volume":
                named_volumes.append(record)
            elif mount_type == "bind" and _under(source, CAPTURED_BIND_ROOTS):
                captured_binds.append(record)
            elif mount_type == "bind" and _under(source, RUNTIME_BIND_ROOTS):
                runtime_mounts.append(record)
            elif mount_type == "bind" and bool(mount.get("RW")):
                external_binds.append(record)

        environment_names = sorted({
            str(value).partition("=")[0]
            for value in (config.get("Env") or [])
            if str(value).partition("=")[0]
        })
        labels = sorted(str(key) for key in (config.get("Labels") or {}))
        database = _database_type(name, image_ref)
        size_rw = int(
            writable_sizes.get(
                container_id,
                summary.get("SizeRw", 0) or 0,
            )
        )
        mutable_image = _image_is_mutable(image_ref)
        database_consistency = "APPLICATION_AWARE_BACKUP_REQUIRED" if database else "NOT_APPLICABLE"

        container = {
            "name": name,
            "id": str(inspected.get("Id") or "")[:12],
            "state": str((inspected.get("State") or {}).get("Status") or summary.get("State") or "unknown"),
            "image_ref": image_ref,
            "image_id": image_id,
            "image_repo_digests": repo_digests,
            "mutable_image_reference": mutable_image,
            "environment_variable_names": environment_names,
            "label_names": labels,
            "restart_policy": str((host_config.get("RestartPolicy") or {}).get("Name") or "no"),
            "privileged": bool(host_config.get("Privileged")),
            "security_options": sorted(str(value) for value in (host_config.get("SecurityOpt") or [])),
            "cap_add": sorted(str(value) for value in (host_config.get("CapAdd") or [])),
            "cap_drop": sorted(str(value) for value in (host_config.get("CapDrop") or [])),
            "devices": len(host_config.get("Devices") or []),
            "ports": len(host_config.get("PortBindings") or {}),
            "command_recorded": config.get("Cmd") is not None,
            "entrypoint_recorded": config.get("Entrypoint") is not None,
            "networks": sorted(str(value) for value in attached_networks),
            "network_attachments": [
                {
                    "name": str(network_name),
                    "ip_address": str((attachment or {}).get("IPAddress") or ""),
                    "global_ipv6_address": str((attachment or {}).get("GlobalIPv6Address") or ""),
                    "mac_address": str((attachment or {}).get("MacAddress") or ""),
                    "aliases": sorted(str(value) for value in ((attachment or {}).get("Aliases") or []) if value),
                }
                for network_name, attachment in sorted(attached_networks.items())
            ],
            "captured_bind_mounts": captured_binds,
            "named_volumes": named_volumes,
            "external_writable_bind_mounts": external_binds,
            "runtime_mounts": runtime_mounts,
            "writable_layer_bytes": size_rw,
            "database_type": database,
            "database_consistency": database_consistency,
            "configuration_status": "RECORDED_NOT_CAPTURED",
        }
        result["containers"].append(container)

        if not repo_digests:
            result["warnings"].append({"code": "IMAGE_DIGEST_MISSING", "container": name, "message": "No immutable registry image digest was found."})
        if mutable_image:
            result["warnings"].append({"code": "MUTABLE_IMAGE_REFERENCE", "container": name, "message": f"Image reference {image_ref} can change over time."})
        if size_rw > 0:
            result["warnings"].append({"code": "WRITABLE_LAYER_DATA", "container": name, "bytes": size_rw, "message": "Writable container-layer data is not protected."})
        if external_binds:
            result["warnings"].append({"code": "EXTERNAL_WRITABLE_BIND", "container": name, "count": len(external_binds), "message": "Writable bind-mounted data exists outside the current recovery scope."})
        if database:
            result["warnings"].append({"code": "DATABASE_CONSISTENCY", "container": name, "database": database, "message": f"{database} has no verified application-aware backup hook."})

    result["containers"].sort(key=lambda item: item["name"].lower())
    custom_networks = [item for item in result["networks"] if item["name"] not in {"bridge", "host", "none"}]
    warnings_by_code = {}
    for warning in result["warnings"]:
        code = warning["code"]
        severity, recommendation = WARNING_GUIDANCE.get(
            code,
            ("REVIEW", "Review this item before relying on complete application recovery."),
        )
        warning["severity"] = severity
        warning["recommendation"] = recommendation
        warnings_by_code[code] = warnings_by_code.get(code, 0) + 1

    summary = {
        "containers": len(result["containers"]),
        "running_containers": sum(item["state"] == "running" for item in result["containers"]),
        "container_configurations_recorded": len(result["containers"]),
        "custom_networks_recorded": len(custom_networks),
        "named_volume_mounts": sum(len(item["named_volumes"]) for item in result["containers"]),
        "captured_bind_mounts": sum(len(item["captured_bind_mounts"]) for item in result["containers"]),
        "external_writable_bind_mounts": sum(len(item["external_writable_bind_mounts"]) for item in result["containers"]),
        "writable_layer_containers": warnings_by_code.get("WRITABLE_LAYER_DATA", 0),
        "database_containers_without_hooks": warnings_by_code.get("DATABASE_CONSISTENCY", 0),
        "mutable_image_references": warnings_by_code.get("MUTABLE_IMAGE_REFERENCE", 0),
        "images_without_repo_digest": warnings_by_code.get("IMAGE_DIGEST_MISSING", 0),
        "inspection_failures": inspection_failures,
        "warning_count": len(result["warnings"]),
    }
    result["summary"] = summary
    result["checks"] = [
        {"key": "appdata", "label": "AppData recovery", "status": "PROTECTED", "detail": "/DATA/AppData is in the current verified bundle scope."},
        {"key": "named_volumes", "label": "Docker named volumes", "status": "PROTECTED", "detail": "Docker Engine verified named volumes are in the current bundle scope."},
        {"key": "container_config", "label": "Container configuration", "status": "RECORDED_NOT_CAPTURED", "detail": f"{summary['container_configurations_recorded']} configurations inventoried; exact reconstruction is not implemented yet."},
        {"key": "networks", "label": "Docker networks", "status": "RECORDED_NOT_CAPTURED", "detail": f"{summary['custom_networks_recorded']} custom networks inventoried; recreation is not implemented yet."},
        {"key": "image_reproducibility", "label": "Image reproducibility", "status": "WARNING" if summary["mutable_image_references"] or summary["images_without_repo_digest"] else "RECORDED", "detail": f"{summary['mutable_image_references']} mutable references; {summary['images_without_repo_digest']} images without a registry digest."},
        {"key": "databases", "label": "Database consistency", "status": "WARNING" if summary["database_containers_without_hooks"] else "NOT_DETECTED", "detail": f"{summary['database_containers_without_hooks']} database containers need application-aware backup hooks."},
        {"key": "writable_layers", "label": "Writable container layers", "status": "WARNING" if summary["writable_layer_containers"] else "CLEAR", "detail": f"{summary['writable_layer_containers']} containers report writable-layer data."},
        {"key": "external_binds", "label": "External writable bind mounts", "status": "WARNING" if summary["external_writable_bind_mounts"] else "CLEAR", "detail": f"{summary['external_writable_bind_mounts']} writable bind mounts are outside the current scope."},
        {"key": "filesystem_metadata", "label": "ACLs and extended attributes", "status": "NOT_INCLUDED", "detail": "ACL and extended-attribute capture is not implemented yet."},
    ]
    result["assessment_status"] = "VERIFIED" if inspection_failures == 0 and not result["errors"] else "PARTIALLY VERIFIED"
    result["overall_rating"] = "ATTENTION REQUIRED" if result["warnings"] else "CURRENT SCOPE READY"
    result["guided_actions"] = [
        {
            "id": code.lower(),
            "severity": WARNING_GUIDANCE.get(code, ("REVIEW", ""))[0],
            "title": code.replace("_", " ").title(),
            "affected": count,
            "status": "ACTION_REQUIRED",
            "instruction": WARNING_GUIDANCE.get(
                code,
                ("REVIEW", "Review this finding before recovery."),
            )[1],
            "verification": "Run the Readiness scan again after completing this action.",
        }
        for code, count in sorted(warnings_by_code.items())
    ]
    return result


def apply_verified_snapshot_coverage(report, manifest):
    """Mark runtime findings that are protected by a verified snapshot artifact."""
    updated = _copy_json(report if isinstance(report, dict) else {})
    manifest = manifest if isinstance(manifest, dict) else {}
    recovery = manifest.get("recovery_bundle") or {}
    components = recovery.get("components") or {}
    reconstruction = components.get("reconstruction_evidence") or {}
    database = components.get("database_consistency") or {}
    external = components.get("selected_external_binds") or {}
    metadata = components.get("filesystem_metadata") or {}
    images = components.get("image_recovery_strategy") or {}
    verified = (
        manifest.get("snapshot_status") == "VERIFIED"
        and manifest.get("verification_status") == "VERIFIED"
        and recovery.get("status") == "VERIFIED"
        and reconstruction.get("status") == "VERIFIED"
    )
    updated["verified_snapshot_coverage"] = {
        "status": "VERIFIED" if verified else "NOT INCLUDED",
        "snapshot_id": str(manifest.get("snapshot_id") or "") if verified else "",
        "containers": int(reconstruction.get("container_count", 0) or 0) if verified else 0,
        "networks": int(reconstruction.get("network_count", 0) or 0) if verified else 0,
        "sha256": str(reconstruction.get("sha256") or "") if verified else "",
        "sensitive_values_publicly_exposed": False,
    }
    if not verified:
        return updated
    for check in updated.get("checks") or []:
        if not isinstance(check, dict):
            continue
        if check.get("key") == "container_config":
            check["status"] = "PROTECTED"
            check["detail"] = (
                f"{int(reconstruction.get('container_count', 0) or 0)} private "
                "container configurations are checksummed in recovery point "
                + str(manifest.get("snapshot_id") or "")
                + "."
            )
        elif check.get("key") == "networks":
            check["status"] = "PROTECTED"
            check["detail"] = (
                f"{int(reconstruction.get('network_count', 0) or 0)} Docker network "
                "definitions are checksummed in the current recovery point."
            )
        elif check.get("key") == "databases" and database.get("status") == "VERIFIED":
            check["status"] = "PROTECTED"
            check["detail"] = (
                f"{int(database.get('verified_quiesced_count', 0) or 0)} database "
                "containers were verified cleanly quiesced throughout capture."
            )
        elif check.get("key") == "external_binds" and external.get("status") == "VERIFIED":
            check["status"] = "PROTECTED"
            check["detail"] = (
                f"{int(external.get('path_count', 0) or 0)} explicitly selected external "
                "bind paths are checksummed in the current recovery point."
            )
        elif check.get("key") == "filesystem_metadata" and metadata.get("status") == "VERIFIED":
            check["status"] = "PROTECTED"
            check["detail"] = (
                "Mode, ownership, extended attributes and POSIX ACL xattrs are checksummed."
            )
        elif check.get("key") == "image_reproducibility" and images.get("status") == "RECORDED":
            missing = int(images.get("local_exports_required", 0) or 0)
            check["status"] = "RECORDED" if missing == 0 else "WARNING"
            check["detail"] = (
                f"{int(images.get('registry_digest_images', 0) or 0)} images have registry "
                f"digests; {missing} trusted local image exports remain required."
            )
    protected_action_ids = set()
    if database.get("status") == "VERIFIED":
        protected_action_ids.add("database_consistency")
    if external.get("status") == "VERIFIED":
        protected_action_ids.add("external_writable_bind")
    if images and int(images.get("local_exports_required", 0) or 0) == 0:
        protected_action_ids.update({"image_digest_missing", "mutable_image_reference"})
    for action in updated.get("guided_actions") or []:
        if action.get("id") in protected_action_ids:
            action["status"] = "VERIFIED_IN_CURRENT_SNAPSHOT"
            action["verification"] = (
                "Checksummed evidence is present in the current verified recovery point."
            )
    return updated
