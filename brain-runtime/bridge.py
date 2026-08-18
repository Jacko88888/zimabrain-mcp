import json
import os
import re
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import flask_app

SOURCE_COMMIT = "d1add8738146a04b42e7285965f6811467b88e47"
MAX_BODY_BYTES = 1024 * 1024
ANSWER_LOCK = threading.Lock()


def _bounded_json(value, limit=300000):
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return text if len(text) <= limit else text[:limit] + "\n<truncated>"


def _containers_from(value):
    if isinstance(value, dict):
        for key in ("items", "containers"):
            candidate = value.get(key)
            if isinstance(candidate, list) and candidate and any(
                isinstance(item, dict) and ("name" in item or "container" in item)
                for item in candidate
            ):
                return candidate
        for child in value.values():
            found = _containers_from(child)
            if found:
                return found
    elif isinstance(value, list):
        if value and any(isinstance(item, dict) and ("name" in item or "container" in item) for item in value):
            return value
        for child in value:
            found = _containers_from(child)
            if found:
                return found
    return []


def _disks_from(value):
    if isinstance(value, dict):
        for key in ("disks", "devices", "items"):
            candidate = value.get(key)
            if isinstance(candidate, list) and candidate and any(
                isinstance(item, dict) and ("device" in item or "name" in item)
                for item in candidate
            ):
                return candidate
        for child in value.values():
            found = _disks_from(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _disks_from(child)
            if found:
                return found
    return []


def _legacy_report(payload):
    fallback = payload.get("fallback") if isinstance(payload, dict) else {}
    evidence = fallback.get("evidence") if isinstance(fallback, dict) else {}
    containers = payload.get("containers") if isinstance(payload.get("containers"), list) else _containers_from(evidence)
    disks = payload.get("disks") if isinstance(payload.get("disks"), list) else _disks_from(evidence)

    lines = [
        "===== ZIMABRAIN MCP VERIFIED EVIDENCE =====",
        "Generated: " + datetime.now(timezone.utc).isoformat(),
        "Question intent: " + str(fallback.get("intent") or "unknown"),
        "Verification: " + str(fallback.get("verification") or "NOT VERIFIED"),
        "Verified MCP answer: " + str(fallback.get("answer") or "No bounded evidence answer was produced."),
        "Evidence sources: " + ", ".join(str(item) for item in fallback.get("sources") or []),
        "",
        "===== CONTAINERS =====",
        "Name | Status | Image | Ports",
    ]

    running = 0
    for item in containers[:160]:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("container") or "unknown"
        status = item.get("state") or item.get("status") or "unknown"
        image = item.get("image") or "unknown"
        ports = item.get("ports") or ""
        if str(status).lower().startswith(("up", "running")):
            running += 1
        lines.append(f"{name} | {status} | {image} | {ports}")

    if containers:
        lines.append(f"Containers: {running}/{len(containers)}")

    lines.extend([
        "",
        "===== DISKS / SMART SUMMARY =====",
        "Device | Model | Size | Mount | Health | Temp | Realloc | Pending | CRC | Power On",
    ])
    for item in disks[:80]:
        if not isinstance(item, dict):
            continue
        lines.append(" | ".join(str(item.get(key) or "N/A") for key in (
            "device", "model", "size", "mount", "status", "temperature",
            "reallocatedSectors", "pendingSectors", "crcErrors", "powerOnHours",
        )))

    lines.extend([
        "",
        "===== RAW DASHBOARD ALERTS =====",
        ("OK: " if fallback.get("verification") == "VERIFIED" else "WARN: ")
        + str(fallback.get("answer") or "Evidence is incomplete."),
        "",
        "===== STRUCTURED MCP EVIDENCE =====",
        _bounded_json(evidence),
    ])
    return "\n".join(lines)


def _same_report_evidence(payload):
    fallback = payload.get("fallback") if isinstance(payload, dict) else {}
    evidence = fallback.get("evidence") if isinstance(fallback, dict) else {}
    compact = _bounded_json(evidence)
    containers = payload.get("containers") if isinstance(payload.get("containers"), list) else _containers_from(evidence)
    disks = payload.get("disks") if isinstance(payload.get("disks"), list) else _disks_from(evidence)

    docker_ps = []
    docker_states = []
    for item in containers[:160]:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("container") or "unknown"
        image = item.get("image") or "unknown"
        status = item.get("state") or item.get("status") or "unknown"
        ports = item.get("ports") or ""
        docker_ps.append(f"{name}|{image}|{status}|{ports}")
        docker_states.append(f"{name}|{image}|{status}|{item.get('health') or 'none'}|{item.get('restartCount') or 0}")

    disk_lines = []
    for item in disks[:80]:
        if isinstance(item, dict):
            disk_lines.append(_bounded_json(item, 4000))

    unavailable = "Not collected through the legacy host-command path; use STRUCTURED_MCP_EVIDENCE."
    return {
        "boot_id": unavailable,
        "failed_units": str(evidence.get("failedServices") or evidence.get("failed_units") or ""),
        "active_services": unavailable,
        "service_hotlist": unavailable,
        "tailscale": unavailable,
        "process_top": str(evidence.get("processes") or ""),
        "io_top": str(evidence.get("activity") or evidence.get("dockerStats") or ""),
        "iostat_brief": unavailable,
        "lsblk": "\n".join(disk_lines),
        "disk_identity": "\n".join(disk_lines),
        "mounts": str(evidence.get("mounts") or evidence.get("storage") or ""),
        "media_paths": unavailable,
        "path_state": unavailable,
        "docker_ps": "\n".join(docker_ps),
        "docker_states": "\n".join(docker_states),
        "docker_access": compact,
        "docker_security": str(evidence.get("scan") or evidence.get("security") or ""),
        "nvidia": unavailable,
        "smart": str(evidence.get("smart") or "\n".join(disk_lines)),
        "nvme_smart": str(evidence.get("nvme") or "\n".join(disk_lines)),
        "port_reachability": str(evidence.get("scan") or ""),
        "zfw_status": str(evidence.get("firewall") or ""),
        "zfw_files": unavailable,
        "zfw_chains": str(evidence.get("firewall") or ""),
        "auditd": unavailable,
        "self_docker_security": unavailable,
        "ip_addr": str(evidence.get("interfaces") or ""),
        "ip_route": str(evidence.get("routes") or ""),
        "resolv": str(evidence.get("dns") or ""),
        "host_os": str(evidence.get("system") or ""),
        "kernel": str(evidence.get("system") or ""),
        "uptime": str(evidence.get("system") or ""),
        "cpu_info": str(evidence.get("system") or ""),
        "cpu_usage": str(evidence.get("system") or ""),
        "memory": str(evidence.get("system") or ""),
        "loadavg": str(evidence.get("system") or ""),
        "thermal_zones": str(evidence.get("sensors") or ""),
        "sensors": str(evidence.get("sensors") or ""),
        "rauc": str(evidence.get("rauc") or ""),
        "cmdline": unavailable,
        "host_date": datetime.now(timezone.utc).isoformat(),
        "mcp_verification": str(fallback.get("verification") or "NOT VERIFIED"),
        "mcp_answer": str(fallback.get("answer") or ""),
        "mcp_sources": ", ".join(str(item) for item in fallback.get("sources") or []),
        "structured_mcp_evidence": compact,
        "failed_unit_details": [],
        "failed_unit_details_collected": False,
        "bind_mount_permissions": {},
    }


def _verification_from_answer(answer):
    match = re.search(r"@@VERIFY:(VERIFIED|PARTIALLY VERIFIED|NOT VERIFIED)@@", answer or "", re.I)
    return match.group(1).upper() if match else None


def answer(payload):
    question = " ".join(str(payload.get("question") or "").split())
    if len(question) < 3 or len(question) > 500:
        raise ValueError("Question must contain between 3 and 500 characters")

    evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
    report = _legacy_report(evidence)
    same_report = _same_report_evidence(evidence)

    with ANSWER_LOCK:
        flask_app.DASHBOARD_REPORT = report
        flask_app.DASHBOARD_STATUS = "Current evidence supplied by the read-only ZimaBrain MCP collectors."
        flask_app.DASHBOARD_BUNDLE_CACHE = None
        flask_app.DASHBOARD_BUNDLE_CACHE_AT = 0.0
        flask_app.collect_same_report_evidence = lambda: same_report
        brain_answer = flask_app.answer_question(question)

    text = str(brain_answer or "").strip()
    verification = _verification_from_answer(text)
    text = re.sub(r"@@VERIFY:(?:VERIFIED|PARTIALLY VERIFIED|NOT VERIFIED)@@\s*", "", text, flags=re.I)
    return {
        "status": "ok",
        "engine": "full-zimabrain",
        "sourceRepository": "Jacko88888/zimabrain-snapshot-lab",
        "sourceCommit": SOURCE_COMMIT,
        "verification": verification,
        "answer": text,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "ZimaBrainBridge/1.0"

    def _json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {
                "status": "ok",
                "engine": "full-zimabrain",
                "sourceCommit": SOURCE_COMMIT,
            })
        else:
            self._json(404, {"status": "error", "error": "Not found"})

    def do_POST(self):
        if self.path != "/answer":
            self._json(404, {"status": "error", "error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
            if length < 2 or length > MAX_BODY_BYTES:
                raise ValueError("Invalid request size")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            self._json(200, answer(payload))
        except ValueError as error:
            self._json(400, {"status": "error", "error": str(error)})
        except Exception as error:
            self._json(503, {"status": "error", "error": str(error)[:500]})

    def log_message(self, format, *args):
        print("%s - %s" % (self.address_string(), format % args), flush=True)


if __name__ == "__main__":
    host = os.environ.get("ZIMABRAIN_BRIDGE_HOST", "0.0.0.0")
    port = int(os.environ.get("ZIMABRAIN_BRIDGE_PORT", "8601"))
    print(f"Full ZimaBrain bridge listening on {host}:{port} commit={SOURCE_COMMIT}", flush=True)
    ThreadingHTTPServer((host, port), Handler).serve_forever()
