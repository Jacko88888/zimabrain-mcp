import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
SOURCE = ROOT / "source"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SOURCE))

import bridge  # noqa: E402
from brain.layers import containers as containers_layer  # noqa: E402


class StructuredEvidenceBridgeTests(unittest.TestCase):
    def test_clear_failed_service_evidence_stays_clear(self):
        payload = {
            "fallback": {
                "evidence": {
                    "failedServices": {
                        "collectorStatus": "success",
                        "verified": True,
                        "state": "clear",
                        "observedFailedServices": 0,
                        "services": [],
                        "note": "The host systemd manager reported no failed units.",
                    }
                }
            }
        }

        same_report = bridge._same_report_evidence(payload)
        self.assertEqual(same_report["failed_units"], "")

    def test_uncollected_legacy_fields_do_not_become_findings(self):
        same_report = bridge._same_report_evidence({"fallback": {"evidence": {}}})

        self.assertEqual(same_report["media_paths"], "")
        self.assertEqual(same_report["service_hotlist"], "")
        self.assertEqual(same_report["auditd"], "")
        self.assertNotIn("Not collected", "\n".join(str(value) for value in same_report.values()))

    def test_structured_failed_service_is_rendered_for_legacy_verifier(self):
        payload = {
            "fallback": {
                "evidence": {
                    "failedServices": {
                        "collectorStatus": "success",
                        "verified": True,
                        "state": "attention",
                        "observedFailedServices": 1,
                        "services": [
                            {"name": "example.service", "state": "failed"}
                        ],
                    }
                }
            }
        }

        same_report = bridge._same_report_evidence(payload)
        self.assertEqual(same_report["failed_units"], "example.service failed")

    def test_clear_payload_creates_no_legacy_media_or_failed_unit_findings(self):
        payload = {
            "fallback": {
                "evidence": {
                    "failedServices": {
                        "state": "clear",
                        "observedFailedServices": 0,
                        "services": [],
                    }
                }
            }
        }

        same_report = bridge._same_report_evidence(payload)
        findings = bridge.flask_app.evaluate_critical_same_report(same_report)
        titles = {item.get("title") for item in findings}

        self.assertNotIn("ZimaOS media mirror path missing", titles)
        self.assertNotIn(
            "Failed systemd unit detected; detailed correlation unavailable",
            titles,
        )

    def test_global_attention_question_does_not_invent_legacy_findings(self):
        result = bridge.answer({
            "question": "What needs attention?",
            "evidence": {
                "fallback": {
                    "intent": "comprehensive_health",
                    "verification": "VERIFIED",
                    "answer": (
                        "1 evidence-backed attention signal(s) were observed: "
                        "ZFW has saved rules but is not applied; external "
                        "reachability remains unverified."
                    ),
                    "sources": [
                        "docker_health",
                        "zima_failed_services",
                        "dashboard_evidence",
                    ],
                    "evidence": {
                        "failedServices": {
                            "collectorStatus": "success",
                            "verified": True,
                            "state": "clear",
                            "observedFailedServices": 0,
                            "services": [],
                        },
                        "firewall": {"state": "configured_not_applied"},
                    },
                }
            },
        })

        self.assertNotIn("ZimaOS media mirror path missing", result["answer"])
        self.assertNotIn("Failed systemd unit detected", result["answer"])
        self.assertIn("Comprehensive System Health Layer", result["answer"])

    def test_system_metrics_are_rendered_for_host_layer(self):
        same_report = bridge._same_report_evidence({
            "fallback": {
                "evidence": {
                    "system": {
                        "cpuModel": "Example CPU",
                        "cpuCount": 4,
                        "cpuUsagePercent": 22.5,
                        "totalMemoryBytes": 8 * 1024 * 1024 * 1024,
                        "availableMemoryBytes": 5 * 1024 * 1024 * 1024,
                        "usedMemoryBytes": 3 * 1024 * 1024 * 1024,
                        "swapTotalBytes": 1024 * 1024 * 1024,
                        "swapUsedBytes": 256 * 1024 * 1024,
                        "loadAverage": [0.1, 0.2, 0.3],
                        "uptimeSeconds": 3600,
                        "timezone": "Europe/Berlin",
                    }
                }
            }
        })

        self.assertIn("CPU_USAGE_PERCENT=22.5", same_report["cpu_usage"])
        self.assertIn("Mem:", same_report["memory"])
        self.assertEqual(same_report["uptime"], "3600")
        self.assertEqual(same_report["timezone"], "Europe/Berlin")

    def test_container_security_rows_are_not_invented_when_missing(self):
        same_report = bridge._same_report_evidence({
            "fallback": {"evidence": {"security": {"items": []}}}
        })
        self.assertEqual(same_report["docker_security"], "")

    def test_container_security_rows_render_inspected_settings(self):
        same_report = bridge._same_report_evidence({
            "fallback": {
                "evidence": {
                    "security": {
                        "items": [{
                            "name": "socket-reader",
                            "privileged": False,
                            "dockerSocket": True,
                            "hostPid": False,
                            "hostNetwork": True,
                        }]
                    }
                }
            }
        })
        self.assertIn("socket-reader", same_report["docker_security"])
        self.assertIn("DockerSock=/var/run/docker.sock", same_report["docker_security"])
        self.assertIn("NetworkMode=host", same_report["docker_security"])

    def test_container_layer_marks_missing_inspection_not_verified(self):
        result = containers_layer.answer(
            {"same_report_evidence": {"docker_security": ""}},
            "Which containers have elevated privileges or Docker socket access?",
        )
        self.assertEqual(result["trust_state"], "NOT VERIFIED")
        self.assertIn("evidence absence", "\n".join(result["lines"]))


if __name__ == "__main__":
    unittest.main()
