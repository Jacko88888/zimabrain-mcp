import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
SOURCE = ROOT / "source"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SOURCE))

import bridge  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
