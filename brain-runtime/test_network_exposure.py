import json
import pathlib
import sys
import unittest


SOURCE = pathlib.Path(__file__).resolve().parent / "source"
sys.path.insert(0, str(SOURCE))

from brain.layers import network_exposure  # noqa: E402


def bundle(firewall_state="service_only"):
    evidence = {
        "scan": {
            "externalReachabilityMeasured": False,
            "findings": [
                {"code": "external_reachability_unverified", "severity": "unknown", "verified": False}
            ],
        },
        "ports": {
            "listeners": [
                {
                    "port": 8621,
                    "protocol": "tcp",
                    "process": "docker-proxy",
                    "address": "0.0.0.0",
                    "scope": "all_interfaces",
                },
                {
                    "port": 8790,
                    "protocol": "tcp",
                    "process": "docker-proxy",
                    "address": "127.0.0.1",
                    "scope": "localhost",
                },
            ],
        },
        "firewall": {
            "state": firewall_state,
            "serviceRunning": True,
            "active": firewall_state == "active",
            "savedRules": 0,
        },
        "containers": [
            {
                "name": "zimabrain-mcp-ui",
                "ports": [
                    {"private": 3000, "public": 8621, "type": "tcp", "ip": "0.0.0.0"}
                ],
            },
            {"name": "tailscale", "ports": []},
        ],
        "applications": {
            "items": [
                {
                    "containers": [
                        {
                            "name": "zimabrain-mcp-ui",
                            "mounts": [
                                {
                                    "source": "/DATA/AppData/zimabrain-mcp",
                                    "destination": "/app",
                                    "readWrite": True,
                                }
                            ],
                        }
                    ]
                }
            ]
        },
        "interfaces": {"interfaces": [{"name": "eth0"}]},
    }
    return {
        "same_report_evidence": {
            "structured_mcp_evidence": json.dumps(evidence),
            "port_reachability": "",
        }
    }


class StructuredNetworkExposureTests(unittest.TestCase):
    def test_service_only_is_not_rendered_as_active_firewall(self):
        answer = network_exposure.answer(bundle())
        text = "\n".join(answer["lines"])

        self.assertIn("Potentially LAN-accessible socket rows: 1", text)
        self.assertIn("no LAN connection probe was collected", text)
        self.assertIn("Collector state: `service_only`", text)
        self.assertIn("service is running, but no active ZFW hooks", text)
        self.assertNotIn("LAN reachable:", text)
        self.assertNotIn("installed/active", text)
        self.assertEqual(answer["trust_state"], "PARTIALLY VERIFIED")
        self.assertIn("LAN connection and internet reachability were not measured", answer["trust_detail"])

    def test_published_ports_and_tunnels_are_rendered_from_structured_evidence(self):
        answer = network_exposure.answer(bundle())
        text = "\n".join(answer["lines"])

        self.assertIn("Published bindings observed: 1", text)
        self.assertIn("0.0.0.0:8621 -> 3000/tcp", text)
        self.assertIn("Published containers with writable `/DATA` mounts: zimabrain-mcp-ui", text)
        self.assertIn("tailscale", text)
        self.assertNotIn("No published Docker ports were parsed", text)
        self.assertNotIn("No top exposure risk was detected", text)

    def test_active_firewall_requires_active_collector_state(self):
        answer = network_exposure.answer(bundle("active"))
        text = "\n".join(answer["lines"])

        self.assertIn("Active ZFW hooks were verified", text)


if __name__ == "__main__":
    unittest.main()
