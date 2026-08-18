import pathlib
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent


class NetworkBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.network = yaml.safe_load((ROOT / "docker-compose.network.yml").read_text(encoding="utf-8"))

    def test_collector_has_no_tcp_port_and_uses_fixed_unix_socket(self):
        collector = self.network["services"]["zimabrain-network-collector"]
        self.assertNotIn("ports", collector)
        self.assertEqual(collector["network_mode"], "host")
        self.assertEqual(collector["environment"]["NETWORK_COLLECTOR_SOCKET"], "/run/zimabrain-network/collector.sock")
        server = self.network["services"]["zimabrain-mcp-server"]
        self.assertTrue(server["volumes"][0]["read_only"])

    def test_collector_is_read_only_and_has_only_network_read_capabilities(self):
        collector = self.network["services"]["zimabrain-network-collector"]
        self.assertTrue(collector["read_only"])
        self.assertEqual(collector["cap_drop"], ["ALL"])
        self.assertEqual(set(collector["cap_add"]), {"NET_ADMIN", "NET_RAW"})
        self.assertEqual(collector["security_opt"], ["no-new-privileges:true"])
        self.assertNotIn("privileged", collector)

    def test_host_configuration_mounts_are_read_only(self):
        collector = self.network["services"]["zimabrain-network-collector"]
        mounts = [str(item) for item in collector["volumes"]]
        self.assertIn("/etc/resolv.conf:/host/etc/resolv.conf:ro", mounts)
        self.assertIn("/var/lib/casaos_data/zfw/rules.json:/host/zfw/rules.json:ro", mounts)
        self.assertIn("/proc:/host/proc:ro", mounts)

    def test_collector_has_no_shell_execution_or_user_supplied_command(self):
        collector = (ROOT / "network-collector/src/collector.js").read_text(encoding="utf-8")
        self.assertIn("execFile", collector)
        self.assertNotIn("exec(", collector)
        self.assertNotIn("shell:", collector)
        self.assertIn('new Set(["github.com", "zimaspace.com", "cloudflare.com"])', collector)


if __name__ == "__main__":
    unittest.main()
