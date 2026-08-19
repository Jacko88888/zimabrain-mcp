import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parent


class InstallerReferenceTests(unittest.TestCase):
    def test_installer_supports_branch_and_exact_commit_archives(self):
        installer = (ROOT / "install-zimaos.sh").read_text(encoding="utf-8")

        self.assertIn('if [ "${#RELEASE_REF}" -eq 40 ]', installer)
        self.assertIn('${REPOSITORY_URL}/archive/${RELEASE_REF}.tar.gz', installer)
        self.assertIn('${REPOSITORY_URL}/archive/refs/heads/${RELEASE_REF}.tar.gz', installer)

    def test_installer_detects_timezone_and_writes_compose_environment(self):
        installer = (ROOT / "install-zimaos.sh").read_text(encoding="utf-8")

        self.assertIn("/etc/timezone", installer)
        self.assertIn("/etc/localtime", installer)
        self.assertIn("printf 'TZ=%s\\n'", installer)
        self.assertIn('echo "Detected timezone: ${HOST_TIMEZONE}"', installer)


if __name__ == "__main__":
    unittest.main()
