import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parent


class UiPortabilityTests(unittest.TestCase):
    def test_ui_has_no_george_or_sydney_identity_defaults(self):
        index = (ROOT / "ui/runtime/public/index.html").read_text(encoding="utf-8")
        app = (ROOT / "ui/runtime/public/app.js").read_text(encoding="utf-8")
        compose = (ROOT / "compose.portable.yaml").read_text(encoding="utf-8")

        self.assertNotIn("Australia/Sydney", index + app + compose)
        self.assertNotIn('class="avatar">GH', index)
        self.assertIn("data.system?.hostname", app)
        self.assertIn("data.system?.timezone", app)
        self.assertIn('${TZ:-UTC}', compose)
