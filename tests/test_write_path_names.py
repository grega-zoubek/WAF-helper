import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "control-api"))

from app.signature_workflow import OBJECT_NAME_RE, default_object_name  # noqa: E402
from app.protection_lifecycle import _safe_object_name  # noqa: E402


class ObjectNameTests(unittest.TestCase):
    def test_injection_shaped_names_are_rejected(self):
        for bad in ("waf-x -overwrite", "-force", "waf-a b", "waf-x;rm", "waf-a#b", "other-name"):
            self.assertIsNone(OBJECT_NAME_RE.fullmatch(bad), bad)

    def test_generated_names_pass(self):
        name = default_object_name("www.ess.gov.si", "bdac3c4c-32c9")
        self.assertTrue(OBJECT_NAME_RE.fullmatch(name), name)
        self.assertTrue(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,30}", _safe_object_name("waf app one", "blk")))


if __name__ == "__main__":
    unittest.main()
