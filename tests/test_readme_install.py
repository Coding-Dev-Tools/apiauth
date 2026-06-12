"""Guards README install instructions stay honest & working.

apiauth is NOT on public PyPI (web-verified 2026-06-12: no `apiauth` project on
PyPI.org); it is served only from the project's self-hosted index
(pypi-index/simple/apiauth/). A bare `pip install apiauth` therefore fails for
every reader. This test pins the README to the two install paths that actually
resolve and forbids the broken bare command + bogus PyPI badge from returning.
Regression for finding marketing-bare-pip-install-broken-multisurface.
"""
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
README = os.path.join(HERE, os.pardir, "README.md")
INDEX_URL = "https://coding-dev-tools.github.io/pypi-index/simple/"


class ReadmeInstallHonesty(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(README, encoding="utf-8") as fh:
            cls.text = fh.read()
        cls.lines = cls.text.splitlines()

    def test_no_bare_pip_install(self):
        # No line is exactly `pip install apiauth` (the command that 404s)
        for ln in self.lines:
            self.assertNotEqual(
                ln.strip(), "pip install apiauth",
                "Bare `pip install apiauth` is back — fails (not on public PyPI).",
            )

    def test_no_public_pypi_badge(self):
        self.assertNotIn("pypi.org/project/apiauth", self.text)
        self.assertNotIn("img.shields.io/pypi/v/apiauth", self.text)

    def test_has_index_url_path(self):
        self.assertIn(
            "pip install --index-url %s apiauth" % INDEX_URL, self.text,
            "Canonical self-hosted-index install path missing.",
        )

    def test_has_git_fallback(self):
        self.assertIn(
            "pip install git+https://github.com/Coding-Dev-Tools/apiauth.git",
            self.text,
        )

    def test_index_actually_serves_apiauth(self):
        # The path we advertise must resolve to a real artifact in the index.
        idx = os.path.join(
            HERE, os.pardir, os.pardir, "pypi-index", "simple", "apiauth", "index.html"
        )
        if not os.path.exists(idx):
            self.skipTest("pypi-index not present in this checkout")
        with open(idx, encoding="utf-8") as fh:
            html = fh.read()
        self.assertTrue(
            re.search(r"apiauth-[\d.]+(-py3-none-any\.whl|\.tar\.gz)", html),
            "Index advertised in README serves no apiauth artifact.",
        )


if __name__ == "__main__":
    unittest.main()
