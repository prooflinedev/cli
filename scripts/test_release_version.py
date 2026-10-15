"""Release admission binds a version to the ref and main's ancestry."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/release-version.py"


class ReleaseAdmission(unittest.TestCase):
    def test_ref_version_and_main_ancestry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def git(*arguments: str) -> None:
                subprocess.run(["git", *arguments], cwd=root, check=True, capture_output=True)
            git("init", "--quiet", "-b", "main")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.com")
            git("remote", "add", "origin", str(root))
            (root / 'Cargo.toml').write_text('[package]\nversion = "1.2.3"\n')
            (root / "openapi.public.json").write_text(json.dumps({"info": {"version": "1.2.3"}}))
            git("add", ".")
            git("commit", "--quiet", "-m", "fixture")
            for ref, admitted in (("refs/heads/main", True), ("refs/tags/v1.2.3", True),
                                  ("refs/tags/v9.9.9", False), ("refs/heads/feature", False)):
                with self.subTest(ref=ref):
                    output = root / "output"
                    output.unlink(missing_ok=True)
                    result = subprocess.run([sys.executable, str(SCRIPT)], cwd=root,
                        env={**os.environ, "GITHUB_REF": ref, "GITHUB_OUTPUT": str(output)},
                        capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, admitted, result.stderr)
                    if admitted:
                        self.assertEqual(output.read_text(), "version=1.2.3\n")
                    else:
                        self.assertFalse(output.exists())
            git("checkout", "--quiet", "-b", "feature")
            (root / "change").write_text("unmerged")
            git("add", ".")
            git("commit", "--quiet", "-m", "unmerged")
            result = subprocess.run([sys.executable, str(SCRIPT)], cwd=root,
                env={**os.environ, "GITHUB_REF": "refs/tags/v1.2.3", "GITHUB_OUTPUT": str(root / "rejected")},
                capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "rejected").exists())


if __name__ == "__main__":
    unittest.main()
