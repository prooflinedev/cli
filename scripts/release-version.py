"""Admit a release only at its package version and a commit on main."""
import os
from pathlib import Path
import re
import subprocess
import tomllib

version = tomllib.loads(Path("Cargo.toml").read_text())["package"]["version"]
if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
    raise SystemExit("package version must be x.y.z")
ref = os.environ["GITHUB_REF"]
if ref not in ("refs/heads/main", f"refs/tags/v{version}"):
    raise SystemExit("release requires main or a tag equal to the package version")
subprocess.run(["git", "fetch", "--quiet", "origin", "main"], check=True)
subprocess.run(["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"], check=True)
with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
    output.write(f"version={version}\n")
print(f"Release version: {version}")
