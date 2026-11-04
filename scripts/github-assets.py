"""Reserve the version on GitHub and verify or upload each checked release asset."""

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def gh(*args):
    return subprocess.check_output(["gh", *args, "--repo", os.environ["GITHUB_REPOSITORY"]], text=True)


def stage(version, directory):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("invalid CLI version")
    tag = f"v{version}"
    commit = os.environ["GITHUB_SHA"]
    # Create first so a concurrent publisher cannot claim the same version.
    # A failed create can also mean this run already reserved the release.
    subprocess.run(
        ["gh", "release", "create", tag, "--repo", os.environ["GITHUB_REPOSITORY"],
         "--target", commit, "--draft", "--title", f"Proofline {version}", "--notes", f"Proofline CLI {version}."],
        check=False, capture_output=True,
    )

    def read():
        release = json.loads(gh("release", "view", tag, "--json", "targetCommitish,assets,isDraft"))
        if release["targetCommitish"] != commit:
            raise ValueError("GitHub release belongs to a different commit")
        return release

    release = read()
    existing = {asset["name"]: asset["digest"] for asset in release["assets"]}
    expected = {
        path.name: "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        for path in directory.iterdir()
    }
    if any(expected.get(name) != digest for name, digest in existing.items()):
        raise ValueError("GitHub release has an unexpected asset")
    for name in sorted(expected.keys() - existing.keys()):
        if not release["isDraft"]:
            raise ValueError("published GitHub release is missing an asset")
        gh("release", "upload", tag, str(directory / name))
    if {asset["name"]: asset["digest"] for asset in read()["assets"]} != expected:
        raise ValueError("GitHub release asset verification failed")


if __name__ == "__main__":
    stage(sys.argv[1], Path(sys.argv[2]))
