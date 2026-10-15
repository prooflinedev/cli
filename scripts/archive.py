"""Package one checked CLI binary with deterministic archive metadata."""
import gzip
import io
from pathlib import Path
import sys
import tarfile

target = sys.argv[1]
source = Path("target") / target / "release/proofline"
data = source.read_bytes()
Path("artifacts").mkdir(exist_ok=True)
with Path(f"artifacts/proofline-{target}.tar.gz").open("wb") as output:
    with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            entry = tarfile.TarInfo("proofline")
            entry.size = len(data)
            entry.mode = 0o755
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(data))
