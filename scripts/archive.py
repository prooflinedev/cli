"""Package one checked CLI binary with deterministic archive metadata."""
import gzip
import io
from pathlib import Path
import sys
import tarfile

target = sys.argv[1]
binary = "proofline.exe" if "windows" in target else "proofline"
source = Path("target") / target / "release" / binary
data = source.read_bytes()
Path("artifacts").mkdir(exist_ok=True)
with Path(f"artifacts/proofline-{target}.tar.gz").open("wb") as output:
    with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            entry = tarfile.TarInfo(binary)
            entry.size = len(data)
            entry.mode = 0o755
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(data))
