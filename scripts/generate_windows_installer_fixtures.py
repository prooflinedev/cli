"""Generate offline release fixtures for PowerShell validator tests.

Fixtures intentionally contain a fake PE header and MUST NOT be executed.
"""

import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile


def pack(*members: tuple[str, bytes, bytes]) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, data, kind in members:
                header = tarfile.TarInfo(name)
                header.type = kind
                header.size = len(data) if kind == tarfile.REGTYPE else 0
                header.mtime = 0
                tar.addfile(header, io.BytesIO(data))
    return output.getvalue()


def pe_fixture() -> bytes:
    image = bytearray(1024)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    return bytes(image)


def main(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    binary = pe_fixture()
    base = pack(("proofline.exe", binary, tarfile.REGTYPE))
    (destination / "valid.tar.gz").write_bytes(base)
    upgraded_binary = bytearray(binary)
    upgraded_binary[512] = 0x42  # different digest, same fake PE header
    upgraded = pack(("proofline.exe", bytes(upgraded_binary), tarfile.REGTYPE))
    (destination / "upgrade.tar.gz").write_bytes(upgraded)
    (destination / "SHA256SUMS-upgrade").write_text(
        f"{hashlib.sha256(upgraded).hexdigest()}  proofline-x86_64-pc-windows-msvc.tar.gz\n",
        encoding="ascii",
    )
    (destination / "bad-digest.tar.gz").write_bytes(base + b"tampered")
    (destination / "traversal.tar.gz").write_bytes(
        pack(("../proofline.exe", binary, tarfile.REGTYPE))
    )
    (destination / "unexpected-member.tar.gz").write_bytes(
        pack(("proofline.exe", binary, tarfile.REGTYPE), ("extra.txt", b"evil", tarfile.REGTYPE))
    )
    (destination / "symlink.tar.gz").write_bytes(
        pack(("proofline.exe", b"", tarfile.SYMTYPE))
    )
    (destination / "not-pe.tar.gz").write_bytes(
        pack(("proofline.exe", b"not a PE" * 128, tarfile.REGTYPE))
    )
    name = "proofline-x86_64-pc-windows-msvc.tar.gz"
    sha = hashlib.sha256(base).hexdigest()
    other = hashlib.sha256(b"other archive bytes").hexdigest()
    (destination / "SHA256SUMS").write_text(
        f"{sha}  {name}\n{other}  proofline-x86_64-unknown-linux-musl.tar.gz\n",
        encoding="ascii",
    )
    (destination / "SHA256SUMS-mismatch").write_text(
        f"{'0'*64}  {name}\n", encoding="ascii"
    )
    (destination / "SHA256SUMS-duplicate").write_text(
        f"{sha}  {name}\n{sha}  {name}\n", encoding="ascii"
    )
    (destination / "SHA256SUMS-missing").write_text(
        f"{other}  proofline-x86_64-unknown-linux-musl.tar.gz\n", encoding="ascii"
    )
    (destination / "SHA256SUMS-malformed").write_text(
        f"not-a-hash  {name}\n", encoding="ascii"
    )
    # The release's archive format is deterministic; assert our fixture name,
    # tar type and content are correct before it reaches PowerShell tests.
    with tarfile.open(fileobj=io.BytesIO(base), mode="r:gz") as tar:
        names = tar.getnames()
        assert names == ["proofline.exe"], names
        assert tar.extractfile(tar.getmembers()[0]).read() == binary
    print(f"Created offline fixture files in {destination}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate_windows_installer_fixtures.py DIRECTORY")
    main(Path(sys.argv[1]))
