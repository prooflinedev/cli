#!/usr/bin/env python3
"""Verify real curl S3 signatures and release ordering against local HTTPS."""
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parent.parent
ACCOUNT = "a" * 32
HOST = f"{ACCOUNT}.r2.cloudflarestorage.com"
ACCESS = "b" * 32
SECRET = "c" * 64
TARGETS = sorted([
    "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin", "aarch64-apple-darwin",
])


class PublishTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temp.name)
        cert = cls.base / "cert.pem"
        key = cls.base / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST},DNS:proofline.sh",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                code = cls.probe_status if self.path.endswith("SHA256SUMS") else 200
                body = cls.latest.encode() if self.path == "/cli/latest" else b""
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_PUT(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                cls.requests.append((self.path, dict(self.headers), body))
                status = 403 if self.path == cls.reject else 200
                if self.headers.get("If-None-Match") == "*" and self.path in cls.objects:
                    status = 412
                if status == 200:
                    cls.objects.add(self.path)
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.fakebin = cls.base / "bin"
        cls.fakebin.mkdir()
        curl = shutil.which("curl")
        if not curl:
            raise RuntimeError("curl is required")
        wrapper = cls.fakebin / "curl"
        destination = f"{HOST}:443:127.0.0.1:{cls.server.server_port}"
        wrapper.write_text(
            f"#!/bin/sh\nexec {shlex.quote(curl)} --noproxy '*' "
            f"--connect-to {shlex.quote(destination)} --connect-to proofline.sh:443:127.0.0.1:{cls.server.server_port} --cacert {shlex.quote(str(cert))} \"$@\"\n"
        )
        wrapper.chmod(0o755)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def setUp(self):
        type(self).requests = []
        type(self).reject = None
        type(self).objects = set()
        type(self).probe_status = 404
        type(self).latest = "0.0.9"
        self.dist = self.base / self._testMethodName
        self.dist.mkdir()
        self.env = os.environ.copy()
        self.env.update({
            "PATH": str(self.fakebin) + os.pathsep + self.env["PATH"],
            "GITHUB_SHA": "d" * 40,
            "CLOUDFLARE_ACCOUNT_ID": ACCOUNT,
            "CLI_RELEASE_R2_CREDENTIALS": json.dumps({
                "access_key_id": ACCESS, "secret_access_key": SECRET,
            }),
        })
        manifest = []
        for target in TARGETS:
            name = f"proofline-{target}.tar.gz"
            body = f"archive for {target}\n".encode()
            (self.dist / name).write_bytes(body)
            manifest.append(f"{hashlib.sha256(body).hexdigest()}  {name}\n")
        (self.dist / "SHA256SUMS").write_text("".join(manifest))

    def run_publish(self, version="0.1.0"):
        result = subprocess.run([
            str(ROOT / "scripts/publish-r2.sh"), version, str(self.dist),
        ], env=self.env, capture_output=True, text=True, timeout=30)
        self.assertNotIn(ACCESS, result.stdout + result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        return result

    def test_signed_uploads_and_latest_last(self):
        result = self.run_publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        prefix = "/proofline-cli-releases/"
        expected = ["0.1.0/RELEASE.json"] + [f"0.1.0/proofline-{target}.tar.gz" for target in TARGETS]
        expected += ["0.1.0/SHA256SUMS", "latest"]
        self.assertEqual([path for path, _, _ in self.requests], [prefix + key for key in expected])
        for path, original_headers, body in self.requests:
            headers = {name.lower(): value for name, value in original_headers.items()}
            payload = hashlib.sha256(body).hexdigest()
            self.assertEqual(headers["x-amz-content-sha256"], payload)
            match = re.fullmatch(
                r"AWS4-HMAC-SHA256 Credential=([^/]+)/([0-9]+)/auto/s3/aws4_request, "
                r"SignedHeaders=([^,]+), Signature=([0-9a-f]{64})", headers["authorization"],
            )
            self.assertIsNotNone(match, headers["authorization"])
            access, date, signed_headers, signature = match.groups()
            self.assertEqual(access, ACCESS)
            canonical_headers = "".join(f"{name}:{headers[name].strip()}\n" for name in signed_headers.split(";"))
            canonical = f"PUT\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload}"
            scope = f"{date}/auto/s3/aws4_request"
            to_sign = f"AWS4-HMAC-SHA256\n{headers['x-amz-date']}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
            signing_key = ("AWS4" + SECRET).encode()
            for part in [date, "auto", "s3", "aws4_request"]:
                signing_key = hmac.new(signing_key, part.encode(), hashlib.sha256).digest()
            self.assertEqual(signature, hmac.new(signing_key, to_sign.encode(), hashlib.sha256).hexdigest())
            self.assertEqual(headers["host"], HOST)
            self.assertEqual(headers["cache-control"], "public, max-age=60" if path.endswith("/latest") else "public, max-age=31536000, immutable")
        self.assertEqual(self.requests[-1][2], b"0.1.0\n")

    def test_upload_refusal_keeps_latest_absent(self):
        type(self).reject = f"/proofline-cli-releases/0.1.0/proofline-{TARGETS[1]}.tar.gz"
        self.assertNotEqual(self.run_publish().returncode, 0)
        self.assertEqual(len(self.requests), 3)
        self.assertFalse(any(path.endswith("/latest") for path, _, _ in self.requests))

    def test_checksum_mismatch_writes_nothing(self):
        (self.dist / f"proofline-{TARGETS[-1]}.tar.gz").write_bytes(b"damaged")
        self.assertNotEqual(self.run_publish().returncode, 0)
        self.assertEqual(self.requests, [])

    def test_missing_archive_writes_nothing(self):
        (self.dist / f"proofline-{TARGETS[-1]}.tar.gz").unlink()
        self.assertNotEqual(self.run_publish().returncode, 0)
        self.assertEqual(self.requests, [])

    def test_existing_or_unavailable_release_and_version_regression_refuse(self):
        for status, latest in [(200, "0.0.9"), (503, "0.0.9"), (404, "1.10.0"), (404, "0.1.0")]:
            with self.subTest(status=status, latest=latest):
                type(self).probe_status = status
                type(self).latest = latest
                self.assertNotEqual(self.run_publish().returncode, 0)
                self.assertEqual(self.requests, [])

    def test_reserved_version_cannot_overwrite_partial_release(self):
        type(self).objects.add("/proofline-cli-releases/0.1.0/RELEASE.json")
        self.assertNotEqual(self.run_publish().returncode, 0)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0][1]["If-None-Match"], "*")

    def test_invalid_credentials_and_version_write_nothing(self):
        self.env["CLI_RELEASE_R2_CREDENTIALS"] = json.dumps({"access_key_id": "invalid", "secret_access_key": SECRET})
        self.assertNotEqual(self.run_publish().returncode, 0)
        self.assertNotEqual(self.run_publish("../latest").returncode, 0)
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
