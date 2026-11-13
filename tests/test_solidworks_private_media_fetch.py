"""Regression coverage for private R2 installer transfers and redaction."""
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from scripts.solidworks_private_media_fetch import check_url, fetch, http_status

SECRET = "https://abc123.r2.cloudflarestorage.com/private/Setup.exe?X-Amz-Signature=TOP_SECRET"
NOW = datetime(2026, 11, 13, 20, 0, 0, tzinfo=timezone.utc)


class Response:
    def __init__(self, data=b"Private licensed file"):
        self.stream = io.BytesIO(data)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return self.stream.read(limit)


class Client:
    def __init__(self, *items):
        self.items = list(items)
        self.calls = 0

    def open(self, req, timeout=0):
        self.calls += 1
        next_item = self.items.pop(0)
        if isinstance(next_item, Exception):
            raise next_item
        return next_item


def http_error(code):
    return HTTPError(SECRET, code, "Sensitive URL and account detail", {}, None)


class FetchTests(unittest.TestCase):
    def test_success_writes_file_without_exposing_secret(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            result = fetch(SECRET, folder / "Setup.exe", opener=Client(Response()), sleep=lambda _: None)
            self.assertEqual(result["result"], "DOWNLOADED")
            self.assertTrue(result["download_verified"])
            self.assertEqual((folder / "Setup.exe").read_bytes(), b"Private licensed file")
            self.assertNotIn("TOP_SECRET", json.dumps(result))
            self.assertNotIn("abc123", json.dumps(result))

    def test_404_is_not_retried_and_partial_file_is_absent(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            client = Client(http_error(404))
            result = fetch(SECRET, folder / "Setup.exe", opener=client, sleep=lambda _: None)
            self.assertEqual(result["result"], "HTTP_404_NOT_FOUND")
            self.assertEqual(client.calls, 1)
            self.assertFalse((folder / "Setup.exe").exists())

    def test_403_is_not_retried(self):
        with tempfile.TemporaryDirectory() as t:
            client = Client(http_error(403))
            result = fetch(SECRET, Path(t) / "Setup.exe", opener=client, sleep=lambda _: None)
            self.assertEqual(result["result"], "HTTP_403_FORBIDDEN")
            self.assertEqual(client.calls, 1)

    def test_retry_503_then_success(self):
        with tempfile.TemporaryDirectory() as t:
            client = Client(http_error(503), Response(b"OK"))
            result = fetch(SECRET, Path(t) / "Setup.exe", opener=client, sleep=lambda _: None)
            self.assertEqual(result["result"], "DOWNLOADED")
            self.assertEqual(client.calls, 2)

    def test_http_allowlist(self):
        self.assertEqual(http_status(401), "HTTP_401_UNAUTHORIZED")
        self.assertEqual(http_status(404), "HTTP_404_NOT_FOUND")
        self.assertEqual(http_status(429), "HTTP_429_RATE_LIMITED")
        self.assertEqual(http_status(502), "HTTP_5XX")

    def test_missing_and_unsafe_urls(self):
        self.assertEqual(check_url(""), "MISSING_CONFIGURATION")
        for url in ("http://example.com/private", "https://user:password@example.com/file",
                    "file:///tmp/file.exe", "https://example.com:8080/x",
                    "https://example.com/file\nheader"):
            with self.subTest(url=url):
                self.assertEqual(check_url(url), "UNSAFE_URL")

    def test_expired_r2_signature_is_classified_without_network(self):
        url = ("https://example.r2.cloudflarestorage.com/object?"
               "X-Amz-Date=20261113T180000Z&X-Amz-Expires=3600"
               "&X-Amz-Signature=SECRET")
        self.assertEqual(check_url(url, NOW), "PRESIGNED_URL_EXPIRED")

    def test_valid_r2_signature_not_rejected(self):
        url = ("https://example.r2.cloudflarestorage.com/object?"
               "X-Amz-Date=20261113T180000Z&X-Amz-Expires=21600"
               "&X-Amz-Signature=SECRET")
        self.assertIsNone(check_url(url, NOW))

    def test_malformed_expiration_rejected(self):
        url = ("https://example.r2.cloudflarestorage.com/object?"
               "X-Amz-Date=notadate&X-Amz-Expires=abcd")
        self.assertEqual(check_url(url), "UNSAFE_URL")

    def test_no_network_on_expired(self):
        with tempfile.TemporaryDirectory() as t:
            client = Client(Response())
            expired = "https://a.r2.cloudflarestorage.com/o?X-Amz-Date=20200101T000000Z&X-Amz-Expires=60"
            result = fetch(expired, Path(t) / "file.exe", opener=client)
            self.assertEqual(result["result"], "PRESIGNED_URL_EXPIRED")
            self.assertEqual(client.calls, 0)

    def test_cli_missing_secret_is_sanitized(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            result = subprocess.run(
                [sys.executable, "-m", "scripts.solidworks_private_media_fetch",
                 "--destination", str(folder / "Setup.exe"),
                 "--output", str(folder / "result.json")],
                env={"PATH": __import__("os").environ.get("PATH", "")},
                text=True, capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads((folder / "result.json").read_text())["result"],
                             "MISSING_CONFIGURATION")
            self.assertFalse((folder / "Setup.exe").exists())


if __name__ == "__main__":
    unittest.main()
