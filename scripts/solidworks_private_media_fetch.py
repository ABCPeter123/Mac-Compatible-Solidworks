"""Privacy-safe HTTPS downloader for a privately licensed installer.

No signed URLs, query strings, cookies, HTTP error bodies, file paths,
installer bytes or raw exception messages appear in output artifacts/logs.
A 404 is a permanent missing-object response, not a retryable Wine failure.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BYTES = 1024 * 1024 * 1024
MAX_URL_LENGTH = 8192
MAX_ATTEMPTS = 3
ALLOWED = {
    "DOWNLOADED", "MISSING_CONFIGURATION", "UNSAFE_URL",
    "PRESIGNED_URL_EXPIRED", "HTTP_401_UNAUTHORIZED",
    "HTTP_403_FORBIDDEN", "HTTP_404_NOT_FOUND",
    "HTTP_429_RATE_LIMITED", "HTTP_5XX", "HTTP_OTHER",
    "TRANSPORT_ERROR", "DOWNLOAD_TOO_LARGE",
}


class HTTPSOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Never send credentials or signed URLs to non-HTTPS redirects."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            raise ValueError("Unsafe redirect")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def check_url(url: str, now: datetime | None = None) -> str | None:
    """Returns a bounded status only. Does not reveal URL or query contents."""
    if not url:
        return "MISSING_CONFIGURATION"
    if len(url) > MAX_URL_LENGTH or url.strip() != url or any(ord(c) < 32 for c in url):
        return "UNSAFE_URL"
    try:
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme.lower() != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or parsed.port not in (None, 443)):
            return "UNSAFE_URL"
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        signed = query.get("X-Amz-Date")
        ttl = query.get("X-Amz-Expires")
        if signed and ttl and len(signed) == len(ttl) == 1:
            timestamp = datetime.strptime(signed[0], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            lifetime = int(ttl[0])
            if not 1 <= lifetime <= 604800:
                return "UNSAFE_URL"
            if (now or datetime.now(timezone.utc)) >= timestamp + timedelta(seconds=lifetime):
                return "PRESIGNED_URL_EXPIRED"
    except (ValueError, OverflowError):
        return "UNSAFE_URL"
    return None


def http_status(code: int) -> str:
    return {
        401: "HTTP_401_UNAUTHORIZED",
        403: "HTTP_403_FORBIDDEN",
        404: "HTTP_404_NOT_FOUND",
        429: "HTTP_429_RATE_LIMITED",
    }.get(code, "HTTP_5XX" if 500 <= code <= 599 else "HTTP_OTHER")


def fetch(url: str, dest: Path, *, opener=None, sleep=time.sleep) -> dict:
    """Download to a temporary file, then atomically install on complete transfer."""
    result = {
        "schema": 1,
        "component": "Private installer HTTPS transfer",
        "result": "TRANSPORT_ERROR",
        "download_verified": False,
        "digest_check": "NOT_CHECKED_HERE",
        "installer_executed": False,
        "secret_url_logged": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    invalid = check_url(url)
    if invalid:
        result["result"] = invalid
        return result
    dest.parent.mkdir(parents=True, exist_ok=True)
    client = opener if opener is not None else urllib.request.build_opener(HTTPSOnlyRedirect)
    for attempt in range(MAX_ATTEMPTS):
        temporary = None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SWCompat-PrivateInstallerFetch/1.0"})
            with client.open(req, timeout=90) as response:
                fd, tempname = tempfile.mkstemp(dir=dest.parent, prefix=".swcompat-download-")
                temporary = Path(tempname)
                total = 0
                with os.fdopen(fd, "wb") as stream:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > MAX_BYTES:
                            result["result"] = "DOWNLOAD_TOO_LARGE"
                            return result
                        stream.write(chunk)
                os.replace(temporary, dest)
                temporary = None
            result["result"] = "DOWNLOADED"
            result["download_verified"] = True
            return result
        except urllib.error.HTTPError as exc:
            result["result"] = http_status(exc.code)
            if exc.code not in (429, 500, 502, 503, 504) or attempt + 1 == MAX_ATTEMPTS:
                return result
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            result["result"] = "TRANSPORT_ERROR"
            return result
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
        sleep(1)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch installer from secret environment URL without logging it")
    parser.add_argument("--output", type=Path, required=True, help="Sanitized status report")
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args(argv)
    result = fetch(os.environ.get("SWCOMPAT_INSTALLER_URL", ""), args.destination)
    try:
        out = args.output.expanduser().resolve()
        dest = args.destination.expanduser().resolve()
        if out == dest:
            raise ValueError("Report path must differ from the executable")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError):
        parser.error("Unable to write sanitized media-download status")
    print("Private installer download:", result["result"])
    if result["result"] == "HTTP_404_NOT_FOUND":
        print("R2 object/key could not be fetched. Verify exact bucket, object name and signed GET URL locally.")
    elif result["result"] in ("PRESIGNED_URL_EXPIRED", "HTTP_403_FORBIDDEN"):
        print("Verify R2 signed URL expiration, method GET and token permissions; generate a fresh URL.")
    elif result["result"] == "MISSING_CONFIGURATION":
        print("Set SWCOMPAT_INSTALLER_URL in GitHub Actions repository secrets.")
    return 0 if result["result"] == "DOWNLOADED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
