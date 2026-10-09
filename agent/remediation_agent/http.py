# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Minimal JSON/bytes HTTP client for the public vulnerability and package registries.

Outbound requests are restricted to an allowlist of hosts over HTTPS. Redirects
are followed only when the target is also an allowlisted HTTPS host, so a
crafted package name or a compromised response cannot steer the agent to an
internal endpoint (for example, the instance metadata service) or to another
URL scheme.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

USER_AGENT = "agentic-dependency-remediation/0.1"
TIMEOUT_SECONDS = 30
MAX_RESPONSE_BYTES = 50 * 1024 * 1024

ALLOWED_HOSTS = frozenset(
    {
        "api.osv.dev",  # vulnerability database
        "pypi.org",  # Python package index
        "registry.npmjs.org",  # npm registry
        "repo1.maven.org",  # Maven Central
    }
)


class HttpError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


def check_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS or parsed.username or parsed.port not in (None, 443):
        raise ValueError(f"Outbound request to '{parsed.scheme}://{parsed.hostname}' is not allowed.")


class _AllowlistRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(urllib.parse.urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# check_url runs before every request, on every redirect target, and on the final URL,
# so only allowlisted HTTPS hosts are ever contacted.
_OPENER = urllib.request.build_opener(_AllowlistRedirectHandler)


def request(
    method: str,
    url: str,
    *,
    body: Any | None = None,
    headers: dict[str, str] | None = None,
    raw: bool = False,
) -> Any:
    check_url(url)
    data = json.dumps(body).encode() if body is not None else None
    all_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if data is not None:
        all_headers["Content-Type"] = "application/json"
    all_headers.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=all_headers, method=method)
    try:
        with _OPENER.open(req, timeout=TIMEOUT_SECONDS) as response:
            check_url(response.geturl())
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        detail = exc.read(2000).decode(errors="replace")[:500]
        raise HttpError(exc.code, detail) from exc
    if len(payload) > MAX_RESPONSE_BYTES:
        raise HttpError(413, "Response is too large.")
    if raw:
        return payload
    return json.loads(payload) if payload else None
