"""The only module that touches the network (patched in tests)."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib would replay the Authorization header to a redirect target (any host, even http://)."""

    def redirect_request(self, *args, **kwargs):
        return None  # the 3xx is returned to the caller as an ordinary non-2xx response


_OPENER = urllib.request.build_opener(_NoRedirect)


class Response:
    def __init__(self, status: int, headers, fp):
        self.status = status
        self.headers = dict(headers or {})
        self._fp = fp

    def header(self, name: str) -> str | None:
        name = name.lower()
        return next((v for k, v in self.headers.items() if k.lower() == name), None)

    def read(self) -> bytes:
        try:
            return self._fp.read()
        finally:
            self.close()

    def json(self):
        return json.loads(self.read().decode("utf-8"))

    def iter_lines(self):
        for raw in self._fp:
            yield raw.decode("utf-8", "replace").rstrip("\r\n")

    def close(self) -> None:
        try:
            self._fp.close()
        except Exception:
            pass


def send(method: str, url: str, headers: dict | None = None, body: bytes | None = None, timeout: float = 300) -> Response:
    """Perform an HTTPS request; non-2xx statuses (including 3xx) are returned, not raised or followed."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        r = _OPENER.open(req, timeout=timeout)
        return Response(r.status, r.headers.items(), r)
    except urllib.error.HTTPError as e:
        return Response(e.code, (e.headers or {}).items(), e)


def form(fields: dict) -> tuple[bytes, dict]:
    return (
        urllib.parse.urlencode(fields).encode("utf-8"),
        {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
