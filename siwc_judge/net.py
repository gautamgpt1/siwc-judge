"""The only module that touches the network (patched in tests)."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


class Response:
    def __init__(self, status: int, headers: dict, fp):
        self.status = status
        self.headers = headers
        self._fp = fp

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
    """Perform an HTTPS request; non-2xx statuses are returned, not raised."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return Response(r.status, dict(r.headers), r)
    except urllib.error.HTTPError as e:
        return Response(e.code, dict(e.headers or {}), e)


def form(fields: dict) -> tuple[bytes, dict]:
    return (
        urllib.parse.urlencode(fields).encode("utf-8"),
        {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
