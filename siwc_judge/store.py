"""Credential and host-id storage, kept outside any repository."""
from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
import uuid
from pathlib import Path

TOKEN_FIELDS = ("access_token", "refresh_token", "expires_at", "expires_in", "earliest_refresh_at")


def home() -> Path:
    override = os.environ.get("SIWC_JUDGE_HOME")
    return Path(override) if override else Path.home() / ".siwc-judge"


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)  # Windows: inherits the user-profile ACL


def _write_private(path: Path, data: dict) -> None:
    _private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="." + path.name + ".", suffix=".tmp")  # 0600 on POSIX
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def host_id() -> str:
    """Opaque stable per-host id (urn:uuid form), created once before the first sign-in and never deleted."""
    path = home() / "host.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8")).get("ext_agent_host_id")
        if value:
            return value
    except (OSError, ValueError):
        pass
    value = "urn:uuid:" + str(uuid.uuid4())
    _write_private(path, {"ext_agent_host_id": value})
    return value


def load() -> dict | None:
    try:
        return json.loads((home() / "credentials.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def save(record: dict) -> None:
    _write_private(home() / "credentials.json", record)


def clear_tokens(record: dict, *, keep_id_token: bool) -> dict:
    """Drop the session but keep the registration (client_id, identity) for the next sign-in."""
    out = {k: v for k, v in record.items() if k not in TOKEN_FIELDS}
    if not keep_id_token:  # the docs: omit id_token_hint after signing out
        out.pop("id_token", None)
    return out


def delete() -> None:
    with contextlib.suppress(FileNotFoundError):
        (home() / "credentials.json").unlink()


@contextlib.contextmanager
def lock(timeout: float = 60, stale: float = 120):
    """Cross-process lock so two runs never spend the same rotating refresh token."""
    path = home() / "credentials.lock"
    _private_dir(path.parent)
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            break
        except FileExistsError:
            with contextlib.suppress(OSError):
                if time.time() - path.stat().st_mtime > stale:
                    path.unlink()  # left behind by a crashed process
                    continue
            if time.monotonic() > deadline:
                raise TimeoutError(f"another process holds {path}") from None
            time.sleep(0.1)
    try:
        yield
    finally:
        with contextlib.suppress(OSError):
            path.unlink()
