"""Credential and host-id storage, kept outside any repository."""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path


def home() -> Path:
    override = os.environ.get("SIWC_JUDGE_HOME")
    return Path(override) if override else Path.home() / ".siwc-judge"


def _write_private(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def host_id() -> str:
    """Opaque stable per-host id (urn:uuid form), created once before the first sign-in."""
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


def delete() -> None:
    try:
        (home() / "credentials.json").unlink()
    except FileNotFoundError:
        pass
