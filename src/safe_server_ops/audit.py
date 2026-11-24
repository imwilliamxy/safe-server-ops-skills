"""Append-only JSONL audit logger for opsd."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogger:
    """Thread-safe append-only JSONL audit trail (0600 permissions)."""

    def __init__(self, log_path: Path | str) -> None:
        self._path = Path(log_path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def record(
        self,
        *,
        action: str,
        ok: bool,
        server: str | None = None,
        target: str | None = None,
        plan_token_id: str | None = None,
        approved_by: str | None = None,
        exit_code: int | None = None,
        duration_ms: int | None = None,
        summary: str = "",
        extra: dict[str, Any] | None = None,
    ) -> None:
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "action": action,
            "ok": ok,
        }
        if server is not None:
            entry["server"] = server
        if target is not None:
            entry["target"] = target
        if plan_token_id is not None:
            entry["plan_token_id"] = plan_token_id
        if approved_by is not None:
            entry["approved_by"] = approved_by
        if exit_code is not None:
            entry["exit_code"] = exit_code
        if duration_ms is not None:
            entry["duration_ms"] = duration_ms
        if summary:
            entry["summary"] = summary
        if extra:
            entry["extra"] = extra

        line = (json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8")
        with self._lock:
            fd = os.open(
                str(self._path),
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            try:
                os.write(fd, line)
            finally:
                os.close(fd)
