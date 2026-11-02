# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Remembers which assertions have been accepted, so none is accepted twice."""

from __future__ import annotations

import threading
from datetime import datetime, timezone


def _ms(when: datetime) -> int:
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return int(when.timestamp() * 1000)


class MemoryReplayCache:
    """One process's memory, at most `max` live entries. A full cache refuses rather than forgetting."""

    def __init__(self, max_entries: int = 10_000) -> None:
        self._entries: dict[str, int] = {}
        self._max = max_entries
        self._lock = threading.Lock()

    def check_and_record(self, assertion_id: str, expires_at: datetime) -> bool:
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        with self._lock:
            until = self._entries.get(assertion_id)
            if until is not None and until > now:
                return True
            if len(self._entries) >= self._max:
                expired = [k for k, v in self._entries.items() if v <= now]
                for k in expired:
                    del self._entries[k]
                if len(self._entries) >= self._max:
                    raise RuntimeError(f"the replay cache holds {self._max} live assertions and cannot record another")
            self._entries[assertion_id] = _ms(expires_at)
            return False
