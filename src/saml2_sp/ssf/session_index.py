# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Which of the application's own sessions belong to which person and identity-provider session."""

from __future__ import annotations

import threading
from datetime import datetime, timezone

DEFAULT_SUBJECT_ATTRIBUTE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
MAIL_ATTRIBUTES = [
    "urn:oid:0.9.2342.19200300.100.1.3",
    "mail",
    "email",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
]
EMAIL_NAMEID = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"


def _ms(when: datetime) -> int:
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return int(when.timestamp() * 1000)


class MemorySessionIndex:
    def __init__(self, max_entries: int = 100_000) -> None:
        self._sessions: dict[str, dict] = {}
        self._max = max_entries
        self._lock = threading.Lock()

    def add(self, session: dict) -> None:
        with self._lock:
            if len(self._sessions) >= self._max and session["local_id"] not in self._sessions:
                now = int(datetime.now(timezone.utc).timestamp() * 1000)
                expired = [key for key, value in self._sessions.items() if value.get("expires_at") is not None and _ms(value["expires_at"]) <= now]
                for key in expired:
                    del self._sessions[key]
                while len(self._sessions) >= self._max:
                    del self._sessions[next(iter(self._sessions))]
            stored = dict(session)
            if stored.get("email"):
                stored["email"] = stored["email"].lower()
            self._sessions[session["local_id"]] = stored

    def remove(self, local_id: str) -> None:
        with self._lock:
            self._sessions.pop(local_id, None)

    def _find(self, match) -> list[str]:
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        out = []
        for key, value in list(self._sessions.items()):
            expires = value.get("expires_at")
            if expires is not None and _ms(expires) <= now:
                del self._sessions[key]
                continue
            if match(value):
                out.append(key)
        return out

    def by_person(self, person: str) -> list[str]:
        with self._lock:
            return self._find(lambda session: session.get("person") == person)

    def by_email(self, email: str) -> list[str]:
        wanted = email.lower()
        with self._lock:
            return self._find(lambda session: session.get("email") == wanted)

    def by_idp_session(self, idp_session: str) -> list[str]:
        with self._lock:
            return self._find(lambda session: session.get("idp_session") == idp_session)


def tracked_from(local_id: str, login, subject_attribute: str | None = None, expires_at: datetime | None = None) -> dict:
    attribute = subject_attribute or DEFAULT_SUBJECT_ATTRIBUTE
    person = (getattr(login, "attributes", {}) or {}).get(attribute, [None])[0]
    email = next((getattr(login, "attributes", {}).get(name, [None])[0] for name in MAIL_ATTRIBUTES if getattr(login, "attributes", {}).get(name)), None)
    if email is None and getattr(login, "name_id_format", None) == EMAIL_NAMEID:
        email = getattr(login, "name_id", None)
    return {
        "local_id": local_id,
        "person": person,
        "email": email,
        "idp_session": getattr(login, "session_index", None),
        "expires_at": expires_at if expires_at is not None else getattr(login, "session_not_on_or_after", None),
    }
