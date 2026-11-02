# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Failures reported by the service provider."""

from __future__ import annotations


class SamlStatus:
    """A non-success status an identity provider answered with."""

    def __init__(self, code: str, sub_code: str | None = None, message: str | None = None) -> None:
        self.code = code
        self.sub_code = sub_code
        self.message = message

    def __repr__(self) -> str:
        return f"SamlStatus(code={self.code!r}, sub_code={self.sub_code!r}, message={self.message!r})"


class SamlError(Exception):
    """Every failure this package reports is one of these."""

    def __init__(self, code: str, message: str, *, cause: BaseException | None = None, status: SamlStatus | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        if cause is not None:
            self.__cause__ = cause
