# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The back channel: identity-provider metadata and artifact resolution. TLS is verified."""

from __future__ import annotations

import os
import ssl
import tempfile
import urllib.error
import urllib.request

from saml2_sp.errors import SamlError

MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 15


class HttpAnswer:
    def __init__(self, status: int, content_type: str, body: str) -> None:
        self.status = status
        self.content_type = content_type
        self.body = body


def send(url: str, method: str = "GET", headers: dict[str, str] | None = None, body: str | None = None,
         tls: dict[str, str] | None = None, code: str = "metadata") -> HttpAnswer:
    if not (url.startswith("https://") or url.startswith("http://")):
        raise SamlError(code, f"{url} is not an http(s) URL")
    data = None if body is None else body.encode("utf-8")
    req_headers = dict(headers or {})
    if data is not None:
        req_headers["content-length"] = str(len(data))
    request = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    ctx = None
    temps: list[str] = []
    tls = tls or {}
    if url.startswith("https://"):
        ctx = ssl.create_default_context()
        if tls.get("ca"):
            ctx.load_verify_locations(cadata=tls["ca"])
        if tls.get("cert") and tls.get("key"):
            cert_path = _write_temp(tls["cert"])
            key_path = _write_temp(tls["key"])
            temps.extend([cert_path, key_path])
            ctx.load_cert_chain(cert_path, key_path)
    try:
        try:
            response = urllib.request.urlopen(request, timeout=TIMEOUT_S, context=ctx)
        except urllib.error.HTTPError as err:
            response = err
        except Exception as err:
            raise SamlError(code, f"{url}: {err}") from err
        chunks: list[bytes] = []
        size = 0
        while True:
            part = response.read(65536)
            if not part:
                break
            size += len(part)
            if size > MAX_BYTES:
                raise SamlError(code, f"{url} answered more than {MAX_BYTES} bytes")
            chunks.append(part)
        content_type = ""
        if response.headers is not None:
            content_type = response.headers.get("content-type") or ""
        status = getattr(response, "status", None)
        if status is None:
            status = response.getcode()
        return HttpAnswer(int(status or 0), content_type, b"".join(chunks).decode("utf-8", "replace"))
    except SamlError:
        raise
    except Exception as err:
        message = str(err).lower()
        if "timed out" in message or "timeout" in message:
            raise SamlError(code, f"{url} did not answer within {TIMEOUT_S} s") from err
        raise SamlError(code, f"{url}: {err}") from err
    finally:
        for path in temps:
            try:
                os.unlink(path)
            except OSError:
                pass


def _write_temp(pem: str) -> str:
    handle = tempfile.NamedTemporaryFile("w", delete=False)
    try:
        handle.write(pem)
        handle.close()
    except Exception:
        handle.close()
        raise
    return handle.name
