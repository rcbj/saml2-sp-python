# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The back channel: identity-provider metadata, artifact resolution and the Shared Signals
transmitter. TLS is verified. Plain http is refused unless the host is loopback."""

from __future__ import annotations

import ipaddress
import os
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from saml2_sp.errors import SamlError

MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 15


class HttpAnswer:
    def __init__(self, status: int, content_type: str, body: str) -> None:
        self.status = status
        self.content_type = content_type
        self.body = body


def is_loopback_host(host: str) -> bool:
    """A loopback host: 127.0.0.0/8, ::1 or the name localhost. ``host`` is a urlsplit hostname."""
    host = host.lower()
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.version == 4:
        return address in ipaddress.ip_network("127.0.0.0/8")
    return address == ipaddress.IPv6Address("::1")


def plain_http_refusal(url: str, code: str) -> SamlError | None:
    """The refusal of a plain http URL, unless it names a loopback host, where the bytes never leave
    the machine. Userinfo is never loopback, so ``http://localhost:80@host/`` cannot pass as
    localhost, and neither can a URL with whitespace or a control character, which urlsplit and
    urllib's own request parsing could read differently. The message names the scheme and
    host[:port] only: never userinfo, path or query."""
    authority = url[len("http://"):]
    for stop in "/?#":
        authority = authority.split(stop, 1)[0]
    _, at, hostport = authority.rpartition("@")
    shown = hostport if at else authority
    if not at and not any(ord(c) <= 0x20 or ord(c) == 0x7F for c in url):
        try:
            host = urllib.parse.urlsplit(url).hostname or ""
        except ValueError:
            host = ""
        if is_loopback_host(host):
            return None
    shown = "".join(c for c in shown if 0x20 < ord(c) != 0x7F)
    return SamlError(code, f"http://{shown} is refused: plain http is allowed only to a loopback host "
                     "(127.0.0.0/8, ::1, localhost); use https")


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    """Applies the plain-http rule to a redirect's target too: urllib follows redirects."""

    def __init__(self, code: str) -> None:
        super().__init__()
        self._code = code

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.lower().startswith("http://"):
            refusal = plain_http_refusal(newurl, self._code)
            if refusal is not None:
                raise refusal
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def send(url: str, method: str = "GET", headers: dict[str, str] | None = None, body: str | None = None,
         tls: dict[str, str] | None = None, code: str = "metadata") -> HttpAnswer:
    if not (url.startswith("https://") or url.startswith("http://")):
        raise SamlError(code, f"{url} is not an http(s) URL")
    # Every fetch this library makes goes through here: the identity provider's metadata (its signing
    # keys), the ArtifactResolve (the signed request out, the assertion back) and the Shared Signals
    # transmitter (SETs and the bearer token). None of them may travel in the clear off this machine,
    # so plain http is refused before any lookup or connection unless the host is loopback.
    if url.startswith("http://"):
        refusal = plain_http_refusal(url, code)
        if refusal is not None:
            raise refusal
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
    handlers: list[urllib.request.BaseHandler] = [_CheckedRedirects(code)]
    if ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    try:
        try:
            response = opener.open(request, timeout=TIMEOUT_S)
        except urllib.error.HTTPError as err:
            response = err
        except SamlError:
            raise
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
