# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""HTTP-Redirect and HTTP-POST encodings (SAML 2.0 Bindings, sections 3.4 and 3.5)."""

from __future__ import annotations

import base64
import re
import zlib
from urllib.parse import quote, unquote

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from saml2_sp.errors import SamlError
from saml2_sp.signature import RSA_SHA256, SIGNATURE_ALGORITHMS
from saml2_sp.xml import escape_xml

MAX_INFLATED = 1024 * 1024
_URI_SAFE = "-_.!~*'()"
_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_BAD_PCT = re.compile(r"%(?![0-9A-Fa-f]{2})")


def uri_escape(value: str) -> str:
    return quote(value, safe=_URI_SAFE)


def uri_unescape(value: str) -> str:
    text = value.replace("+", "%20")
    if _BAD_PCT.search(text):
        raise SamlError("binding", "the query string is not validly percent-encoded")
    return unquote(text)


def deflate_raw(data: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(data) + compressor.flush()


def inflate_raw(data: bytes, limit: int = MAX_INFLATED) -> bytes:
    decompressor = zlib.decompressobj(wbits=-15)
    out = decompressor.decompress(data, limit + 1)
    if len(out) > limit or decompressor.unconsumed_tail:
        raise SamlError("binding", "the message inflates past the limit")
    return out + decompressor.flush()


def redirect_query(param: str, xml: str, relay_state: str | None, key) -> str:
    encoded = base64.b64encode(deflate_raw(xml.encode("utf-8"))).decode("ascii")
    parts = [f"{param}={uri_escape(encoded)}"]
    if relay_state is not None:
        parts.append(f"RelayState={uri_escape(relay_state)}")
    parts.append(f"SigAlg={uri_escape(RSA_SHA256)}")
    signed = "&".join(parts)
    signature = base64.b64encode(key.sign(signed.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())).decode("ascii")
    return f"{signed}&Signature={uri_escape(signature)}"


def read_redirect(raw_query: str, param: str, certs: list) -> dict:
    raw: dict[str, str] = {}
    query = raw_query[1:] if raw_query.startswith("?") else raw_query
    for pair in query.split("&"):
        if not pair:
            continue
        eq = pair.find("=")
        name = uri_unescape(pair if eq < 0 else pair[:eq])
        if name in raw:
            raise SamlError("binding", f"the query string carries {name} twice")
        raw[name] = "" if eq < 0 else pair[eq + 1:]
    message = raw.get(param)
    if message is None:
        raise SamlError("binding", f"the query string carries no {param}")
    try:
        xml = inflate_raw(base64.b64decode(uri_unescape(message))).decode("utf-8")
    except SamlError:
        raise
    except Exception as err:
        raise SamlError("binding", f"{param} is not a DEFLATE-encoded message") from err
    relay_state = uri_unescape(raw["RelayState"]) if "RelayState" in raw else None
    if "Signature" not in raw:
        return {"xml": xml, "relay_state": relay_state, "signed": False}
    sig_alg = uri_unescape(raw.get("SigAlg", ""))
    hash_name = SIGNATURE_ALGORITHMS.get(sig_alg)
    if not hash_name:
        raise SamlError("signature", f"the query is signed with {sig_alg or '(no SigAlg)'}, which is refused")
    signed_parts = [f"{param}={message}"]
    if "RelayState" in raw:
        signed_parts.append(f"RelayState={raw['RelayState']}")
    signed_parts.append(f"SigAlg={raw.get('SigAlg', '')}")
    data = "&".join(signed_parts).encode("utf-8")
    try:
        sig_bytes = base64.b64decode(uri_unescape(raw["Signature"]))
    except Exception as err:
        raise SamlError("signature", "the query string signature does not verify against the identity provider's certificate") from err
    hash_alg = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}[hash_name]
    for cert in certs:
        try:
            cert.public_key().verify(sig_bytes, data, padding.PKCS1v15(), hash_alg)
            return {"xml": xml, "relay_state": relay_state, "signed": True}
        except Exception:
            continue
    raise SamlError("signature", "the query string signature does not verify against the identity provider's certificate")


def read_post(value: str, param: str) -> str:
    compact = re.sub(r"\s+", "", value)
    if not compact or not _B64.match(compact):
        raise SamlError("binding", f"{param} is not base64")
    return base64.b64decode(compact).decode("utf-8")


def post_form_html(action: str, fields: dict[str, str], nonce: str | None = None, title: str | None = None) -> str:
    inputs = "\n      ".join(
        f'<input type="hidden" name="{escape_xml(name)}" value="{escape_xml(value)}">' for name, value in fields.items()
    )
    script = f'\n    <script nonce="{escape_xml(nonce)}">document.forms[0].submit();</script>' if nonce else ""
    return f"""<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>{escape_xml(title or "Signing in")}</title></head>
  <body>
    <form method="post" action="{escape_xml(action)}">
      {inputs}
      <noscript><p>Your browser is not running scripts. Press Continue to go on.</p></noscript>
      <button type="submit">Continue</button>
    </form>{script}
  </body>
</html>
"""
