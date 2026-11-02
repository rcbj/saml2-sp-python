# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Verifying a Security Event Token (a compact JWS) against the transmitter's published keys."""

from __future__ import annotations

import base64
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from saml2_sp.errors import SamlError

ALGS = {
    "RS256": {"hash": "sha256", "kty": "RSA"},
    "RS384": {"hash": "sha384", "kty": "RSA"},
    "RS512": {"hash": "sha512", "kty": "RSA"},
    "PS256": {"hash": "sha256", "kty": "RSA", "pss": True},
    "PS384": {"hash": "sha384", "kty": "RSA", "pss": True},
    "PS512": {"hash": "sha512", "kty": "RSA", "pss": True},
    "ES256": {"hash": "sha256", "kty": "EC", "p1363": True, "size": 32},
    "ES384": {"hash": "sha384", "kty": "EC", "p1363": True, "size": 48},
    "ES512": {"hash": "sha512", "kty": "EC", "p1363": True, "size": 66},
    "EdDSA": {"hash": None, "kty": "OKP"},
    "Ed25519": {"hash": None, "kty": "OKP"},
}
SUPPORTED_JWS_ALGS = list(ALGS)
_HASH = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


def _b64url(value: str, what: str) -> bytes:
    if not _B64URL.match(value):
        raise SamlError("signature", f"the SET's {what} is not base64url")
    pad = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _key_for(jwk: dict):
    try:
        kty = jwk.get("kty")
        if kty == "RSA":
            n = int.from_bytes(_b64url(jwk["n"], "key"), "big")
            e = int.from_bytes(_b64url(jwk["e"], "key"), "big")
            return rsa.RSAPublicNumbers(e, n).public_key()
        if kty == "EC":
            curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}[jwk["crv"]]
            x = int.from_bytes(_b64url(jwk["x"], "key"), "big")
            y = int.from_bytes(_b64url(jwk["y"], "key"), "big")
            return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        if kty == "OKP":
            return ed25519.Ed25519PublicKey.from_public_bytes(_b64url(jwk["x"], "key"))
        raise ValueError(f"unsupported kty {kty}")
    except SamlError:
        raise
    except Exception as err:
        raise SamlError("signature", f"the transmitter's key {jwk.get('kid') or ''} cannot be read: {err}") from err


def _verify(key, spec: dict, data: bytes, sig: bytes) -> bool:
    try:
        if spec["hash"] is None:
            key.verify(sig, data)
            return True
        algorithm = _HASH[spec["hash"]]
        if spec.get("pss"):
            key.verify(sig, data, padding.PSS(mgf=padding.MGF1(algorithm), salt_length=algorithm.digest_size), algorithm)
            return True
        if spec.get("p1363"):
            size = spec["size"]
            if len(sig) != size * 2:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big"))
            key.verify(der, data, ec.ECDSA(algorithm))
            return True
        key.verify(sig, data, padding.PKCS1v15(), algorithm)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def verify_compact_jws(token: str, keys: list[dict]) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise SamlError("signature", "the SET is not a compact JWS")
    header_b, payload_b, sig_b = parts
    try:
        header = json.loads(_b64url(header_b, "header").decode("utf-8"))
        payload = json.loads(_b64url(payload_b, "payload").decode("utf-8"))
    except SamlError:
        raise
    except Exception as err:
        raise SamlError("signature", "the SET's header or payload is not JSON") from err
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise SamlError("signature", "the SET's header or payload is not a JSON object")
    alg = str(header.get("alg") or "")
    spec = ALGS.get(alg)
    if spec is None:
        raise SamlError("signature", f"the SET is signed with {alg or '(no alg)'}, which this receiver does not verify ({', '.join(SUPPORTED_JWS_ALGS)})")
    if "crit" in header:
        raise SamlError("signature", "the SET's header has a crit member this receiver does not understand")
    kid = header["kid"] if isinstance(header.get("kid"), str) else None
    candidates = [
        key for key in keys
        if (kid is None or key.get("kid") == kid) and key.get("kty") == spec["kty"]
        and (not key.get("use") or key.get("use") == "sig") and (not key.get("alg") or key.get("alg") == alg)
    ]
    if not candidates:
        which = f" with kid {kid}" if kid else ""
        raise SamlError("signature", f"the transmitter publishes no {spec['kty']} signing key{which}")
    data = f"{header_b}.{payload_b}".encode("ascii")
    signature = _b64url(sig_b, "signature")
    for jwk in candidates:
        if _verify(_key_for(jwk), spec, data, signature):
            return {"header": header, "payload": payload}
    raise SamlError("signature", "the SET's signature does not verify against the transmitter's keys")
