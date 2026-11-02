# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The configuration: seven settings, four of them with defaults. The rest is in the identity provider's metadata."""

from __future__ import annotations

import json
import math
import os
import re

from cryptography.hazmat.primitives.asymmetric import rsa

from saml2_sp.errors import SamlError
from saml2_sp.x509util import certificate_pem, load_certificate, load_private_key, private_key_pem

_REQUEST = ("redirect", "post")
_RESPONSE = ("post", "redirect", "artifact")


class ResolvedConfig:
    """The configuration with its files read and its defaults filled in.

    ``signals`` is present only when CAEP and RISC are off. Omitted means on: test ``signals not in config``.
    """

    def __init__(self, **fields: object) -> None:
        self.__dict__.update(fields)

    def __contains__(self, key: object) -> bool:
        return key in self.__dict__


def _expand(value: str) -> str:
    seen = 0
    while value.startswith("env:") or value.startswith("file:"):
        seen += 1
        if seen > 4:
            raise SamlError("config", f"the placeholder {value} is nested too deeply")
        if value.startswith("env:"):
            name = value[4:]
            if not name or name not in os.environ:
                raise SamlError("config", f"environment variable {name or value} is not set")
            value = os.environ[name]
            continue
        value = value[5:]
    return value


def _looks_like_pem(value: str) -> bool:
    return "-----BEGIN " in value


def material(value: str, base_dir: str, what: str) -> str:
    value = _expand(value)
    if _looks_like_pem(value):
        return value
    path = value if os.path.isabs(value) else os.path.abspath(os.path.join(base_dir, value))
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError as err:
        raise SamlError("config", f"{what} is neither a PEM nor a readable file ({path})") from err


def _absolute_url(value: object, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SamlError("config", f"{what} is required")
    if not re.match(r"https?://", value):
        raise SamlError("config", f"{what} must be an absolute http(s) URL, not {value}")
    return value


def _one_of(value: object, allowed: tuple[str, ...], default: str, what: str) -> str:
    if value is None or value == "":
        return default
    if value not in allowed:
        raise SamlError("config", f"{what} must be one of {', '.join(allowed)}, not {value}")
    return str(value)


def _number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def resolve_config(config: dict, base_dir: str | None = None) -> ResolvedConfig:
    if not isinstance(config, dict):
        raise SamlError("config", "the configuration must be an object")
    base = base_dir or os.getcwd()
    entity_id = config.get("entityId")
    if not isinstance(entity_id, str) or not entity_id.strip():
        raise SamlError("config", "entityId is required")
    acs_url = _absolute_url(config.get("acsUrl"), "acsUrl")
    if not isinstance(config.get("privateKey"), str) or not isinstance(config.get("certificate"), str):
        raise SamlError("config", "privateKey and certificate are required: every AuthnRequest is signed")
    try:
        key_pem = material(config["privateKey"], base, "privateKey")
        cert_pem = material(config["certificate"], base, "certificate")
        private_key = load_private_key(key_pem)
        certificate = load_certificate(cert_pem)
    except SamlError:
        raise
    except Exception as err:
        raise SamlError("config", f"the private key or certificate cannot be read: {err}") from err
    if not isinstance(private_key, rsa.RSAPrivateKey):
        kind = "ec" if private_key.__class__.__name__.lower().startswith("ec") else private_key.__class__.__name__
        raise SamlError("config", f"the private key is {kind}; an RSA key is required")
    if private_key.public_key().public_numbers() != certificate.public_key().public_numbers():
        raise SamlError("config", "the certificate is not for the private key")
    idp_metadata = config.get("idpMetadata")
    if not isinstance(idp_metadata, str) or not idp_metadata.strip():
        raise SamlError("config", "idpMetadata is required")
    idp_metadata = _expand(idp_metadata.strip())
    if not re.match(r"https?://", idp_metadata) and not idp_metadata.startswith("<"):
        idp_metadata = idp_metadata if os.path.isabs(idp_metadata) else os.path.abspath(os.path.join(base, idp_metadata))
    skew = config["clockSkewSeconds"] if "clockSkewSeconds" in config and config["clockSkewSeconds"] is not None else 60
    if not _number(skew) or skew < 0 or skew > 600:
        raise SamlError("config", "clockSkewSeconds must be a number from 0 to 600")
    if "signals" in config and not isinstance(config["signals"], bool):
        raise SamlError("config", "signals must be true or false")
    fields: dict[str, object] = {
        "entity_id": entity_id,
        "acs_url": acs_url,
        "private_key": private_key,
        "private_key_pem": private_key_pem(private_key),
        "certificate": certificate,
        "certificate_pem": certificate_pem(certificate),
        "idp_metadata": idp_metadata,
        "request_binding": _one_of(config.get("requestBinding"), _REQUEST, "redirect", "requestBinding"),
        "response_binding": _one_of(config.get("responseBinding"), _RESPONSE, "post", "responseBinding"),
        "clock_skew_ms": int(skew) * 1000,
        "want_assertions_signed": True if config.get("wantAssertionsSigned") is None else config.get("wantAssertionsSigned"),
        "want_assertions_encrypted": False if config.get("wantAssertionsEncrypted") is None else config.get("wantAssertionsEncrypted"),
        "allow_unsolicited": False if config.get("allowUnsolicited") is None else config.get("allowUnsolicited"),
    }
    if config.get("signals") is False:
        fields["signals"] = False
    if config.get("idpCa"):
        fields["idp_ca"] = material(config["idpCa"], base, "idpCa")
    if config.get("idpEntityId"):
        fields["idp_entity_id"] = config["idpEntityId"]
    if config.get("nameIdFormat"):
        fields["name_id_format"] = config["nameIdFormat"]
    return ResolvedConfig(**fields)


def read_config_file(path: str, overrides: dict | None = None) -> ResolvedConfig:
    try:
        with open(path, encoding="utf-8") as handle:
            parsed = json.load(handle)
    except Exception as err:
        raise SamlError("config", f"{path} cannot be read as JSON: {err}") from err
    defined = {k: v for k, v in (overrides or {}).items() if v is not None}
    if not isinstance(parsed, dict):
        raise SamlError("config", "the configuration must be an object")
    return resolve_config({**parsed, **defined}, os.path.dirname(os.path.abspath(path)))
