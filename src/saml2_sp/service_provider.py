# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The service provider: login, the assertion consumer, and metadata."""

from __future__ import annotations

import base64
import os
from urllib.parse import parse_qsl

from saml2_sp.artifact import resolve_artifact
from saml2_sp.backchannel import send
from saml2_sp.bindings import post_form_html, read_post, read_redirect, redirect_query
from saml2_sp.config import ResolvedConfig, read_config_file, resolve_config
from saml2_sp.errors import SamlError
from saml2_sp.metadata import read_idp_metadata, write_sp_metadata
from saml2_sp.replay import MemoryReplayCache
from saml2_sp.response import validate_response
from saml2_sp.signature import sign_enveloped
from saml2_sp.xml import BINDING, NS, escape_xml, new_id, parse_xml

_BINDING_URI = {"post": BINDING["post"], "redirect": BINDING["redirect"], "artifact": BINDING["artifact"]}


class LoginRequest:
    def __init__(self, **fields: object) -> None:
        self.__dict__.update(fields)


def _first(pairs: list[tuple[str, str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in pairs:
        if key not in out:
            out[key] = value
    return out


def _form_of(body) -> dict[str, str]:
    if body is None:
        return {}
    if isinstance(body, str):
        return _first(parse_qsl(body, keep_blank_values=True))
    if isinstance(body, dict):
        return {key: value for key, value in body.items() if isinstance(value, str)}
    return {}


class ServiceProvider:
    def __init__(self, config: ResolvedConfig, idp=None, replay_cache=None) -> None:
        self.config = config
        self._idp = idp
        self._replay_cache = replay_cache or MemoryReplayCache()

    @staticmethod
    def create(config: dict, base_dir: str | None = None, replay_cache=None) -> "ServiceProvider":
        provider = ServiceProvider(resolve_config(config, base_dir), None, replay_cache)
        provider.refresh_metadata()
        return provider

    @staticmethod
    def from_file(path: str, overrides: dict | None = None, replay_cache=None) -> "ServiceProvider":
        provider = ServiceProvider(read_config_file(path, overrides), None, replay_cache)
        provider.refresh_metadata()
        return provider

    @property
    def idp(self):
        if self._idp is None:
            raise SamlError("metadata", "the identity provider's metadata has not been loaded")
        return self._idp

    def _tls(self) -> dict:
        ca = getattr(self.config, "idp_ca", None)
        return {"ca": ca} if ca else {}

    def refresh_metadata(self):
        source = self.config.idp_metadata
        if source.startswith("<"):
            xml = source
        elif source.startswith("http://") or source.startswith("https://"):
            answer = send(source, headers={"accept": "application/samlmetadata+xml, application/xml, text/xml"}, tls=self._tls(), code="metadata")
            if answer.status != 200:
                raise SamlError("metadata", f"{source} answered HTTP {answer.status}")
            xml = answer.body
        else:
            try:
                with open(source, encoding="utf-8") as handle:
                    xml = handle.read()
            except OSError as err:
                raise SamlError("metadata", f"the identity provider metadata file {source} cannot be read") from err
        self._idp = read_idp_metadata(xml, getattr(self.config, "idp_entity_id", None))
        return self._idp

    def metadata(self) -> str:
        return write_sp_metadata(
            self.config.entity_id,
            self.config.acs_url,
            self.config.certificate,
            bool(self.config.want_assertions_signed),
            getattr(self.config, "name_id_format", None),
        )

    def login(self, relay_state: str | None = None, force_authn: bool = False, is_passive: bool = False,
              subject_hint: str | None = None, subject_hint_format: str | None = None,
              request_binding: str | None = None, response_binding: str | None = None, nonce: str | None = None) -> LoginRequest:
        binding = request_binding or self.config.request_binding
        response = response_binding or self.config.response_binding
        if response == "artifact" and not self.idp.artifact_resolution_services:
            raise SamlError("config", "the identity provider has no SOAP ArtifactResolutionService, so the Response cannot come by artifact")
        destination = self.idp.sso_urls.get(binding)
        if not destination:
            which = "POST" if binding == "post" else "Redirect"
            raise SamlError("config", f"the identity provider has no SingleSignOnService on HTTP-{which}")
        if relay_state is not None and len(relay_state.encode("utf-8")) > 80:
            raise SamlError("config", "relayState is longer than the 80 bytes the bindings allow")
        element_id = new_id(os.urandom(20).hex())
        force = ' ForceAuthn="true"' if force_authn else ""
        passive = ' IsPassive="true"' if is_passive else ""
        if subject_hint is not None:
            form = f' Format="{escape_xml(subject_hint_format)}"' if subject_hint_format else ""
            subject = f"<saml:Subject><saml:NameID{form}>{escape_xml(subject_hint)}</saml:NameID></saml:Subject>"
        else:
            subject = ""
        name_format = getattr(self.config, "name_id_format", None)
        policy = (
            f'<samlp:NameIDPolicy Format="{escape_xml(name_format)}" AllowCreate="true"/>'
            if name_format else '<samlp:NameIDPolicy AllowCreate="true"/>'
        )
        xml = (
            f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" ID="{element_id}" Version="2.0"'
            f' IssueInstant="{_iso()}" Destination="{escape_xml(destination)}"'
            f' AssertionConsumerServiceURL="{escape_xml(self.config.acs_url)}" ProtocolBinding="{_BINDING_URI[response]}"{force}{passive}>'
            f"<saml:Issuer>{escape_xml(self.config.entity_id)}</saml:Issuer>"
            f"{subject}{policy}</samlp:AuthnRequest>"
        )
        if binding == "redirect":
            query = redirect_query("SAMLRequest", xml, relay_state, self.config.private_key)
            join = "&" if "?" in destination else "?"
            return LoginRequest(id=element_id, binding=binding, response_binding=response, url=f"{destination}{join}{query}", xml=xml)
        signed = sign_enveloped(xml, element_id, self.config.private_key, self.config.certificate)
        fields = {"SAMLRequest": base64.b64encode(signed.encode("utf-8")).decode("ascii")}
        if relay_state is not None:
            fields["RelayState"] = relay_state
        html = post_form_html(destination, fields, nonce=nonce)
        return LoginRequest(id=element_id, binding=binding, response_binding=response, url=destination, fields=fields, html=html, xml=signed)

    def acs(self, method: str, url: str, body=None, request_id: str | list[str] | None = None):
        idp = self.idp
        verb = method.upper()
        raw_query = url.split("?", 1)[1].split("#", 1)[0] if "?" in url else ""
        query = _first(parse_qsl(raw_query, keep_blank_values=True))
        form = _form_of(body) if verb == "POST" else {}
        expected = [] if request_id is None else ([request_id] if isinstance(request_id, str) else list(request_id))
        ctx = {
            "entity_id": self.config.entity_id,
            "acs_url": self.config.acs_url,
            "idp_entity_id": idp.entity_id,
            "idp_certificates": idp.signing_certificates,
            "decryption_key": self.config.private_key,
            "clock_skew_ms": self.config.clock_skew_ms,
            "want_assertions_signed": self.config.want_assertions_signed,
            "want_assertions_encrypted": self.config.want_assertions_encrypted,
            "allow_unsolicited": self.config.allow_unsolicited,
            "replay_cache": self._replay_cache,
            "expected_request_ids": expected,
        }
        saml_art = form.get("SAMLart") or query.get("SAMLart")
        if saml_art:
            resolved = resolve_artifact({
                "artifact": saml_art,
                "entity_id": self.config.entity_id,
                "idp_entity_id": idp.entity_id,
                "artifact_resolution_services": idp.artifact_resolution_services,
                "idp_certificates": idp.signing_certificates,
                "key": self.config.private_key,
                "certificate": self.config.certificate,
                "tls": self._tls(),
            })
            relay = form.get("RelayState") if form.get("SAMLart") else query.get("RelayState")
            return validate_response({
                "xml": resolved["xml"],
                "response": resolved["response"],
                "binding": "artifact",
                "relay_state": relay,
                "authenticated_by_binding": True,
            }, ctx)
        if verb == "POST" and form.get("SAMLResponse"):
            xml = read_post(form["SAMLResponse"], "SAMLResponse")
            root = parse_xml(xml, "the Response")
            return validate_response({
                "xml": xml, "response": root, "binding": "post",
                "relay_state": form.get("RelayState"), "authenticated_by_binding": False,
            }, ctx)
        if query.get("SAMLResponse"):
            message = read_redirect(raw_query, "SAMLResponse", idp.signing_certificates)
            root = parse_xml(message["xml"], "the Response")
            return validate_response({
                "xml": message["xml"], "response": root, "binding": "redirect",
                "relay_state": message["relay_state"], "authenticated_by_binding": message["signed"],
            }, ctx)
        raise SamlError("binding", "the request carries no SAMLResponse or SAMLart")


def _iso() -> str:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
