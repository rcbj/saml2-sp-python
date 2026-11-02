# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The HTTP-Artifact binding, as the receiving side of a Response."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from saml2_sp.backchannel import send
from saml2_sp.errors import SamlError
from saml2_sp.signature import sign_enveloped, verify_signed
from saml2_sp.xml import NS, STATUS_SUCCESS, assert_unique_ids, attr, child, children, escape_xml, new_id, parse_xml, text


def _iso(when: datetime | None = None) -> str:
    when = when or datetime.now(timezone.utc)
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"


def parse_artifact(saml_art: str) -> dict:
    import base64
    import re
    raw = base64.b64decode(re.sub(r"\s+", "", saml_art))
    if len(raw) != 44 or int.from_bytes(raw[0:2], "big") != 0x0004:
        raise SamlError("artifact", "SAMLart is not a SAML 2.0 type 0x0004 artifact")
    return {"endpoint_index": int.from_bytes(raw[2:4], "big"), "source_id": raw[4:24]}


def resolve_artifact(data: dict) -> dict:
    import os
    parsed = parse_artifact(data["artifact"])
    expected = hashlib.sha1(data["idp_entity_id"].encode("utf-8")).digest()
    if parsed["source_id"] != expected:
        raise SamlError("artifact", f"the artifact was not issued by {data['idp_entity_id']}")
    services: dict[int, str] = data["artifact_resolution_services"]
    location = services.get(parsed["endpoint_index"])
    if location is None and parsed["endpoint_index"] == 0 and services:
        location = next(iter(services.values()))
    if not location:
        raise SamlError("artifact", f"the identity provider's metadata has no SOAP ArtifactResolutionService with index {parsed['endpoint_index']}")
    element_id = new_id(os.urandom(20).hex())
    unsigned = (
        f'<samlp:ArtifactResolve xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" ID="{element_id}" Version="2.0" '
        f'IssueInstant="{_iso()}" Destination="{escape_xml(location)}">'
        f'<saml:Issuer>{escape_xml(data["entity_id"])}</saml:Issuer>'
        f'<samlp:Artifact>{escape_xml(data["artifact"])}</samlp:Artifact>'
        "</samlp:ArtifactResolve>"
    )
    signed = sign_enveloped(unsigned, element_id, data["key"], data["certificate"])
    envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<soap:Envelope xmlns:soap="{NS["soap"]}"><soap:Body>{signed}</soap:Body></soap:Envelope>'
    )
    answer = send(location, method="POST", headers={
        "content-type": "text/xml; charset=utf-8",
        "soapaction": '"http://www.oasis-open.org/committees/security"',
        "accept": "text/xml",
    }, body=envelope, tls=data.get("tls") or {}, code="artifact")
    if answer.status != 200:
        raise SamlError("artifact", f"the artifact resolution service answered HTTP {answer.status}")
    root = parse_xml(answer.body, "the ArtifactResponse")
    assert_unique_ids(root)
    body = child(root, NS["soap"], "Body") if root.tag == f"{{{NS['soap']}}}Envelope" else None
    artifact_response = child(body, NS["samlp"], "ArtifactResponse") if body is not None else None
    if artifact_response is None:
        raise SamlError("artifact", "the artifact resolution service did not answer with a SOAP ArtifactResponse")
    xml = answer.body
    signed_response = verify_signed(artifact_response, data["idp_certificates"], "the ArtifactResponse")
    if signed_response is not None:
        xml = signed_response
        artifact_response = parse_xml(signed_response, "the signed ArtifactResponse")
    if attr(artifact_response, "InResponseTo") != element_id:
        raise SamlError("artifact", "the ArtifactResponse does not answer this ArtifactResolve")
    issuer = child(artifact_response, NS["saml"], "Issuer")
    if issuer is not None and text(issuer) != data["idp_entity_id"]:
        raise SamlError("artifact", f"the ArtifactResponse was issued by {text(issuer)}")
    status = child(artifact_response, NS["samlp"], "Status")
    code_el = child(status, NS["samlp"], "StatusCode") if status is not None else None
    code = attr(code_el, "Value") if code_el is not None else (attr(status, "Value") if status is not None else None)
    if code != STATUS_SUCCESS:
        raise SamlError("artifact", f"the artifact resolution failed: {code or 'no status'}")
    responses = children(artifact_response, NS["samlp"], "Response")
    if not responses:
        raise SamlError("artifact", "the identity provider did not resolve the artifact (unknown, expired, or already used)")
    return {"xml": xml, "response": responses[0]}
