# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Identity-provider metadata in, and this service provider's metadata out."""

from __future__ import annotations

from saml2_sp.errors import SamlError
from saml2_sp.x509util import certificate_pem, load_certificate
from saml2_sp.xml import BINDING, NS, attr, children, descendants, escape_xml, parse_xml, pem_body, text, to_pem

ENCRYPTION_METHODS = [
    "http://www.w3.org/2009/xmlenc11#aes256-gcm",
    "http://www.w3.org/2009/xmlenc11#aes128-gcm",
    "http://www.w3.org/2009/xmlenc11#rsa-oaep",
    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
]


class IdpMetadata:
    def __init__(self, entity_id: str, sso_urls: dict[str, str], artifact_resolution_services: dict[int, str],
                 signing_certificates: list, want_authn_requests_signed: bool) -> None:
        self.entity_id = entity_id
        self.sso_urls = sso_urls
        self.artifact_resolution_services = artifact_resolution_services
        self.signing_certificates = signing_certificates
        self.want_authn_requests_signed = want_authn_requests_signed


def _certificates_of(role, use: str) -> list:
    out = []
    for descriptor in children(role, NS["md"], "KeyDescriptor"):
        declared = attr(descriptor, "use")
        if declared and declared != use:
            continue
        for data in descendants(descriptor, NS["ds"], "X509Data"):
            first = children(data, NS["ds"], "X509Certificate")
            if not first:
                continue
            try:
                out.append(load_certificate(to_pem(text(first[0]))))
            except Exception as err:
                raise SamlError("metadata", f"a {use} certificate in the identity provider's metadata cannot be read") from err
    return out


def read_idp_metadata(xml: str, entity_id: str | None = None) -> IdpMetadata:
    root = parse_xml(xml, "the identity provider metadata")
    entity = None
    if root.tag == f"{{{NS['md']}}}EntityDescriptor":
        entity = root
    elif root.tag == f"{{{NS['md']}}}EntitiesDescriptor":
        all_entities = [e for e in descendants(root, NS["md"], "EntityDescriptor") if descendants(e, NS["md"], "IDPSSODescriptor")]
        if entity_id:
            entity = next((e for e in all_entities if attr(e, "entityID") == entity_id), None)
        elif len(all_entities) == 1:
            entity = all_entities[0]
        if entity is None:
            if entity_id:
                raise SamlError("metadata", f"the metadata aggregate has no identity provider {entity_id}")
            raise SamlError("metadata", f"the metadata aggregate holds {len(all_entities)} identity providers; name one with idpEntityId")
    else:
        raise SamlError("metadata", "the identity provider metadata is not an EntityDescriptor")
    identifier = attr(entity, "entityID")
    if not identifier:
        raise SamlError("metadata", "the identity provider metadata has no entityID")
    if entity_id and identifier != entity_id:
        raise SamlError("metadata", f"the metadata describes {identifier}, not {entity_id}")
    roles = children(entity, NS["md"], "IDPSSODescriptor")
    if not roles:
        raise SamlError("metadata", f"{identifier}'s metadata has no IDPSSODescriptor")
    role = roles[0]
    sso_urls: dict[str, str] = {}
    for sso in children(role, NS["md"], "SingleSignOnService"):
        binding = attr(sso, "Binding")
        location = attr(sso, "Location")
        if not location:
            continue
        if binding == BINDING["redirect"] and "redirect" not in sso_urls:
            sso_urls["redirect"] = location
        if binding == BINDING["post"] and "post" not in sso_urls:
            sso_urls["post"] = location
    services: dict[int, str] = {}
    for ars in children(role, NS["md"], "ArtifactResolutionService"):
        location = attr(ars, "Location")
        if attr(ars, "Binding") == BINDING["soap"] and location:
            services[int(attr(ars, "index") or 0)] = location
    signing = _certificates_of(role, "signing")
    if not signing:
        raise SamlError("metadata", f"{identifier}'s metadata names no signing certificate")
    if "redirect" not in sso_urls and "post" not in sso_urls:
        raise SamlError("metadata", f"{identifier}'s metadata has no HTTP-Redirect or HTTP-POST SingleSignOnService")
    return IdpMetadata(identifier, sso_urls, services, signing, attr(role, "WantAuthnRequestsSigned") == "true")


def write_sp_metadata(entity_id: str, acs_url: str, certificate, want_assertions_signed: bool, name_id_format: str | None = None) -> str:
    cert = pem_body(certificate_pem(certificate))
    key_info = f"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
    methods = "".join(f'\n      <md:EncryptionMethod Algorithm="{method}"/>' for method in ENCRYPTION_METHODS)

    def key(use: str) -> str:
        extra = methods if use == "encryption" else ""
        return f'    <md:KeyDescriptor use="{use}">\n      {key_info}{extra}\n    </md:KeyDescriptor>'

    acs = escape_xml(acs_url)
    name_id = f"\n    <md:NameIDFormat>{escape_xml(name_id_format)}</md:NameIDFormat>" if name_id_format else ""
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="{NS["md"]}" xmlns:ds="{NS["ds"]}" entityID="{escape_xml(entity_id)}">
  <md:SPSSODescriptor protocolSupportEnumeration="{NS["samlp"]}" AuthnRequestsSigned="true" WantAssertionsSigned="{str(want_assertions_signed).lower()}">
{key("signing")}
{key("encryption")}{name_id}
    <md:AssertionConsumerService Binding="{BINDING["post"]}" Location="{acs}" index="0" isDefault="true"/>
    <md:AssertionConsumerService Binding="{BINDING["redirect"]}" Location="{acs}" index="1"/>
    <md:AssertionConsumerService Binding="{BINDING["artifact"]}" Location="{acs}" index="2"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
'''
