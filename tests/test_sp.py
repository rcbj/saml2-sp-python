# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The service provider against the stub identity provider, on every binding."""

from __future__ import annotations

import base64
import re

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from saml2_sp import SamlError, ServiceProvider
from saml2_sp.bindings import inflate_raw
from saml2_sp.xml import parse_xml
from stub_idp import (
    ACS,
    IDP_CERTIFICATE,
    IDP_ENTITY,
    SP_CERT,
    SP_CERTIFICATE,
    SP_ENTITY,
    SP_KEY,
    SP_PRIVATE,
    artifact_for,
    assertion_xml,
    encrypt_assertion,
    idp_metadata,
    redirect_response_query,
    response_xml,
    sign_xml,
    signed_assertion,
    start_ars,
)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def config(extra: dict | None = None, ars_url: str | None = None) -> dict:
    out = {
        "entityId": SP_ENTITY,
        "acsUrl": ACS,
        "privateKey": SP_KEY,
        "certificate": SP_CERT,
        "idpMetadata": idp_metadata(ars_url or "https://idp.test/saml2/ars"),
    }
    out.update(extra or {})
    return out


def post(sp: ServiceProvider, xml: str, request_id, relay_state: str | None = None):
    body = {"SAMLResponse": _b64(xml)}
    if relay_state:
        body["RelayState"] = relay_state
    return sp.acs("POST", "/saml/acs", body, request_id=request_id)


def rejects(fn, code: str, pattern: str | None = None) -> None:
    with pytest.raises(SamlError) as caught:
        fn()
    assert caught.value.code == code, str(caught.value)
    if pattern:
        assert re.search(pattern, str(caught.value))


def test_refuses_a_configuration_without_a_key_or_with_another_certificate():
    bad = config()
    bad["privateKey"] = None
    rejects(lambda: ServiceProvider.create(bad), "config", "privateKey")
    rejects(lambda: ServiceProvider.create(config({"certificate": idp_metadata() and open_cert()})), "config", "not for the private key")


def open_cert() -> str:
    from stub_idp import IDP_CERT
    return IDP_CERT


def test_reads_the_identity_provider_from_its_metadata():
    sp = ServiceProvider.create(config())
    assert sp.idp.entity_id == IDP_ENTITY
    assert sp.idp.sso_urls["redirect"] == "https://idp.test/saml2/sso"
    assert len(sp.idp.signing_certificates) == 1


def test_writes_metadata_with_a_signed_requests_key_and_the_acs_on_all_three_bindings():
    sp = ServiceProvider.create(config())
    xml = sp.metadata()
    root = parse_xml(xml, "metadata")
    acs = root.findall(".//{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService")
    assert [item.get("Binding").split(":")[-1] for item in acs] == ["HTTP-POST", "HTTP-Redirect", "HTTP-Artifact"]
    assert all(item.get("Location") == ACS for item in acs)
    assert re.search(r'AuthnRequestsSigned="true"', xml)
    assert re.search(r'<md:KeyDescriptor use="encryption">[\s\S]*xmlenc11#aes256-gcm[\s\S]*</md:KeyDescriptor>', xml)


def test_omits_signals_unless_it_is_false():
    sp = ServiceProvider.create(config())
    assert "signals" not in sp.config
    assert sp.config.entity_id == SP_ENTITY
    assert sp.config.acs_url == ACS
    assert sp.config.request_binding == "redirect"
    assert sp.config.response_binding == "post"
    explicit = ServiceProvider.create(config({"signals": True}))
    assert "signals" not in explicit.config
    assert explicit.config.entity_id == sp.config.entity_id
    assert explicit.config.acs_url == sp.config.acs_url


def test_records_signals_false_and_still_resolves_the_saml_fields():
    sp = ServiceProvider.create(config({"signals": False, "wantAssertionsEncrypted": True}))
    assert sp.config.signals is False
    assert sp.config.entity_id == SP_ENTITY
    assert sp.config.acs_url == ACS
    assert sp.config.request_binding == "redirect"
    assert sp.config.response_binding == "post"
    assert sp.config.want_assertions_signed is True
    assert sp.config.want_assertions_encrypted is True
    assert sp.config.allow_unsolicited is False
    assert sp.config.clock_skew_ms == 60_000
    assert sp.idp.entity_id == IDP_ENTITY


def test_refuses_a_signals_value_that_is_not_true_or_false():
    rejects(lambda: ServiceProvider.create(config({"signals": "no"})), "config", r"^signals must be true or false$")


def test_redirect_authn_request_is_deflated_and_signed():
    sp = ServiceProvider.create(config())
    req = sp.login(relay_state="/home")
    assert req.binding == "redirect"
    raw = req.url.split("?", 1)[1]
    signed_part, sig_part = raw.split("&Signature=")
    from urllib.parse import unquote
    SP_CERTIFICATE.public_key().verify(
        base64.b64decode(unquote(sig_part)),
        signed_part.encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    from urllib.parse import parse_qs
    query = parse_qs(raw, keep_blank_values=True)
    xml = inflate_raw(base64.b64decode(query["SAMLRequest"][0])).decode()
    assert f'ID="{req.id}"' in xml
    assert 'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"' in xml
    assert 'Destination="https://idp.test/saml2/sso"' in xml
    assert query["RelayState"][0] == "/home"
    assert req.url.startswith("https://idp.test/saml2/sso?")


def test_post_authn_request_is_an_enveloped_signature_in_a_form():
    sp = ServiceProvider.create(config({"requestBinding": "post"}))
    req = sp.login(response_binding="artifact", nonce="abc")
    assert req.binding == "post"
    xml = base64.b64decode(req.fields["SAMLRequest"]).decode()
    assert re.search(r"<saml:Issuer>[^<]+</saml:Issuer><ds:Signature", xml)
    assert "HTTP-Artifact" in xml
    root = parse_xml(xml, "the AuthnRequest")
    assert verify_ok(root, SP_CERTIFICATE)
    assert re.search(r'<script nonce="abc">', req.html)
    assert re.search(r'<button type="submit">', req.html)


def verify_ok(root, cert) -> bool:
    from saml2_sp.signature import verify_signed
    signed = verify_signed(root, [cert], "the message")
    return signed is not None


def test_subject_hint_follows_the_issuer_and_its_signature():
    sp = ServiceProvider.create(config({"requestBinding": "post"}))
    req = sp.login(
        subject_hint="alice<&>",
        subject_hint_format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        force_authn=True,
    )
    xml = base64.b64decode(req.fields["SAMLRequest"]).decode()
    assert re.search(
        r'</ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice&lt;&amp;&gt;</saml:NameID></saml:Subject><samlp:NameIDPolicy',
        xml,
    )
    assert 'ForceAuthn="true"' in xml
    assert verify_ok(parse_xml(xml, "the AuthnRequest"), SP_CERTIFICATE)
    assert "<saml:Subject>" not in sp.login().xml


def test_refuses_a_relay_state_over_80_bytes():
    sp = ServiceProvider.create(config())
    with pytest.raises(SamlError, match="80 bytes"):
        sp.login(relay_state="x" * 81)


def test_signed_response_and_signed_assertion():
    sp = ServiceProvider.create(config())
    who = post(sp, response_xml({"in_response_to": "_req1", "sign": True}), "_req1", "/home")
    assert who.name_id == "alice-1234"
    assert who.name_id_format == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    assert who.session_index == "_session1"
    assert who.relay_state == "/home"
    assert who.binding == "post"
    assert who.attributes["groups"] == ["staff", "admins"]
    assert who.attributes["urn:oid:0.9.2342.19200300.100.1.3"] == ["alice@example.com"]
    assert who.attribute_friendly_names["urn:oid:0.9.2342.19200300.100.1.3"] == "mail"
    assert who.authn_context_class_ref == "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"


def test_accepts_a_signed_assertion_in_an_unsigned_response():
    sp = ServiceProvider.create(config())
    who = post(sp, response_xml({"in_response_to": "_req1"}), "_req1")
    assert who.name_id == "alice-1234"


def test_refuses_an_unsigned_assertion_by_default():
    sp = ServiceProvider.create(config())
    xml = response_xml({"in_response_to": "_r", "sign": True, "assertion": assertion_xml({"in_response_to": "_r"})["xml"]})
    rejects(lambda: post(sp, xml, "_r"), "validation", "not signed")
    lax = ServiceProvider.create(config({"wantAssertionsSigned": False}))
    assert post(lax, xml, "_r").name_id == "alice-1234"


def test_refuses_a_response_with_nothing_signed():
    sp = ServiceProvider.create(config({"wantAssertionsSigned": False}))
    xml = response_xml({"in_response_to": "_r", "assertion": assertion_xml({"in_response_to": "_r"})["xml"]})
    rejects(lambda: post(sp, xml, "_r"), "validation", "neither")


def test_refuses_an_assertion_altered_after_it_was_signed():
    sp = ServiceProvider.create(config())
    xml = response_xml({"in_response_to": "_r"}).replace("alice-1234", "mallory")
    rejects(lambda: post(sp, xml, "_r"), "signature")


def test_refuses_a_signature_by_another_key():
    sp = ServiceProvider.create(config())
    made = assertion_xml({"in_response_to": "_r"})
    xml = response_xml({"in_response_to": "_r", "assertion": sign_xml(made["xml"], made["id"], SP_PRIVATE, SP_CERTIFICATE)})
    rejects(lambda: post(sp, xml, "_r"), "signature", "does not verify")


def test_is_not_fooled_by_signature_wrapping():
    sp = ServiceProvider.create(config())
    signed = signed_assertion({"in_response_to": "_r"})
    forged = assertion_xml({"in_response_to": "_r", "name_id": "mallory"})["xml"]
    rejects(lambda: post(sp, response_xml({"in_response_to": "_r", "assertion": forged + signed["xml"]}), "_r"), "validation", "exactly one")
    hidden = re.sub(r'ID="[^"]+"', f'ID="{signed["id"]}"', forged, count=1).replace(
        "</saml:Assertion>", f"<saml:Advice>{signed['xml']}</saml:Advice></saml:Assertion>"
    )
    rejects(lambda: post(sp, response_xml({"in_response_to": "_r", "assertion": hidden}), "_r"), "signature", "two elements")
    sig_xml = re.search(r"<ds:Signature[\s\S]*</ds:Signature>", signed["xml"]).group(0)
    moved = re.sub(r"(</saml:Issuer>)", rf"\1{sig_xml}", forged, count=1)
    rejects(lambda: post(sp, response_xml({"in_response_to": "_r", "assertion": moved}), "_r"), "signature", "refers to")


def test_refuses_a_response_for_another_audience_acs_or_that_has_expired():
    sp = ServiceProvider.create(config())
    rejects(lambda: post(sp, response_xml({"in_response_to": "_r", "assertion": signed_assertion({"in_response_to": "_r", "audience": "https://other.test"})["xml"]}), "_r"), "validation", "not for")
    rejects(lambda: post(sp, response_xml({"in_response_to": "_r", "assertion": signed_assertion({"in_response_to": "_r", "recipient": "https://other.test/acs"})["xml"]}), "_r"), "validation", "Recipient")
    rejects(lambda: post(sp, response_xml({"in_response_to": "_r", "assertion": signed_assertion({"in_response_to": "_r", "not_on_or_after_ms": -120_000})["xml"]}), "_r"), "validation", "expired")
    rejects(lambda: post(sp, response_xml({"in_response_to": "_r", "destination": "https://other.test/acs"}), "_r"), "validation", "addressed to")
    rejects(lambda: post(sp, response_xml({"in_response_to": "_r", "assertion": signed_assertion({"in_response_to": "_r", "issuer": "https://evil.test"})["xml"]}), "_r"), "validation", "issued by")


def test_refuses_an_answer_to_another_request_and_an_unsolicited_one():
    sp = ServiceProvider.create(config())
    rejects(lambda: post(sp, response_xml({"in_response_to": "_r"}), "_other"), "validation", "not a request this browser")
    rejects(lambda: post(sp, response_xml({"in_response_to": "_r"}), None), "validation", "not a request this browser")
    rejects(lambda: post(sp, response_xml({}), None), "validation", "unsolicited")
    open_sp = ServiceProvider.create(config({"allowUnsolicited": True}))
    assert post(open_sp, response_xml({}), None).in_response_to is None


def test_refuses_the_same_assertion_twice():
    sp = ServiceProvider.create(config())
    xml = response_xml({"in_response_to": "_r", "sign": True})
    post(sp, xml, "_r")
    rejects(lambda: post(sp, xml, "_r"), "replay")


def test_reports_a_non_success_status():
    sp = ServiceProvider.create(config())
    with pytest.raises(SamlError) as caught:
        post(sp, response_xml({"in_response_to": "_r", "status": "urn:oasis:names:tc:SAML:2.0:status:Responder"}), "_r")
    assert caught.value.code == "status"
    assert caught.value.status.code == "urn:oasis:names:tc:SAML:2.0:status:Responder"


def test_refuses_a_doctype():
    sp = ServiceProvider.create(config())
    xml = f'<!DOCTYPE x [<!ENTITY e "x">]>{response_xml({"in_response_to": "_r"})}'
    rejects(lambda: post(sp, xml, "_r"), "xml", "DOCTYPE")


def test_decrypts_an_encrypted_assertion():
    sp = ServiceProvider.create(config())
    for cipher in ("aes-256-gcm", "aes-128-cbc"):
        made = signed_assertion({"in_response_to": "_r"})
        who = post(sp, response_xml({"in_response_to": "_r", "sign": True, "assertion": encrypt_assertion(made["xml"], cipher)}), "_r")
        assert who.name_id == "alice-1234"
        assert who.encrypted is True
    made = signed_assertion({"in_response_to": "_r"})
    who = post(sp, response_xml({"in_response_to": "_r", "assertion": encrypt_assertion(made["xml"], "aes-256-gcm", "oaep256")}), "_r")
    assert who.name_id == "alice-1234"


def test_refuses_a_plaintext_assertion_when_encryption_is_required():
    sp = ServiceProvider.create(config({"wantAssertionsEncrypted": True}))
    rejects(lambda: post(sp, response_xml({"in_response_to": "_r", "sign": True}), "_r"), "validation", "not encrypted")
    made = signed_assertion({"in_response_to": "_r"})
    assert post(sp, response_xml({"in_response_to": "_r", "assertion": encrypt_assertion(made["xml"])}), "_r").encrypted is True


def test_refuses_an_encrypted_assertion_whose_ciphertext_was_altered():
    sp = ServiceProvider.create(config())
    enc = encrypt_assertion(signed_assertion({"in_response_to": "_r"})["xml"])
    values = re.findall(r"<xenc:CipherValue>([^<]+)</xenc:CipherValue>", enc)
    last = values[-1]
    blob = bytearray(base64.b64decode(last))
    blob[20] ^= 1
    rejects(lambda: post(sp, response_xml({"in_response_to": "_r", "assertion": enc.replace(last, base64.b64encode(blob).decode())}), "_r"), "decryption")


def test_decrypts_an_encrypted_attribute():
    sp = ServiceProvider.create(config())
    secret = encrypt_assertion(
        '<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="employeeNumber"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>',
        "aes-256-gcm",
        "oaep256",
        "EncryptedAttribute",
    )
    made = assertion_xml({"in_response_to": "_r", "extra_attributes": secret})
    who = post(sp, response_xml({"in_response_to": "_r", "assertion": sign_xml(made["xml"], made["id"])}), "_r")
    assert who.attributes["employeeNumber"] == ["E-42"]


def test_redirect_response_verifies_the_query_signature():
    sp = ServiceProvider.create(config())
    query = redirect_response_query(response_xml({"in_response_to": "_r"}), "/there")
    who = sp.acs("GET", f"/saml/acs?{query}", request_id="_r")
    assert who.binding == "redirect"
    assert who.relay_state == "/there"


def test_refuses_a_query_signature_by_another_key_and_a_changed_relay_state():
    sp = ServiceProvider.create(config())
    forged = redirect_response_query(response_xml({"in_response_to": "_r"}), "/x", SP_PRIVATE)
    rejects(lambda: sp.acs("GET", f"/saml/acs?{forged}", request_id="_r"), "signature")
    changed = redirect_response_query(response_xml({"in_response_to": "_r"}), "/x").replace("RelayState=%2Fx", "RelayState=%2Fy")
    rejects(lambda: sp.acs("GET", f"/saml/acs?{changed}", request_id="_r"), "signature")


@pytest.fixture(scope="module")
def ars():
    server = start_ars()
    yield server
    server.close()


def test_resolves_the_artifact(ars):
    sp = ServiceProvider.create(config({"responseBinding": "artifact"}, ars.url))
    req = sp.login()
    assert "HTTP-Artifact" in req.xml
    artifact = artifact_for()
    ars.put(artifact, response_xml({"in_response_to": req.id}))
    from urllib.parse import quote
    who = sp.acs("GET", f"/saml/acs?SAMLart={quote(artifact, safe='')}&RelayState=%2Fa", request_id=req.id)
    assert who.binding == "artifact"
    assert who.relay_state == "/a"
    assert who.name_id == "alice-1234"
    assert ars.resolved == [artifact]


def test_accepts_the_artifact_on_a_post_and_fails_when_already_used(ars):
    sp = ServiceProvider.create(config({}, ars.url))
    artifact = artifact_for()
    ars.put(artifact, response_xml({"in_response_to": "_r"}))
    from urllib.parse import quote
    who = sp.acs("POST", "/saml/acs", f"SAMLart={quote(artifact, safe='')}", request_id="_r")
    assert who.binding == "artifact"
    rejects(lambda: sp.acs("POST", "/saml/acs", {"SAMLart": artifact}, request_id="_r"), "artifact", "did not resolve")


def test_refuses_an_artifact_from_another_identity_provider(ars):
    sp = ServiceProvider.create(config({}, ars.url))
    from urllib.parse import quote
    rejects(
        lambda: sp.acs("GET", f"/saml/acs?SAMLart={quote(artifact_for('https://evil.test'), safe='')}", request_id="_r"),
        "artifact",
        "not issued by",
    )


def test_refuses_a_request_with_no_saml_message():
    sp = ServiceProvider.create(config())
    rejects(lambda: sp.acs("GET", "/saml/acs"), "binding")


def test_unused_imports_stay_available():
    assert IDP_CERTIFICATE and SP_KEY
