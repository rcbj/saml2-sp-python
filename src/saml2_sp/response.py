# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Validating a samlp:Response under the Web Browser SSO profile."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from lxml import etree

from saml2_sp.encryption import decrypt_element
from saml2_sp.errors import SamlError, SamlStatus
from saml2_sp.signature import verify_signed
from saml2_sp.xml import CM_BEARER, NS, STATUS_SUCCESS, assert_unique_ids, attr, child, children, parse_xml, text

_DATETIME = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class SamlLogin:
    def __init__(self, **fields: object) -> None:
        self.__dict__.update(fields)

    def __repr__(self) -> str:
        return f"SamlLogin({self.__dict__!r})"


def _ms(when: datetime) -> int:
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    delta = when - _EPOCH
    return delta.days * 86_400_000 + delta.seconds * 1000 + delta.microseconds // 1000


def _invalid(message: str) -> None:
    raise SamlError("validation", message)


def _instant(value: str | None, what: str) -> datetime | None:
    if value is None:
        return None
    if not _DATETIME.match(value):
        _invalid(f"{what} is not a UTC dateTime: {value}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _invalid(f"{what} is not a dateTime: {value}")
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _issuer_of(el: etree._Element, required: bool, expected: str, what: str) -> None:
    issuer = child(el, NS["saml"], "Issuer")
    if issuer is None:
        if required:
            _invalid(f"{what} has no Issuer")
        return
    form = attr(issuer, "Format")
    if form and form != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity":
        _invalid(f"{what}'s Issuer has the Format {form}")
    if text(issuer) != expected:
        _invalid(f"{what} was issued by {text(issuer)}, not by {expected}")


def _status_of(response: etree._Element) -> SamlStatus:
    status = child(response, NS["samlp"], "Status")
    if status is None:
        _invalid("the Response has no Status")
    top = child(status, NS["samlp"], "StatusCode")
    if top is None:
        _invalid("the Response has no StatusCode")
    sub = child(top, NS["samlp"], "StatusCode")
    out = SamlStatus(attr(top, "Value") or "")
    if sub is not None and attr(sub, "Value"):
        out.sub_code = attr(sub, "Value")
    message = text(child(status, NS["samlp"], "StatusMessage"))
    if message:
        out.message = message
    return out


def validate_response(received: dict, ctx: dict) -> SamlLogin:
    now = _ms(ctx.get("now") or datetime.now(timezone.utc))
    skew = ctx["clock_skew_ms"]
    response: etree._Element = received["response"]
    root = response.getroottree().getroot()
    assert_unique_ids(root)
    if response.tag != f"{{{NS['samlp']}}}Response":
        _invalid(f"the message is a <{etree.QName(response).localname}>, not a Response")
    signed = verify_signed(response, ctx["idp_certificates"], "the Response")
    if signed is not None:
        response = parse_xml(signed, "the signed Response")
    response_authenticated = signed is not None or received["authenticated_by_binding"]
    if attr(response, "Version") != "2.0":
        _invalid(f"the Response is version {attr(response, 'Version') or '(none)'}, not 2.0")
    response_id = attr(response, "ID") or (_invalid("the Response has no ID") or "")
    _issuer_of(response, False, ctx["idp_entity_id"], "the Response")
    destination = attr(response, "Destination")
    if destination is not None and destination != ctx["acs_url"]:
        _invalid(f"the Response is addressed to {destination}, not to {ctx['acs_url']}")
    if destination is None and response_authenticated and received["binding"] != "artifact":
        _invalid("the Response is signed but has no Destination")
    in_response_to = attr(response, "InResponseTo")
    expected = list(ctx["expected_request_ids"])
    if in_response_to is not None:
        if in_response_to not in expected:
            _invalid(f"the Response answers {in_response_to}, which is not a request this browser has outstanding")
    elif not ctx["allow_unsolicited"]:
        _invalid("the Response is unsolicited (it has no InResponseTo), and unsolicited Responses are not accepted")
    status = _status_of(response)
    if status.code != STATUS_SUCCESS:
        detail = status.sub_code or status.code
        suffix = f": {status.message}" if status.message else ""
        raise SamlError("status", f"the identity provider answered {detail}{suffix}", status=status)

    plain = children(response, NS["saml"], "Assertion")
    encrypted = children(response, NS["saml"], "EncryptedAssertion")
    if len(plain) + len(encrypted) != 1:
        _invalid(f"the Response holds {len(plain) + len(encrypted)} assertions; exactly one is accepted")
    if encrypted:
        assertion_xml = decrypt_element(encrypted[0], ctx["decryption_key"])
        doc = parse_xml(assertion_xml, "the decrypted assertion")
        assert_unique_ids(doc)
        assertion = doc
        if assertion.tag != f"{{{NS['saml']}}}Assertion":
            _invalid("the EncryptedAssertion does not hold an Assertion")
    else:
        if ctx["want_assertions_encrypted"]:
            _invalid("the assertion is not encrypted, and wantAssertionsEncrypted is on")
        assertion = plain[0]
        assertion_xml = None
    signed_assertion = verify_signed(assertion, ctx["idp_certificates"], "the assertion")
    if signed_assertion is not None:
        assertion = parse_xml(signed_assertion, "the signed assertion")
    elif ctx["want_assertions_signed"]:
        _invalid("the assertion is not signed, and wantAssertionsSigned is on")
    elif not response_authenticated:
        _invalid("neither the Response nor its assertion is signed")

    if attr(assertion, "Version") != "2.0":
        _invalid("the assertion is not version 2.0")
    assertion_id = attr(assertion, "ID") or (_invalid("the assertion has no ID") or "")
    _issuer_of(assertion, True, ctx["idp_entity_id"], "the assertion")
    subject = child(assertion, NS["saml"], "Subject")
    if subject is None:
        _invalid("the assertion has no Subject")
    name_id_el = child(subject, NS["saml"], "NameID")
    encrypted_id = child(subject, NS["saml"], "EncryptedID")
    if name_id_el is None and encrypted_id is not None:
        name_id_el = parse_xml(decrypt_element(encrypted_id, ctx["decryption_key"]), "the decrypted NameID")
        if name_id_el.tag != f"{{{NS['saml']}}}NameID":
            _invalid("the EncryptedID does not hold a NameID")
    if name_id_el is None or not text(name_id_el):
        _invalid("the assertion's Subject has no NameID")

    reasons: list[str] = []
    confirmed_until: datetime | None = None
    for confirmation in children(subject, NS["saml"], "SubjectConfirmation"):
        if attr(confirmation, "Method") != CM_BEARER:
            reasons.append(f"method {attr(confirmation, 'Method')}")
            continue
        data = child(confirmation, NS["saml"], "SubjectConfirmationData")
        if data is None:
            reasons.append("no SubjectConfirmationData")
            continue
        recipient = attr(data, "Recipient")
        not_on_or_after = _instant(attr(data, "NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter")
        not_before = attr(data, "NotBefore")
        sc_in_response_to = attr(data, "InResponseTo")
        if recipient != ctx["acs_url"]:
            reasons.append(f"Recipient {recipient or '(none)'}")
        elif not_on_or_after is None:
            reasons.append("no NotOnOrAfter")
        elif _ms(not_on_or_after) <= now - skew:
            reasons.append(f"expired at {not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z")
        elif not_before is not None:
            reasons.append("a NotBefore, which a bearer confirmation must not have")
        elif sc_in_response_to != in_response_to:
            reasons.append(f"InResponseTo {sc_in_response_to or '(none)'}")
        else:
            confirmed_until = not_on_or_after
            break
    if confirmed_until is None:
        _invalid(f"no bearer SubjectConfirmation of the assertion fits: {'; '.join(reasons) or 'there is none'}")

    conditions = child(assertion, NS["saml"], "Conditions")
    if conditions is None:
        _invalid("the assertion has no Conditions, so it names no audience")
    not_before_c = _instant(attr(conditions, "NotBefore"), "Conditions NotBefore")
    not_on_or_after_c = _instant(attr(conditions, "NotOnOrAfter"), "Conditions NotOnOrAfter")
    if not_before_c and _ms(not_before_c) > now + skew:
        _invalid(f"the assertion is not valid before {not_before_c.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z")
    if not_on_or_after_c and _ms(not_on_or_after_c) <= now - skew:
        _invalid(f"the assertion expired at {not_on_or_after_c.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z")
    restrictions = children(conditions, NS["saml"], "AudienceRestriction")
    if not restrictions:
        _invalid("the assertion has no AudienceRestriction")
    for restriction in restrictions:
        if not any(text(audience) == ctx["entity_id"] for audience in children(restriction, NS["saml"], "Audience")):
            _invalid(f"the assertion is not for {ctx['entity_id']}")

    authn_statements = children(assertion, NS["saml"], "AuthnStatement")
    if not authn_statements:
        _invalid("the assertion has no AuthnStatement")
    authn = authn_statements[0]
    authn_instant = _instant(attr(authn, "AuthnInstant"), "AuthnInstant")
    if authn_instant is None:
        _invalid("the AuthnStatement has no AuthnInstant")
    session_not_on_or_after = _instant(attr(authn, "SessionNotOnOrAfter"), "SessionNotOnOrAfter")
    if session_not_on_or_after and _ms(session_not_on_or_after) <= now - skew:
        _invalid("the identity provider's session has already ended")
    context_el = child(authn, NS["saml"], "AuthnContext")
    class_ref = text(child(context_el, NS["saml"], "AuthnContextClassRef")) if context_el is not None else ""

    attributes: dict[str, list[str]] = {}
    friendly: dict[str, str] = {}
    for statement in children(assertion, NS["saml"], "AttributeStatement"):
        decrypted = []
        for enc in children(statement, NS["saml"], "EncryptedAttribute"):
            element = parse_xml(decrypt_element(enc, ctx["decryption_key"]), "the decrypted attribute")
            if element.tag != f"{{{NS['saml']}}}Attribute":
                _invalid("an EncryptedAttribute does not hold an Attribute")
            decrypted.append(element)
        for attribute in [*children(statement, NS["saml"], "Attribute"), *decrypted]:
            name = attr(attribute, "Name")
            if not name:
                continue
            values = ["".join(value.itertext()) for value in children(attribute, NS["saml"], "AttributeValue")]
            attributes.setdefault(name, []).extend(values)
            friend = attr(attribute, "FriendlyName")
            if friend:
                friendly[name] = friend

    keep_until_ms = max(_ms(confirmed_until), _ms(not_on_or_after_c) if not_on_or_after_c else 0) + skew
    keep_until = datetime.fromtimestamp(keep_until_ms / 1000, timezone.utc)
    if ctx["replay_cache"].check_and_record(f"{ctx['idp_entity_id']} {assertion_id}", keep_until):
        raise SamlError("replay", f"the assertion {assertion_id} has been accepted before")

    login = SamlLogin(
        name_id=text(name_id_el),
        name_id_format=attr(name_id_el, "Format"),
        name_qualifier=attr(name_id_el, "NameQualifier"),
        sp_name_qualifier=attr(name_id_el, "SPNameQualifier"),
        session_index=attr(authn, "SessionIndex"),
        session_not_on_or_after=session_not_on_or_after,
        authn_instant=authn_instant,
        authn_context_class_ref=class_ref or None,
        attributes=attributes,
        attribute_friendly_names=friendly,
        issuer=ctx["idp_entity_id"],
        in_response_to=in_response_to,
        relay_state=received.get("relay_state"),
        binding=received["binding"],
        encrypted=bool(encrypted),
        response_id=response_id,
        assertion_id=assertion_id,
    )
    return login
