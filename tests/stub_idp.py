# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""A stub SAML identity provider. Signatures and decryption use cryptography, not a SAML toolkit."""

from __future__ import annotations

import base64
import hashlib
import os
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from saml2_sp.signature import sign_enveloped, verify_signed
from saml2_sp.xml import NS, parse_xml
from saml2_sp.x509util import certificate_pem, create_self_signed_key_pair, load_certificate, private_key_pem

_SP = create_self_signed_key_pair("sp.test", 30, 2048)
_IDP = create_self_signed_key_pair("idp.test", 30, 2048)

SP_KEY = _SP.private_key_pem
SP_CERT = _SP.certificate_pem
IDP_KEY = _IDP.private_key_pem
IDP_CERT = _IDP.certificate_pem
SP_PRIVATE = _SP.private_key
SP_CERTIFICATE = _SP.certificate
IDP_PRIVATE = _IDP.private_key
IDP_CERTIFICATE = _IDP.certificate

IDP_ENTITY = "https://idp.test/saml2"
SP_ENTITY = "https://sp.test/saml/metadata"
ACS = "https://sp.test/saml/acs"


def _iso(offset_ms: int) -> str:
    when = datetime.now(timezone.utc) + timedelta(milliseconds=offset_ms)
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"


def _id() -> str:
    return f"_{os.urandom(16).hex()}"


def _pem_body(pem: str) -> str:
    return "".join(line for line in pem.splitlines() if not line.startswith("-----"))


def idp_metadata(ars_url: str = "https://idp.test/saml2/ars") -> str:
    return (
        f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{IDP_ENTITY}">'
        '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">'
        f'<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{_pem_body(IDP_CERT)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
        f'<md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="{ars_url}" index="0" isDefault="true"/>'
        '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/saml2/sso"/>'
        '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.test/saml2/sso"/>'
        "</md:IDPSSODescriptor></md:EntityDescriptor>"
    )


def assertion_xml(options: dict | None = None) -> dict:
    o = options or {}
    aid = _id()
    irt = f' InResponseTo="{o["in_response_to"]}"' if o.get("in_response_to") else ""
    xml = (
        f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}" Version="2.0" IssueInstant="{_iso(0)}">'
        f'<saml:Issuer>{o.get("issuer") or IDP_ENTITY}</saml:Issuer>'
        f'<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{o.get("name_id") or "alice-1234"}</saml:NameID>'
        f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData Recipient="{o.get("recipient") or ACS}" NotOnOrAfter="{_iso(o.get("not_on_or_after_ms", 300_000))}"{irt}/>'
        "</saml:SubjectConfirmation></saml:Subject>"
        f'<saml:Conditions NotBefore="{_iso(-5000)}" NotOnOrAfter="{_iso(o.get("not_on_or_after_ms", 300_000))}">'
        f'<saml:AudienceRestriction><saml:Audience>{o.get("audience") or SP_ENTITY}</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
        f'<saml:AuthnStatement AuthnInstant="{_iso(-1000)}" SessionIndex="_session1"><saml:AuthnContext>'
        "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>"
        "</saml:AuthnContext></saml:AuthnStatement>"
        '<saml:AttributeStatement><saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" FriendlyName="mail">'
        "<saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>"
        '<saml:Attribute Name="groups"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>'
        f'{o.get("extra_attributes") or ""}</saml:AttributeStatement></saml:Assertion>'
    )
    return {"xml": xml, "id": aid}


def sign_xml(xml: str, element_id: str, key=IDP_PRIVATE, cert=IDP_CERTIFICATE) -> str:
    return sign_enveloped(xml, element_id, key, cert)


def signed_assertion(options: dict | None = None) -> dict:
    made = assertion_xml(options)
    return {"xml": sign_xml(made["xml"], made["id"]), "id": made["id"]}


def encrypt_assertion(assertion: str, cipher: str = "aes-256-gcm", transport: str = "mgf1p", wrapper: str = "EncryptedAssertion") -> str:
    key = os.urandom(32 if cipher == "aes-256-gcm" else 16)
    if cipher == "aes-256-gcm":
        iv = os.urandom(12)
        blob = iv + AESGCM(key).encrypt(iv, assertion.encode("utf-8"), None)
        alg = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
    else:
        iv = os.urandom(16)
        pad = 16 - (len(assertion.encode("utf-8")) % 16)
        padded = assertion.encode("utf-8") + bytes([pad]) * pad
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        blob = iv + encryptor.update(padded) + encryptor.finalize()
        alg = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
    digest = hashes.SHA1() if transport == "mgf1p" else hashes.SHA256()
    public = SP_CERTIFICATE.public_key()
    wrapped = public.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=digest), algorithm=digest, label=None))
    if transport == "mgf1p":
        key_method = '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>'
    else:
        key_method = (
            '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">'
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            '<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/>'
            "</xenc:EncryptionMethod>"
        )
    return (
        f'<saml:{wrapper} xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">'
        f'<xenc:EncryptionMethod Algorithm="{alg}"/>'
        f'<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey>{key_method}'
        f"<xenc:CipherData><xenc:CipherValue>{base64.b64encode(wrapped).decode()}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>"
        f"<xenc:CipherData><xenc:CipherValue>{base64.b64encode(blob).decode()}</xenc:CipherValue></xenc:CipherData>"
        f"</xenc:EncryptedData></saml:{wrapper}>"
    )


def response_xml(options: dict | None = None) -> str:
    o = options or {}
    rid = _id()
    irt = f' InResponseTo="{o["in_response_to"]}"' if o.get("in_response_to") else ""
    dest = "" if o.get("destination") is None and "destination" in o else f' Destination="{ACS if "destination" not in o else o["destination"]}"'
    status = o.get("status") or "urn:oasis:names:tc:SAML:2.0:status:Success"
    if "assertion" in o:
        assertion = o["assertion"]
    elif status.endswith("Success"):
        assertion = signed_assertion({"in_response_to": o.get("in_response_to")})["xml"]
    else:
        assertion = ""
    xml = (
        f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{rid}" Version="2.0" IssueInstant="{_iso(0)}"{dest}{irt}>'
        f'<saml:Issuer>{o.get("issuer") or IDP_ENTITY}</saml:Issuer>'
        f'<samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status>'
        f"{assertion}</samlp:Response>"
    )
    return sign_xml(xml, rid) if o.get("sign") else xml


def redirect_response_query(xml: str, relay_state: str | None = None, key=IDP_PRIVATE) -> str:
    from saml2_sp.bindings import deflate_raw, uri_escape
    from saml2_sp.signature import RSA_SHA256
    parts = [f"SAMLResponse={uri_escape(base64.b64encode(deflate_raw(xml.encode())).decode())}"]
    if relay_state:
        parts.append(f"RelayState={uri_escape(relay_state)}")
    parts.append(f"SigAlg={uri_escape(RSA_SHA256)}")
    signature = base64.b64encode(key.sign("&".join(parts).encode(), padding.PKCS1v15(), hashes.SHA256())).decode()
    return f"{'&'.join(parts)}&Signature={uri_escape(signature)}"


def artifact_for(entity_id: str = IDP_ENTITY) -> str:
    out = bytearray(44)
    out[0:2] = (4).to_bytes(2, "big")
    out[2:4] = (0).to_bytes(2, "big")
    out[4:24] = hashlib.sha1(entity_id.encode()).digest()
    out[24:44] = os.urandom(20)
    return base64.b64encode(out).decode()


class _Ars:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.resolved: list[str] = []
        self.url = ""
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def put(self, artifact: str, response: str) -> None:
        self.store[artifact] = response

    def close(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._thread.join(timeout=5)


def start_ars() -> _Ars:
    holder = _Ars()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("content-length") or 0)
            text = self.rfile.read(length).decode("utf-8", "replace")
            ok = False
            resolve_id = ""
            artifact = ""
            try:
                root = parse_xml(text, "the ArtifactResolve")
                body = root.find(f".//{{{NS['samlp']}}}ArtifactResolve")
                if body is not None:
                    resolve_id = body.get("ID") or ""
                    art = body.find(f"{{{NS['samlp']}}}Artifact")
                    artifact = "".join(art.itertext()).strip() if art is not None else ""
                    signed = verify_signed(body, [SP_CERTIFICATE], "the ArtifactResolve")
                    ok = signed is not None
            except Exception:
                ok = False
            message = holder.store.get(artifact) if ok else None
            holder.store.pop(artifact, None)
            if message:
                holder.resolved.append(artifact)
            answer = (
                '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
                f'<samlp:ArtifactResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
                f'ID="{_id()}" Version="2.0" IssueInstant="{_iso(0)}" InResponseTo="{resolve_id}">'
                f"<saml:Issuer>{IDP_ENTITY}</saml:Issuer>"
                '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
                f"{message or ''}</samlp:ArtifactResponse></soap:Body></soap:Envelope>"
            )
            payload = answer.encode()
            self.send_response(200)
            self.send_header("content-type", "text/xml")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    holder._httpd = httpd
    holder._thread = thread
    holder.url = f"http://127.0.0.1:{httpd.server_address[1]}/ars"
    return holder


def load_pem_key(pem: str):
    return serialization.load_pem_private_key(pem.encode(), password=None)


def load_pem_cert(pem: str):
    return load_certificate(pem)
