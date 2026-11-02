# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""XML signatures. Exclusive canonicalization is lxml's; the cryptography is cryptography's.

Once a signature verifies, the element is read from the XML that was signed, never from a sibling
that arrived beside it. A signature is accepted only as an enveloped signature of its own parent.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree

from saml2_sp.errors import SamlError
from saml2_sp.xml import NS, attr, child, children, pem_body, q

EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
EXC_C14N_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
C14N_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

SIGNATURE_ALGORITHMS = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": "sha256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": "sha384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": "sha512",
}
DIGEST_ALGORITHMS = {
    "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512": "sha512",
}
TRANSFORMS = {ENVELOPED, EXC_C14N, EXC_C14N_COMMENTS, C14N, C14N_COMMENTS}
CANONICALIZATIONS = {EXC_C14N, EXC_C14N_COMMENTS, C14N, C14N_COMMENTS}
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"

_HASH = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}
_CRYPTO_HASH = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}


def is_signed(el: etree._Element) -> bool:
    return len(children(el, NS["ds"], "Signature")) > 0


def _algorithm(parent: etree._Element, local: str) -> str:
    found = child(parent, NS["ds"], local)
    if found is None:
        return ""
    return attr(found, "Algorithm") or ""


def _inclusive(transform: etree._Element) -> list[str] | None:
    for child_el in transform:
        if not isinstance(child_el.tag, str):
            continue
        name = etree.QName(child_el)
        if name.localname == "InclusiveNamespaces":
            return (child_el.get("PrefixList") or "").split()
    return None


def _c14n(el: etree._Element, algorithm: str, prefixes: list[str] | None = None) -> bytes:
    comments = algorithm.endswith("WithComments")
    exclusive = "xml-exc-c14n" in algorithm
    if exclusive:
        return etree.tostring(el, method="c14n", exclusive=True, with_comments=comments, inclusive_ns_prefixes=prefixes)
    return etree.tostring(el, method="c14n", exclusive=False, with_comments=comments)


def _apply_transforms(el: etree._Element, signature: etree._Element, transform_els: list[etree._Element]) -> bytes:
    node: etree._Element | None = el
    data: bytes | None = None
    if not transform_els:
        return _c14n(el, C14N)
    for index, transform in enumerate(transform_els):
        alg = attr(transform, "Algorithm") or ""
        if data is not None:
            node = etree.fromstring(data)
            data = None
        assert node is not None
        if alg == ENVELOPED:
            copied = etree.fromstring(etree.tostring(node))
            for sig in children(copied, NS["ds"], "Signature"):
                # The enveloped transform removes the Signature that contains this Reference.
                value = "".join(children(sig, NS["ds"], "SignatureValue")[0].itertext()) if children(sig, NS["ds"], "SignatureValue") else ""
                original = "".join(children(signature, NS["ds"], "SignatureValue")[0].itertext()) if children(signature, NS["ds"], "SignatureValue") else ""
                if value.replace(" ", "") == original.replace(" ", "") or sig.getparent() is copied:
                    sig.getparent().remove(sig)
                    break
            node = copied
            continue
        if alg in CANONICALIZATIONS:
            data = _c14n(node, alg, _inclusive(transform))
            node = None
            if index == len(transform_els) - 1:
                return data
            continue
        raise SamlError("signature", f"the signature uses the transform {alg or '(none)'}, which is refused")
    if data is not None:
        return data
    assert node is not None
    return _c14n(node, C14N)


def _element_by_id(root: etree._Element, element_id: str) -> etree._Element | None:
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        for name in ("ID", "Id", "id"):
            if el.get(name) == element_id:
                return el
    return None


def verify_signed(el: etree._Element, certs: list, what: str) -> str | None:
    sig_el = child(el, NS["ds"], "Signature")
    if sig_el is None:
        return None
    element_id = attr(el, "ID")
    if not element_id:
        raise SamlError("signature", f"{what} is signed but has no ID for the signature to refer to")
    signed_info = child(sig_el, NS["ds"], "SignedInfo")
    if signed_info is None:
        raise SamlError("signature", f"{what}'s signature has no SignedInfo")
    c14n_alg = _algorithm(signed_info, "CanonicalizationMethod")
    if c14n_alg not in CANONICALIZATIONS:
        raise SamlError("signature", f"{what}'s signature uses the canonicalization {c14n_alg or '(none)'}, which is refused")
    sig_alg = _algorithm(signed_info, "SignatureMethod")
    hash_name = SIGNATURE_ALGORITHMS.get(sig_alg)
    if not hash_name:
        raise SamlError("signature", f"{what}'s signature uses {sig_alg or '(none)'}, which is refused (SHA-1 and non-RSA algorithms are not accepted)")
    refs = children(signed_info, NS["ds"], "Reference")
    if len(refs) != 1:
        raise SamlError("signature", f"{what}'s signature has {len(refs)} references; exactly one is accepted")
    ref = refs[0]
    if attr(ref, "URI") != f"#{element_id}":
        raise SamlError("signature", f"{what}'s signature refers to {attr(ref, 'URI') or '(nothing)'}, not to {what} itself (#{element_id})")
    digest_alg = _algorithm(ref, "DigestMethod")
    digest_name = DIGEST_ALGORITHMS.get(digest_alg)
    if not digest_name:
        raise SamlError("signature", f"{what}'s signature digests with {digest_alg or '(none)'}, which is refused")
    transforms_el = child(ref, NS["ds"], "Transforms")
    transform_els = children(transforms_el, NS["ds"], "Transform") if transforms_el is not None else []
    for transform in transform_els:
        alg = attr(transform, "Algorithm") or ""
        if alg not in TRANSFORMS:
            raise SamlError("signature", f"{what}'s signature uses the transform {alg or '(none)'}, which is refused")
    if not certs:
        raise SamlError("signature", f"no signing certificate is known for the identity provider, so {what} cannot be verified")
    reference = _apply_transforms(el, sig_el, transform_els)
    digest_value = child(ref, NS["ds"], "DigestValue")
    try:
        got = base64.b64decode(re_compact(digest_value))
    except Exception as err:
        raise SamlError("signature", f"{what}'s signature does not verify against the identity provider's certificate: the digest is not base64") from err
    want = _HASH[digest_name](reference).digest()
    if not hmac.compare_digest(got, want):
        raise SamlError("signature", f"{what}'s signature does not verify against the identity provider's certificate: the signature does not verify")
    info_prefixes = None
    method = child(signed_info, NS["ds"], "CanonicalizationMethod")
    if method is not None:
        info_prefixes = _inclusive(method)
    signed_bytes = _c14n(signed_info, c14n_alg, info_prefixes)
    signature_value = child(sig_el, NS["ds"], "SignatureValue")
    try:
        sig_bytes = base64.b64decode(re_compact(signature_value))
    except Exception as err:
        raise SamlError("signature", f"{what}'s signature does not verify against the identity provider's certificate: the signature value is not base64") from err
    verified = False
    for cert in certs:
        try:
            cert.public_key().verify(sig_bytes, signed_bytes, padding.PKCS1v15(), _CRYPTO_HASH[hash_name])
            verified = True
            break
        except Exception:
            continue
    if not verified:
        raise SamlError("signature", f"{what}'s signature does not verify against the identity provider's certificate: the signature does not verify")
    copied = etree.fromstring(etree.tostring(el))
    for sig in list(children(copied, NS["ds"], "Signature")):
        copied.remove(sig)
    return _c14n(copied, EXC_C14N).decode("utf-8")


def re_compact(el: etree._Element | None) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def sign_enveloped(xml: str, element_id: str, key, certificate) -> str:
    from saml2_sp.xml import parse_xml

    root = parse_xml(xml, "the message to sign")
    target = _element_by_id(root, element_id)
    if target is None:
        raise SamlError("signature", f"no element has ID {element_id}")
    reference = etree.tostring(target, method="c14n", exclusive=True, with_comments=False)
    digest = base64.b64encode(hashlib.sha256(reference).digest()).decode("ascii")
    signature = _signature_element(element_id, digest, certificate)
    issuer = None
    for candidate in children(target, NS["saml"], "Issuer"):
        issuer = candidate
        break
    if issuer is not None:
        issuer.addnext(signature)
    else:
        target.insert(0, signature)
    signed_info = children(signature, NS["ds"], "SignedInfo")[0]
    signed_bytes = etree.tostring(signed_info, method="c14n", exclusive=True, with_comments=False)
    value = base64.b64encode(key.sign(signed_bytes, padding.PKCS1v15(), hashes.SHA256())).decode("ascii")
    children(signature, NS["ds"], "SignatureValue")[0].text = value
    return etree.tostring(root, encoding="unicode")


def _signature_element(element_id: str, digest: str, certificate) -> etree._Element:
    nsmap = {"ds": NS["ds"]}
    signature = etree.Element(q(NS["ds"], "Signature"), nsmap=nsmap)
    signed_info = etree.SubElement(signature, q(NS["ds"], "SignedInfo"))
    c14n = etree.SubElement(signed_info, q(NS["ds"], "CanonicalizationMethod"))
    c14n.set("Algorithm", EXC_C14N)
    method = etree.SubElement(signed_info, q(NS["ds"], "SignatureMethod"))
    method.set("Algorithm", RSA_SHA256)
    ref = etree.SubElement(signed_info, q(NS["ds"], "Reference"))
    ref.set("URI", f"#{element_id}")
    transforms = etree.SubElement(ref, q(NS["ds"], "Transforms"))
    enveloped = etree.SubElement(transforms, q(NS["ds"], "Transform"))
    enveloped.set("Algorithm", ENVELOPED)
    exc = etree.SubElement(transforms, q(NS["ds"], "Transform"))
    exc.set("Algorithm", EXC_C14N)
    digest_method = etree.SubElement(ref, q(NS["ds"], "DigestMethod"))
    digest_method.set("Algorithm", SHA256)
    digest_value = etree.SubElement(ref, q(NS["ds"], "DigestValue"))
    digest_value.text = digest
    etree.SubElement(signature, q(NS["ds"], "SignatureValue"))
    key_info = etree.SubElement(signature, q(NS["ds"], "KeyInfo"))
    data = etree.SubElement(key_info, q(NS["ds"], "X509Data"))
    cert = etree.SubElement(data, q(NS["ds"], "X509Certificate"))
    cert.text = _cert_body(certificate)
    return signature


def _cert_body(certificate) -> str:
    from saml2_sp.x509util import certificate_pem
    return pem_body(certificate_pem(certificate))
