# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""XML this package reads and writes. A DOCTYPE is refused before the parser sees it."""

from __future__ import annotations

import re

from lxml import etree

from saml2_sp.errors import SamlError

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
    "xenc11": "http://www.w3.org/2009/xmlenc11#",
    "soap": "http://schemas.xmlsoap.org/soap/envelope/",
}

BINDING = {
    "redirect": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
    "post": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    "artifact": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
    "soap": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
}

STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

_DOCTYPE = re.compile(r"<!DOCTYPE|<!ENTITY", re.IGNORECASE)


def q(ns: str, local: str) -> str:
    return f"{{{ns}}}{local}"


def local_name(el: etree._Element) -> str:
    if not isinstance(el.tag, str):
        return ""
    return etree.QName(el).localname


def parse_xml(text: str, what: str = "the message") -> etree._Element:
    if _DOCTYPE.search(text):
        raise SamlError("xml", f"{what} carries a DOCTYPE or an entity declaration, which SAML never needs")
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False, remove_blank_text=False)
    try:
        root = etree.fromstring(text.encode("utf-8"), parser)
    except etree.XMLSyntaxError as err:
        raise SamlError("xml", f"{what} is not well-formed XML: {err}") from err
    if root is None:
        raise SamlError("xml", f"{what} is not well-formed XML: no document element")
    return root


def serialize(node: etree._Element) -> str:
    return etree.tostring(node, encoding="unicode")


def children(el: etree._Element, ns: str, local: str) -> list[etree._Element]:
    want = q(ns, local)
    return [c for c in el if isinstance(c.tag, str) and c.tag == want]


def child(el: etree._Element, ns: str, local: str) -> etree._Element | None:
    found = children(el, ns, local)
    if len(found) > 1:
        raise SamlError("validation", f"<{local_name(el)}> has more than one <{local}>")
    return found[0] if found else None


def descendants(el: etree._Element, ns: str, local: str) -> list[etree._Element]:
    return list(el.findall(f".//{q(ns, local)}"))


def text(el: etree._Element | None) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def attr(el: etree._Element, name: str) -> str | None:
    if name in el.attrib:
        return el.attrib[name]
    return None


def assert_unique_ids(root: etree._Element) -> None:
    seen: set[str] = set()
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        for name in ("ID", "Id", "id"):
            value = el.get(name)
            if not value:
                continue
            if value in seen:
                raise SamlError("signature", f"two elements carry the ID {value}")
            seen.add(value)


def escape_xml(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")


def new_id(random_hex: str) -> str:
    return f"_{random_hex}"


def pem_body(pem: str) -> str:
    return re.sub(r"-----(BEGIN|END) CERTIFICATE-----", "", pem).replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")


def to_pem(b64: str) -> str:
    body = re.sub(r"\s+", "", b64)
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"
