# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Decrypting an EncryptedAssertion, EncryptedID or EncryptedAttribute. RSA PKCS#1 v1.5 is refused."""

from __future__ import annotations

import base64
import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from lxml import etree

from saml2_sp.errors import SamlError
from saml2_sp.xml import NS, attr, child, descendants, text

CIPHERS = {
    "http://www.w3.org/2009/xmlenc11#aes128-gcm": ("aes-128-gcm", True, 16),
    "http://www.w3.org/2009/xmlenc11#aes192-gcm": ("aes-192-gcm", True, 24),
    "http://www.w3.org/2009/xmlenc11#aes256-gcm": ("aes-256-gcm", True, 32),
    "http://www.w3.org/2001/04/xmlenc#aes128-cbc": ("aes-128-cbc", False, 16),
    "http://www.w3.org/2001/04/xmlenc#aes192-cbc": ("aes-192-cbc", False, 24),
    "http://www.w3.org/2001/04/xmlenc#aes256-cbc": ("aes-256-cbc", False, 32),
}
OAEP_MGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
OAEP = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
DIGESTS = {
    "http://www.w3.org/2000/09/xmldsig#sha1": "sha1",
    "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512": "sha512",
}
MGFS = {
    "http://www.w3.org/2009/xmlenc11#mgf1sha1": "sha1",
    "http://www.w3.org/2009/xmlenc11#mgf1sha256": "sha256",
    "http://www.w3.org/2009/xmlenc11#mgf1sha384": "sha384",
    "http://www.w3.org/2009/xmlenc11#mgf1sha512": "sha512",
}
_HASH = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}


def _fail(message: str, cause: BaseException | None = None) -> None:
    raise SamlError("decryption", message) from cause


def _b64(value: str) -> bytes:
    return base64.b64decode(re.sub(r"\s+", "", value))


def _unwrap_key(encrypted_key: etree._Element, key) -> bytes:
    method = child(encrypted_key, NS["xenc"], "EncryptionMethod")
    alg = attr(method, "Algorithm") if method is not None else ""
    alg = alg or ""
    if alg not in (OAEP_MGF1P, OAEP):
        _fail(f"the content key is wrapped with {alg or '(none)'}; only RSA-OAEP is accepted")
    digest_method = child(method, NS["ds"], "DigestMethod") if method is not None else None
    digest_alg = attr(digest_method, "Algorithm") if digest_method is not None else None
    digest = DIGESTS.get(digest_alg, "") if digest_alg else "sha1"
    if not digest:
        _fail(f"the OAEP digest {digest_alg} is not supported")
    mgf = "sha1"
    if alg == OAEP and method is not None:
        mgf_el = child(method, NS["xenc11"], "MGF")
        mgf_alg = attr(mgf_el, "Algorithm") if mgf_el is not None else None
        if mgf_alg:
            mgf = MGFS.get(mgf_alg, "")
            if not mgf:
                _fail(f"the OAEP mask generation function {mgf_alg} is not supported")
    if mgf != digest:
        _fail(f"OAEP with digest {digest} and MGF1 {mgf} is not supported; one hash is used for both")
    cipher_value = descendants(encrypted_key, NS["xenc"], "CipherValue")
    raw = text(cipher_value[0]) if cipher_value else ""
    try:
        return key.decrypt(_b64(raw), padding.OAEP(mgf=padding.MGF1(algorithm=_HASH[digest]), algorithm=_HASH[digest], label=None))
    except SamlError:
        raise
    except Exception as err:
        _fail("the content key could not be unwrapped with this service provider's key", err)
    return b""


def decrypt_element(encrypted: etree._Element, key) -> str:
    data = child(encrypted, NS["xenc"], "EncryptedData")
    if data is None:
        _fail(f"<{etree.QName(encrypted).localname}> has no EncryptedData")
    method = child(data, NS["xenc"], "EncryptionMethod")
    alg = attr(method, "Algorithm") if method is not None else ""
    cipher = CIPHERS.get(alg or "")
    if cipher is None:
        _fail(f"the content is encrypted with {alg or '(none)'}, which is not supported")
    name, gcm, key_length = cipher
    encrypted_keys = descendants(encrypted, NS["xenc"], "EncryptedKey")
    if not encrypted_keys:
        _fail(f"<{etree.QName(encrypted).localname}> carries no EncryptedKey")
    content_key = _unwrap_key(encrypted_keys[0], key)
    if len(content_key) != key_length:
        _fail(f"the content key is {len(content_key)} bytes; {name} needs {key_length}")
    cipher_data = child(data, NS["xenc"], "CipherData")
    cipher_value = child(cipher_data, NS["xenc"], "CipherValue") if cipher_data is not None else None
    blob = _b64(text(cipher_value))
    try:
        if gcm:
            if len(blob) < 12 + 16:
                _fail("the ciphertext is too short")
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            return AESGCM(content_key).decrypt(blob[:12], blob[12:], None).decode("utf-8")
        if len(blob) < 32 or len(blob) % 16:
            _fail("the ciphertext is not a whole number of blocks")
        decryptor = Cipher(algorithms.AES(content_key), modes.CBC(blob[:16])).decryptor()
        plain = decryptor.update(blob[16:]) + decryptor.finalize()
        pad = plain[-1]
        if pad < 1 or pad > 16:
            _fail("the decrypted content is not padded as XML Encryption pads it")
        return plain[:-pad].decode("utf-8")
    except SamlError:
        raise
    except Exception as err:
        _fail("the content could not be decrypted", err)
    return ""
