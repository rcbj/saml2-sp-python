# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""A self-signed certificate for a service provider's signing key. SAML uses it only as a public-key container."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class KeyPair:
    def __init__(self, private_key_pem: str, certificate_pem: str, certificate: x509.Certificate, private_key: rsa.RSAPrivateKey) -> None:
        self.private_key_pem = private_key_pem
        self.certificate_pem = certificate_pem
        self.certificate = certificate
        self.private_key = private_key

    @property
    def fingerprint256(self) -> str:
        digest = self.certificate.fingerprint(hashes.SHA256())
        return ":".join(f"{b:02X}" for b in digest)

    @property
    def valid_to(self) -> str:
        not_after = self.certificate.not_valid_after_utc
        return not_after.strftime("%b %d %H:%M:%S %Y GMT").replace(" 0", "  ")


def create_self_signed_key_pair(common_name: str, days: int = 1095, bits: int = 3072) -> KeyPair:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    not_before = datetime.now(timezone.utc) - timedelta(seconds=60)
    not_after = not_before + timedelta(days=days)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    der = certificate.public_bytes(serialization.Encoding.DER)
    body = base64.b64encode(der).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    certificate_pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"
    return KeyPair(private_pem, certificate_pem, certificate, private_key)


def load_private_key(pem: str):
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


def load_certificate(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode("utf-8"))


def certificate_pem(certificate: x509.Certificate) -> str:
    der = certificate.public_bytes(serialization.Encoding.DER)
    body = base64.b64encode(der).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def private_key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
