# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""idpCa (demo/saml.json): the install script writes the whole listener CA trust chain to the file
the parameter names, every run, and the library takes that file as its trust store.

The stub identity provider is HTTPS on a four-certificate chain shaped like iya-sts's (leaf, TLS
Issuing CA, Intermediate, Root) and publishes it, leaf first, at GET /tls/server-certificate.
"""

import datetime
import ipaddress
import json
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID

import configure_iya_sts
import trust_chain
from saml2_sp import SamlError, ServiceProvider, create_self_signed_key_pair, resolve_config
from saml2_sp.backchannel import send
from stub_idp import IDP_ENTITY, idp_metadata

ROOT = Path(__file__).resolve().parents[1]
SHIPPED_CONFIG = ROOT / "demo" / "saml.json"
DEFAULT_IDP_CA = "generated/idp-ca.pem"
CERT_RE = trust_chain.CERT_RE


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _cert(subject, key, issuer, issuer_key, ca, leaf_ip=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
        )
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
    if leaf_ip:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(leaf_ip))]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(cert):
    return cert.public_bytes(Encoding.PEM).decode()


@pytest.fixture(scope="module")
def provider():
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(4)]
    root = _cert("sts Root CA", keys[0], "sts Root CA", keys[0], True)
    intermediate = _cert("sts Intermediate CA", keys[1], "sts Root CA", keys[0], True)
    issuing = _cert("sts TLS Issuing CA", keys[2], "sts Intermediate CA", keys[1], True)
    leaf = _cert("127.0.0.1", keys[3], "sts TLS Issuing CA", keys[2], False, leaf_ip="127.0.0.1")
    published = "".join(_pem(cert) for cert in (leaf, issuing, intermediate, root))
    metadata = idp_metadata()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.path == "/tls/server-certificate":
                body, kind = published.encode(), "text/plain"
            elif self.path == "/saml2/metadata":
                body, kind = metadata.encode(), "application/samlmetadata+xml"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("content-type", kind)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            # The token endpoint refuses, so the install script stops right after the chain.
            self.rfile.read(int(self.headers.get("content-length") or 0))
            body = b'{"error":"invalid_client"}'
            self.send_response(401)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with tempfile.TemporaryDirectory(prefix="trust-chain-server-") as directory:
        chain_file = Path(directory, "server.pem")
        key_file = Path(directory, "server.key")
        chain_file.write_text("".join(_pem(cert) for cert in (leaf, issuing, intermediate)), encoding="utf-8")
        key_file.write_bytes(keys[3].private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(chain_file), str(key_file))
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        origin = f"https://127.0.0.1:{server.server_address[1]}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield {"origin": origin, "published": published, "root": root}
        finally:
            server.shutdown()
            server.server_close()


def _demo_dir(directory, origin):
    """A demo directory whose saml.json is the shipped one, its transmitter pointed at the stub."""
    demo = Path(directory, "demo")
    demo.mkdir()
    raw = json.loads(SHIPPED_CONFIG.read_text(encoding="utf-8"))
    raw["ssf"]["transmitter"] = origin
    (demo / "saml.json").write_text(json.dumps(raw), encoding="utf-8")
    return demo


def _blocks(text):
    return [block.strip() for block in CERT_RE.findall(text)]


def _fingerprint(cert):
    return ":".join(f"{byte:02X}" for byte in cert.fingerprint(hashes.SHA256()))


def test_the_shipped_demo_names_generated_idp_ca_pem():
    assert json.loads(SHIPPED_CONFIG.read_text(encoding="utf-8"))["idpCa"] == "file:" + DEFAULT_IDP_CA


def test_save_trust_chain_writes_the_whole_chain_to_idp_ca(provider):
    with tempfile.TemporaryDirectory(prefix="trust-chain-") as directory:
        demo = _demo_dir(directory, provider["origin"])
        target = demo / DEFAULT_IDP_CA
        files = configure_iya_sts.files_of(str(demo / "saml.json"))
        assert Path(files.idp_ca).resolve() == target.resolve()
        saved = trust_chain.save_trust_chain(provider["origin"], files.idp_ca)
        written = target.read_text(encoding="utf-8")
        assert _blocks(written) == _blocks(provider["published"])
        assert len(_blocks(written)) == 4
        assert saved["count"] == 4
        assert saved["anchor_subject"] == "CN=sts Root CA"
        assert saved["anchor_fingerprint"] == _fingerprint(provider["root"])


def test_the_install_script_rewrites_idp_ca_with_the_chain_every_run(provider, monkeypatch, capsys):
    with tempfile.TemporaryDirectory(prefix="trust-chain-") as directory:
        demo = _demo_dir(directory, provider["origin"])
        target = demo / DEFAULT_IDP_CA
        target.parent.mkdir(parents=True)
        # A file from an earlier iya-sts: the script replaces it rather than keeping it.
        target.write_text(_pem(create_self_signed_key_pair("an earlier iya-sts", bits=2048).certificate), encoding="utf-8")
        monkeypatch.setenv("ADMIN_API_CLIENT_SECRET", "unit-test-secret")
        monkeypatch.setenv("PORT", "3000")
        with pytest.raises(SystemExit):
            configure_iya_sts.main([
                "--config", str(demo / "saml.json"), "--idp", provider["origin"], "--no-test-user",
            ])
        assert _blocks(target.read_text(encoding="utf-8")) == _blocks(provider["published"])
        printed = capsys.readouterr().out
        assert f"(4 certificate(s)) to {target}" in printed or f"(4 certificate(s)) to {target.resolve()}" in printed
        assert "trust anchor CN=sts Root CA" in printed
        assert f"sha256 {_fingerprint(provider['root'])}" in printed


def test_the_refresh_entry_point_writes_idp_ca_and_names_the_anchor(provider, capsys):
    with tempfile.TemporaryDirectory(prefix="trust-chain-") as directory:
        demo = _demo_dir(directory, provider["origin"])
        trust_chain.main(["--config", str(demo / "saml.json"), "--idp", provider["origin"]])
        assert _blocks((demo / DEFAULT_IDP_CA).read_text(encoding="utf-8")) == _blocks(provider["published"])
        printed = capsys.readouterr().out
        assert "(4 certificate(s))" in printed
        assert "CN=sts Root CA" in printed
        assert "sha256 " in printed


def test_the_library_trusts_the_identity_provider_through_the_saved_file(provider):
    with tempfile.TemporaryDirectory(prefix="trust-chain-") as directory:
        demo = _demo_dir(directory, provider["origin"])
        url = provider["origin"] + "/saml2/metadata"
        with pytest.raises(SamlError):
            send(url)
        trust_chain.save_trust_chain(provider["origin"], str(demo / DEFAULT_IDP_CA))
        pair = create_self_signed_key_pair("saml2-sp-demo", bits=2048)
        (demo / "generated" / "sp.key").write_text(pair.private_key_pem, encoding="utf-8")
        (demo / "generated" / "sp.crt").write_text(pair.certificate_pem, encoding="utf-8")
        raw = json.loads((demo / "saml.json").read_text(encoding="utf-8"))
        raw["idpMetadata"] = url
        config = resolve_config(raw, str(demo))
        assert _blocks(config.idp_ca) == _blocks(provider["published"])
        provider_sp = ServiceProvider(config, None)
        provider_sp.refresh_metadata()
        assert provider_sp.idp.entity_id == IDP_ENTITY

