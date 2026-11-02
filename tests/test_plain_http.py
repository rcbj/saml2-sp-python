# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Plain http is refused for every fetch (metadata, ArtifactResolve, the Shared Signals
transmitter, and a redirect any of them follows) unless the host is loopback, before any
connection. ``http://0.0.0.0:<port>`` reaches a 127.0.0.1 listener on Linux, so a listener that
sees no connection proves the refusal comes first."""

from __future__ import annotations

import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

import pytest

from saml2_sp import SamlError, ServiceProvider, SignalsReceiver
from saml2_sp.backchannel import is_loopback_host
from stub_idp import ACS, IDP_ENTITY, SP_CERT, SP_ENTITY, SP_KEY, artifact_for, idp_metadata, response_xml, start_ars

REFUSED = "is refused: plain http is allowed only to a loopback host"


def config(source: str) -> dict:
    return {"entityId": SP_ENTITY, "acsUrl": ACS, "privateKey": SP_KEY, "certificate": SP_CERT, "idpMetadata": source}


def refused(fn, code: str, shown: str, secret: str | None = None) -> None:
    with pytest.raises(SamlError) as caught:
        fn()
    message = str(caught.value)
    assert caught.value.code == code, message
    assert message.startswith(f"http://{shown} {REFUSED}"), message
    if secret:
        assert secret not in message
    assert "/md" not in message and "?" not in message


def metadata_of(url: str):
    return lambda: ServiceProvider.create(config(url))


def artifact_at(ars_url: str):
    def run():
        sp = ServiceProvider.create(config(idp_metadata(ars_url)))
        sp.acs("GET", f"/saml/acs?SAMLart={quote(artifact_for(), safe='')}", request_id="_r")
    return run


class _Quiet:
    def info(self, message): pass
    def warn(self, message): pass
    def error(self, message): pass


def transmitter_at(url: str):
    return lambda: SignalsReceiver(transmitter=url, on_end_sessions=lambda ids, event=None: None, log=_Quiet()).start()


class _Tripwire:
    """A 127.0.0.1 listener that counts the connections it is offered."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            self.connections += 1
            conn.close()

    def close(self) -> None:
        self._stop = True
        self._thread.join()
        self.sock.close()


@pytest.fixture
def tripwire():
    wire = _Tripwire()
    yield wire
    wire.close()


def _serve(handler) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


class _Metadata(BaseHTTPRequestHandler):
    location = ""

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        if self.path.startswith("/go"):
            self.send_response(302)
            self.send_header("location", self.location)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        body = idp_metadata().encode()
        self.send_response(200)
        self.send_header("content-type", "application/samlmetadata+xml")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def metadata_server():
    httpd = _serve(_Metadata)
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def test_knows_a_loopback_host():
    for host in ["localhost", "LOCALHOST", "127.0.0.1", "127.1.2.3", "127.255.255.255", "::1"]:
        assert is_loopback_host(host), host
    for host in ["example.com", "0.0.0.0", "128.0.0.1", "10.0.0.1", "localhost.example.com", "::ffff:127.0.0.1", "::", "127.1"]:
        assert not is_loopback_host(host), host


def test_refuses_metadata_artifact_resolve_and_the_transmitter_on_example_com():
    refused(metadata_of("http://example.com/md?x=1"), "metadata", "example.com")
    refused(artifact_at("http://example.com/md"), "artifact", "example.com")
    refused(transmitter_at("http://example.com:8080"), "ssf", "example.com:8080")


def test_refuses_0_0_0_0_before_connecting_to_a_listener_it_would_reach(tripwire):
    # The tripwire is reachable this way: without the refusal, these would connect to it.
    hostport = f"0.0.0.0:{tripwire.port}"
    refused(metadata_of(f"http://{hostport}/md"), "metadata", hostport)
    refused(artifact_at(f"http://{hostport}/md"), "artifact", hostport)
    refused(transmitter_at(f"http://{hostport}"), "ssf", hostport)
    time.sleep(0.3)
    assert tripwire.connections == 0


def test_never_counts_userinfo_as_loopback_and_keeps_the_password_out(tripwire):
    refused(metadata_of(f"http://localhost:{tripwire.port}@example.com/md"), "metadata", "example.com")
    refused(metadata_of(f"http://user:s3cret-pw@localhost:{tripwire.port}/md"), "metadata", f"localhost:{tripwire.port}", "s3cret-pw")
    refused(transmitter_at(f"http://user:s3cret-pw@127.0.0.1:{tripwire.port}"), "ssf", f"127.0.0.1:{tripwire.port}", "s3cret-pw")
    refused(metadata_of(f"http://local\thost:{tripwire.port}/md"), "metadata", f"localhost:{tripwire.port}")
    time.sleep(0.3)
    assert tripwire.connections == 0


def test_refuses_a_redirect_to_plain_http_off_loopback(metadata_server, tripwire):
    _Metadata.location = f"http://0.0.0.0:{tripwire.port}/md"
    port = metadata_server.server_address[1]
    refused(metadata_of(f"http://127.0.0.1:{port}/go"), "metadata", f"0.0.0.0:{tripwire.port}")
    time.sleep(0.3)
    assert tripwire.connections == 0
    _Metadata.location = f"http://localhost:{port}/md"
    assert ServiceProvider.create(config(f"http://127.0.0.1:{port}/go")).idp.entity_id == IDP_ENTITY


def test_reads_metadata_from_127_0_0_1_and_localhost(metadata_server):
    port = metadata_server.server_address[1]
    assert ServiceProvider.create(config(f"http://127.0.0.1:{port}/md")).idp.entity_id == IDP_ENTITY
    assert ServiceProvider.create(config(f"http://localhost:{port}/md")).idp.entity_id == IDP_ENTITY


def test_resolves_an_artifact_at_localhost():
    ars = start_ars()
    try:
        port = ars.url.split(":")[2].split("/")[0]
        sp = ServiceProvider.create(config(idp_metadata(f"http://localhost:{port}/ars")))
        artifact = artifact_for()
        ars.put(artifact, response_xml({"in_response_to": "_r"}))
        who = sp.acs("GET", f"/saml/acs?SAMLart={quote(artifact, safe='')}", request_id="_r")
        assert who.binding == "artifact"
    finally:
        ars.close()


def test_fails_https_to_an_unreachable_host_as_a_connection_error():
    with pytest.raises(SamlError) as caught:
        ServiceProvider.create(config("https://127.0.0.1:1/md"))
    assert caught.value.code == "metadata"
    assert REFUSED not in str(caught.value)
    assert re.search(r"refused|Errno", str(caught.value))
