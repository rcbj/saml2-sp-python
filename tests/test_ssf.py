# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The Shared Signals receiver against a stub transmitter."""

from __future__ import annotations

import base64
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from saml2_sp import CAEP_EVENTS, EVENT, MemorySessionIndex, RISC_EVENTS, SamlError, SignalsReceiver, subject_of
from saml2_sp.ssf.jws import verify_compact_jws

_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwk(key, kid: str = "k1") -> dict:
    numbers = key.public_key().public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {"kty": "RSA", "n": _b64url(n), "e": _b64url(e), "kid": kid, "alg": "RS256", "use": "sig"}


JWK = _jwk(_PRIVATE)


def jws(payload: dict, key=_PRIVATE, header: dict | None = None) -> str:
    head = header or {"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"}
    h = _b64url(json.dumps(head, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    if head.get("alg") in (None, "none", "HS256"):
        sig = b""
    else:
        sig = key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64url(sig)}"


class _Stub:
    def __init__(self) -> None:
        self.queue: dict[str, str] = {}
        self.acked: list[str] = []
        self.errs: dict = {}
        self.streams: list[dict] = []
        self.created = 0
        self.url = ""
        self._httpd = None
        self._thread = None

    def close(self) -> None:
        self._httpd.shutdown()
        self._thread.join(timeout=5)


def start_transmitter() -> _Stub:
    stub = _Stub()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:
            return

        def _out(self, status: int, body=None) -> None:
            raw = b"" if body is None else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _read(self) -> str:
            length = int(self.headers.get("content-length") or 0)
            return self.rfile.read(length).decode() if length else ""

        def do_GET(self) -> None:
            self._dispatch()

        def do_POST(self) -> None:
            self._dispatch()

        def _dispatch(self) -> None:
            path = self.path.split("?", 1)[0]
            text = self._read()
            if path == "/.well-known/ssf-configuration":
                return self._out(200, {
                    "issuer": stub.url,
                    "jwks_uri": f"{stub.url}/jwks",
                    "configuration_endpoint": f"{stub.url}/ssf/stream",
                    "verification_endpoint": f"{stub.url}/ssf/verify",
                    "delivery_methods_supported": ["urn:ietf:rfc:8936"],
                })
            if path == "/jwks":
                return self._out(200, {"keys": [JWK]})
            if path == "/ssf/stream" and self.command == "GET":
                return self._out(200, stub.streams)
            if path == "/ssf/stream" and self.command == "POST":
                body = json.loads(text)
                stub.created += 1
                stream = {
                    "stream_id": f"s{stub.created}",
                    "iss": stub.url,
                    "aud": "my-app",
                    "delivery": {"method": body["delivery"]["method"], "endpoint_url": f"{stub.url}/ssf/poll/s{stub.created}"},
                    "events_requested": body["events_requested"],
                    "events_delivered": body["events_requested"],
                }
                stub.streams.append(stream)
                return self._out(201, stream)
            if path.startswith("/ssf/poll/"):
                body = json.loads(text or "{}")
                for jti in body.get("ack") or []:
                    stub.acked.append(jti)
                    stub.queue.pop(jti, None)
                stub.errs.update(body.get("setErrs") or {})
                for jti in (body.get("setErrs") or {}):
                    stub.queue.pop(jti, None)
                return self._out(200, {"sets": dict(stub.queue), "moreAvailable": False})
            return self._out(404, {"err": "not found"})

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    stub._httpd = httpd
    stub._thread = thread
    stub.url = f"http://127.0.0.1:{httpd.server_address[1]}"
    return stub


def put_set(stub: _Stub, event_type: str, sub_id: dict, extra: dict | None = None, key=_PRIVATE, aud: str | None = None, iss: str | None = None) -> str:
    jti = str(uuid.uuid4())
    stub.queue[jti] = jws({
        "iss": iss or stub.url,
        "aud": aud or "my-app",
        "jti": jti,
        "iat": 1,
        "sub_id": sub_id,
        "events": {event_type: {"event_timestamp": 1, **(extra or {})}},
    }, key)
    return jti


def login(person: str, session_index: str):
    return SimpleNamespace(
        name_id=person,
        name_id_format=None,
        session_index=session_index,
        session_not_on_or_after=None,
        attributes={
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": [f"urn:uuid:{person}"],
            "urn:oid:0.9.2342.19200300.100.1.3": [f"{person}@example.com"],
        },
    )


@pytest.fixture(scope="module")
def stub():
    server = start_transmitter()
    yield server
    server.close()


def test_verifies_a_set_against_the_jwks():
    token = jws({"a": 1})
    assert verify_compact_jws(token, [JWK])["payload"] == {"a": 1}
    with pytest.raises(SamlError, match="does not verify"):
        verify_compact_jws(jws({"a": 1}, _OTHER), [JWK])
    with pytest.raises(SamlError, match="no RSA signing key with kid nope"):
        verify_compact_jws(jws({"a": 1}, _PRIVATE, {"alg": "RS256", "kid": "nope"}), [JWK])
    with pytest.raises(SamlError, match="does not verify"):
        verify_compact_jws(jws({"a": 1}, _PRIVATE, {"alg": "none"}), [JWK])
    with pytest.raises(SamlError, match="does not verify"):
        verify_compact_jws(jws({"a": 1}, _PRIVATE, {"alg": "HS256", "kid": "k1"}), [JWK])


def test_reads_complex_iss_sub_and_email_subjects():
    assert subject_of({"format": "complex", "user": {"format": "iss_sub", "iss": "https://i", "sub": "urn:uuid:a"}, "session": {"format": "opaque", "id": "S1"}}, "https://i") == {"person": "urn:uuid:a", "idp_session": "S1"}
    assert subject_of({"format": "iss_sub", "iss": "https://other", "sub": "urn:uuid:a"}, "https://i") == {}
    assert subject_of({"format": "email", "email": "A@x.com"}, "https://i") == {"email": "A@x.com"}


def test_creates_its_poll_stream_once_and_acknowledges(stub):
    ended = []
    seen = []
    receiver = SignalsReceiver(transmitter=stub.url, on_end_sessions=lambda ids, event=None: ended.append(ids), poll_interval_ms=60_000, log=_quiet())
    receiver.on("*", lambda event: seen.append(event))
    receiver.start()
    receiver.stop()
    assert stub.created == 1
    assert receiver.stream["stream_id"] == "s1"
    receiver.track("L-a1", login("alice", "IDP-A1"))
    receiver.track("L-a2", login("alice", "IDP-A2"))
    receiver.track("L-b1", login("bob", "IDP-B1"))
    j1 = put_set(stub, EVENT["session_revoked"], {"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:alice"}, "session": {"format": "opaque", "id": "IDP-A1"}})
    j2 = put_set(stub, EVENT["credential_change"], {"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:bob"}}, {"credential_type": "password", "change_type": "update"})
    receiver.poll_once()
    assert ended == [["L-a1"]]
    found = next(event for event in seen if event.jti == j2)
    assert found.ended is False
    assert found.sessions == ["L-b1"]
    j3 = put_set(stub, EVENT["account_disabled"], {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:alice"})
    receiver.poll_once()
    assert ended == [["L-a1"], ["L-a2"]]
    assert j1 in stub.acked and j2 in stub.acked
    put_set(stub, EVENT["credential_compromise"], {"format": "email", "email": "BOB@example.com"}, {"credential_type": "password"})
    receiver.poll_once()
    assert ended[2] == ["L-b1"]
    receiver.poll_once()
    assert j3 in stub.acked
    again = SignalsReceiver(transmitter=stub.url, on_end_sessions=lambda ids, event=None: None, log=_quiet())
    again.start()
    again.stop()
    assert stub.created == 1
    assert again.stream["stream_id"] == "s1"


def test_refuses_a_forged_misaddressed_or_foreign_set(stub):
    ended = []
    index = MemorySessionIndex()
    receiver = SignalsReceiver(transmitter=stub.url, session_index=index, on_end_sessions=lambda ids, event=None: ended.append(ids), log=_quiet())
    receiver.start()
    receiver.stop()
    receiver.track("L-c1", login("carol", "IDP-C1"))
    subject = {"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:carol"}, "session": {"format": "opaque", "id": "IDP-C1"}}
    forged = put_set(stub, EVENT["session_revoked"], subject, key=_OTHER)
    misaddressed = put_set(stub, EVENT["session_revoked"], subject, aud="someone-else")
    foreign = put_set(stub, EVENT["session_revoked"], subject, iss="https://evil.example")
    receiver.poll_once()
    assert ended == []
    assert index.by_person("urn:uuid:carol") == ["L-c1"]
    receiver.poll_once()
    for jti in (forged, misaddressed, foreign):
        assert jti in stub.errs


def test_names_all_eight_caep_and_fourteen_risc_event_types():
    assert len(CAEP_EVENTS) == 8
    assert len(RISC_EVENTS) == 14
    assert EVENT["risk_level_change"] in CAEP_EVENTS
    assert EVENT["opt_out_effective"] in RISC_EVENTS


def test_acknowledges_a_valid_set_whose_handler_throws(stub):
    errors = []
    seen = []

    def on_end(ids, event=None):
        raise RuntimeError("store down")

    class Log:
        def info(self, message): pass
        def warn(self, message): pass
        def error(self, message): errors.append(message)

    receiver = SignalsReceiver(transmitter=stub.url, on_end_sessions=on_end, log=Log())
    receiver.on(EVENT["credential_change"], lambda event: (_ for _ in ()).throw(RuntimeError("handler bug")))
    receiver.on("*", lambda event: seen.append(event.jti))
    receiver.start()
    receiver.stop()
    receiver.track("L-d1", login("dave", "IDP-D1"))
    j1 = put_set(stub, EVENT["credential_change"], {"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:dave"}}, {"credential_type": "password", "change_type": "update"})
    j2 = put_set(stub, EVENT["session_revoked"], {"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:dave"}, "session": {"format": "opaque", "id": "IDP-D1"}})
    receiver.poll_once()
    receiver.poll_once()
    receiver.poll_once()
    assert j1 in stub.acked and j2 in stub.acked
    assert j1 not in stub.errs and j2 not in stub.errs
    assert sorted(seen) == sorted([j1, j2])
    assert any(re_handler(message) for message in errors)
    assert any("onEndSessions threw" in message for message in errors)


def re_handler(message: str) -> bool:
    import re
    return re.search(r"handler for .*credential-change threw", message) is not None


def test_never_runs_two_polls_at_once(stub):
    seen = []
    receiver = SignalsReceiver(transmitter=stub.url, on_end_sessions=lambda ids, event=None: None, log=_quiet())
    receiver.on("*", lambda event: seen.append(event.jti))
    receiver.start()
    receiver.stop()
    jti = put_set(stub, EVENT["account_enabled"], {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:erin"})
    threads = [threading.Thread(target=receiver.poll_once) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    receiver.poll_once()
    assert [item for item in seen if item == jti] == [jti]


def test_refuses_a_transmitter_without_poll_delivery():
    receiver = SignalsReceiver(transmitter="http://127.0.0.1:1", on_end_sessions=lambda ids, event=None: None, log=_quiet())
    with pytest.raises(SamlError) as caught:
        receiver.start()
    assert caught.value.code == "ssf"


def _quiet():
    class Log:
        def info(self, message): pass
        def warn(self, message): pass
        def error(self, message): pass
    return Log()


def test_unused_serialization_import():
    assert serialization.Encoding.PEM
