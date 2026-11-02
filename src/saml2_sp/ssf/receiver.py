# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""A Shared Signals receiver: one poll stream of CAEP and RISC events (RFC 8936)."""

from __future__ import annotations

import json
import re
import threading

from saml2_sp.backchannel import send
from saml2_sp.errors import SamlError
from saml2_sp.ssf.events import DEFAULT_ENDING_EVENTS, DEFAULT_EVENTS_REQUESTED, EVENT, subject_of
from saml2_sp.ssf.jws import verify_compact_jws
from saml2_sp.ssf.session_index import MemorySessionIndex, tracked_from

POLL_METHOD = "urn:ietf:rfc:8936"


class _Log:
    def info(self, message: str) -> None:
        print(message)

    def warn(self, message: str) -> None:
        print(message)

    def error(self, message: str) -> None:
        print(message)


class SignalEvent:
    def __init__(self, **fields: object) -> None:
        self.__dict__.update(fields)


class SignalsReceiver:
    def __init__(self, transmitter: str, on_end_sessions, tls: dict | None = None, headers=None,
                 events_requested=None, end_on=None, session_index=None, subject_attribute: str | None = None,
                 description: str | None = None, poll_interval_ms: int = 5000, max_events: int = 50, log=None) -> None:
        if not callable(on_end_sessions):
            raise SamlError("config", "onEndSessions is required")
        if not re.match(r"https?://", transmitter or ""):
            raise SamlError("config", "transmitter must be an http(s) URL")
        self.transmitter = transmitter.rstrip("/")
        self._on_end = on_end_sessions
        self._tls = tls or {}
        self._headers = headers
        self._events_requested = list(events_requested or DEFAULT_EVENTS_REQUESTED)
        self._end_on = list(end_on or DEFAULT_ENDING_EVENTS)
        self._index = session_index or MemorySessionIndex()
        self._subject_attribute = subject_attribute
        self._description = description
        self._poll_interval_ms = poll_interval_ms
        self._max_events = max_events
        self._log = log or _Log()
        self._config = None
        self._stream = None
        self._keys: list = []
        self._keys_at = 0.0
        self._timer: threading.Timer | None = None
        self._running = False
        self._ack: list[str] = []
        self._errs: dict = {}
        self._handlers: dict[str, list] = {}
        self._inflight = None
        self._gate = threading.Lock()

    @property
    def stream(self):
        return self._stream

    def track(self, local_id: str, login, expires_at=None) -> None:
        self._index.add(tracked_from(local_id, login, self._subject_attribute, expires_at))

    def untrack(self, local_id: str) -> None:
        self._index.remove(local_id)

    def on(self, event_type: str, handler):
        self._handlers.setdefault(event_type, []).append(handler)
        return self

    def _call(self, method: str, url: str, body=None) -> dict:
        headers = {"accept": "application/json"}
        if self._headers:
            headers.update(self._headers() or {})
        payload = None
        if body is not None:
            headers["content-type"] = "application/json"
            payload = json.dumps(body)
        answer = send(url, method=method, headers=headers, body=payload, tls=self._tls, code="ssf")
        parsed = None
        if answer.body:
            try:
                parsed = json.loads(answer.body)
            except json.JSONDecodeError:
                parsed = answer.body
        return {"status": answer.status, "json": parsed}

    def _discover(self) -> dict:
        url = f"{self.transmitter}/.well-known/ssf-configuration"
        reply = self._call("GET", url)
        config = reply["json"]
        if reply["status"] != 200 or not isinstance(config, dict) or not config.get("configuration_endpoint") or not config.get("jwks_uri"):
            raise SamlError("ssf", f"{url} answered {reply['status']} without a usable transmitter configuration")
        supported = config.get("delivery_methods_supported")
        if supported and POLL_METHOD not in supported:
            raise SamlError("ssf", "the transmitter does not offer poll delivery (RFC 8936)")
        return config

    def _jwks(self, force: bool = False) -> list:
        import time
        if not force and self._keys and time.time() - self._keys_at < 3600:
            return self._keys
        reply = self._call("GET", self._config["jwks_uri"])
        keys = reply["json"].get("keys") if isinstance(reply["json"], dict) else None
        if reply["status"] != 200 or not isinstance(keys, list):
            raise SamlError("ssf", f"the transmitter's JWKS answered {reply['status']}")
        self._keys = keys
        self._keys_at = time.time()
        return keys

    def _ensure_stream(self) -> dict:
        endpoint = self._config["configuration_endpoint"]
        listed = self._call("GET", endpoint)
        if listed["status"] == 200:
            body = listed["json"]
            all_streams = body if isinstance(body, list) else ([body] if body else [])
            mine = next((item for item in all_streams if isinstance(item, dict) and (item.get("delivery") or {}).get("method") == POLL_METHOD and item.get("stream_id")), None)
            if mine:
                return mine
        elif listed["status"] != 404:
            raise SamlError("ssf", f"listing the streams at {endpoint} answered {listed['status']}: {json.dumps(listed['json'])[:300]}")
        created_body = {"delivery": {"method": POLL_METHOD}, "events_requested": self._events_requested}
        if self._description:
            created_body["description"] = self._description
        created = self._call("POST", endpoint, created_body)
        stream = created["json"] if isinstance(created["json"], dict) else {}
        if created["status"] not in (200, 201) or not stream.get("stream_id"):
            raise SamlError("ssf", f"creating a stream at {endpoint} answered {created['status']}: {json.dumps(created['json'])[:300]}")
        return stream

    def start(self) -> None:
        if self._running:
            return
        self._config = self._discover()
        self._jwks(True)
        self._stream = self._ensure_stream()
        if not (self._stream.get("delivery") or {}).get("endpoint_url"):
            raise SamlError("ssf", "the stream has no poll endpoint_url")
        self._running = True
        delivered = self._stream.get("events_delivered") or []
        self._log.info(f"ssf: polling stream {self._stream.get('stream_id')} at {self._stream['delivery']['endpoint_url']}, delivering {len(delivered)} event type(s)")
        self._iteration()

    def stop(self) -> None:
        self._running = False
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _iteration(self) -> None:
        if not self._running:
            return
        delay = self._poll_interval_ms
        try:
            if self.poll_once():
                delay = 0
        except Exception as err:
            self._log.warn(f"ssf: poll failed: {err}")
            delay = min(self._poll_interval_ms * 4, 60_000)
        if self._running:
            timer = threading.Timer(delay / 1000, self._iteration)
            timer.daemon = True
            self._timer = timer
            timer.start()

    def poll_once(self) -> bool:
        with self._gate:
            if self._inflight is not None:
                event, box = self._inflight
                owner = False
            else:
                event = threading.Event()
                box = {}
                self._inflight = (event, box)
                owner = True
        if not owner:
            event.wait()
            if "error" in box:
                raise box["error"]
            return box.get("result", False)
        try:
            result = self._poll_now()
            box["result"] = result
            return result
        except Exception as err:
            box["error"] = err
            raise
        finally:
            with self._gate:
                self._inflight = None
            event.set()

    def _poll_now(self) -> bool:
        url = self._stream["delivery"]["endpoint_url"]
        ack = self._ack
        self._ack = []
        set_errs = self._errs
        self._errs = {}
        body = {"maxEvents": self._max_events, "returnImmediately": True}
        if ack:
            body["ack"] = ack
        if set_errs:
            body["setErrs"] = set_errs
        try:
            reply = self._call("POST", url, body)
        except Exception:
            self._ack = ack + self._ack
            self._errs = {**set_errs, **self._errs}
            raise
        if reply["status"] != 200:
            self._ack = ack + self._ack
            self._errs = {**set_errs, **self._errs}
            raise SamlError("ssf", f"the poll answered {reply['status']}: {json.dumps(reply['json'])[:300]}")
        payload = reply["json"] if isinstance(reply["json"], dict) else {}
        for jti, token in (payload.get("sets") or {}).items():
            try:
                self._handle(jti, token)
                self._ack.append(jti)
            except Exception as err:
                description = str(err)
                self._log.warn(f"ssf: SET {jti} refused: {description}")
                kind = "invalid_key" if isinstance(err, SamlError) and err.code == "signature" else "invalid_request"
                self._errs[jti] = {"err": kind, "description": description}
        return bool(payload.get("moreAvailable"))

    def _handle(self, jti: str, token: str) -> None:
        try:
            verified = verify_compact_jws(token, self._jwks())
        except SamlError as err:
            if not re.search(r"publishes no|does not verify", str(err)):
                raise
            verified = verify_compact_jws(token, self._jwks(True))
        header = verified["header"]
        payload = verified["payload"]
        if header.get("typ") is not None and str(header["typ"]).lower() != "secevent+jwt":
            raise SamlError("validation", f"the SET's typ is {header.get('typ')}")
        if payload.get("iss") != self._config["issuer"]:
            raise SamlError("validation", f"the SET was issued by {payload.get('iss')}, not {self._config['issuer']}")
        want = self._stream.get("aud")
        wanted = want if isinstance(want, list) else ([want] if want else [])
        aud = payload.get("aud")
        audience = [str(item) for item in (aud if isinstance(aud, list) else ([] if aud is None else [aud]))]
        if wanted and not any(item in wanted for item in audience):
            raise SamlError("validation", f"the SET is for {', '.join(audience)}, not this stream")
        if payload.get("jti") is not None and payload.get("jti") != jti:
            raise SamlError("validation", "the SET's jti is not the one it was delivered under")
        events = payload.get("events")
        if not isinstance(events, dict) or not events:
            raise SamlError("validation", "the SET carries no events")
        for event_type, body in events.items():
            subject = subject_of(payload.get("sub_id") if payload.get("sub_id") is not None else (body or {}).get("subject") if isinstance(body, dict) else None, self._config["issuer"])
            sessions = self._sessions_for(event_type, subject)
            ends = event_type in self._end_on and len(sessions) > 0
            event = SignalEvent(
                type=event_type, payload=body or {}, subject=subject, jti=jti, sessions=sessions, ended=ends,
                iat=payload.get("iat") if isinstance(payload.get("iat"), (int, float)) and not isinstance(payload.get("iat"), bool) else None,
                txn=payload.get("txn") if isinstance(payload.get("txn"), str) else None,
            )
            if ends:
                try:
                    self._on_end(sessions, event)
                except Exception as err:
                    self._log.error(f"ssf: onEndSessions threw for {event_type} (SET {jti} is still acknowledged): {err}")
                    event.ended = False
                if event.ended:
                    for local_id in sessions:
                        self._index.remove(local_id)
            for handler in [*(self._handlers.get(event_type) or []), *(self._handlers.get("*") or [])]:
                try:
                    handler(event)
                except Exception as err:
                    self._log.error(f"ssf: a handler for {event_type} threw (SET {jti} is still acknowledged): {err}")

    def _sessions_for(self, event_type: str, subject: dict) -> list[str]:
        if event_type in (EVENT["verification"], EVENT["stream_updated"]):
            return []
        if subject.get("idp_session"):
            found = self._index.by_idp_session(subject["idp_session"])
            if found or event_type == EVENT["session_revoked"]:
                return found
        if subject.get("person"):
            return self._index.by_person(subject["person"])
        if subject.get("email"):
            return self._index.by_email(subject["email"])
        return []

    def verify(self, state: str | None = None) -> None:
        endpoint = (self._config or {}).get("verification_endpoint") if self._config else None
        if not isinstance(endpoint, str):
            raise SamlError("ssf", "the transmitter publishes no verification_endpoint")
        body = {"stream_id": self._stream["stream_id"]}
        if state:
            body["state"] = state
        reply = self._call("POST", endpoint, body)
        if reply["status"] not in (200, 204):
            raise SamlError("ssf", f"verification answered {reply['status']}")
