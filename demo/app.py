#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The demo: a server-rendered application that signs people in with SAML 2.0.

Several people can be signed in to one browser. The `aset` cookie names an account set. Which
person a tab shows is `/u/<account>/`. `saml_pending` carries the outstanding AuthnRequest ids
across the cross-site POST of the HTTP-POST binding.

GET  /healthz returns 200 and the body ok, before the identity provider is reachable.
GET  /live-status is JSON and does not need an account id: whether any local account
session exists, the subject, the receiver state, and the accepted events (type and jti).
"""

from __future__ import annotations

import base64
import hmac
import hashlib
import json
import os
import secrets
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from configure_iya_sts import endpoints_for  # noqa: E402
from saml2_sp import EVENT, SamlError, ServiceProvider, SignalsReceiver  # noqa: E402

HERE = Path(__file__).resolve().parent
PORT = int(os.environ.get("PORT") or 3000)
SECRET = os.environ["SESSION_SECRET"].encode() if os.environ.get("SESSION_SECRET") else secrets.token_bytes(32)
SESSION_MS = 8 * 3600_000
MAX_SESSIONS = 10_000
MAX_BODY = 512 * 1024
STYLES = (HERE / "public" / "styles.css").read_bytes()
APP_JS = (HERE / "public" / "app.js").read_bytes()
BINDINGS = ("post", "redirect", "artifact")
BINDING_LABEL = {"post": "HTTP-POST", "redirect": "HTTP-Redirect", "artifact": "HTTP-Artifact"}
LOG_SIZE = 25


def _public_from_argv(argv: list[str]) -> tuple[str | None, bool, str | None]:
    public = os.environ.get("PUBLIC_URL")
    given = bool(public)
    config = os.environ.get("SAML_CONFIG")
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--public-url":
            if index + 1 >= len(argv):
                raise SystemExit("--public-url needs a value")
            public = argv[index + 1]
            given = True
            index += 2
            continue
        if arg == "--config":
            if index + 1 >= len(argv):
                raise SystemExit("--config needs a value")
            config = argv[index + 1]
            index += 2
            continue
        raise SystemExit(f"Unknown argument {arg}")
    if given and not str(public or "").strip():
        raise SystemExit("--public-url is empty")
    if public:
        public = public.rstrip("/")
    return public, given, config


PUBLIC_URL, PUBLIC_URL_GIVEN, CONFIG_ARG = _public_from_argv(sys.argv[1:])
CONFIG = str(Path(CONFIG_ARG).resolve() if CONFIG_ARG else HERE / "saml.json")


def _read_file() -> dict:
    try:
        return json.loads(Path(CONFIG).read_text(encoding="utf-8"))
    except OSError:
        return {}


FILE = _read_file()
SIGNALS_OFF = FILE.get("signals") is False
SSF = None if SIGNALS_OFF or not (FILE.get("ssf") or {}).get("transmitter") else FILE.get("ssf")


def _endpoints() -> dict:
    raw = json.loads(Path(CONFIG).read_text(encoding="utf-8"))
    entity = raw.get("entityId") if isinstance(raw.get("entityId"), str) else ""
    acs = raw.get("acsUrl") if isinstance(raw.get("acsUrl"), str) else ""
    if not entity or not acs:
        return {}
    return endpoints_for(entity, acs, {"public_url": PUBLIC_URL, "public_url_given": PUBLIC_URL_GIVEN, "port": PORT})


def port_overrides() -> dict:
    ends = _endpoints()
    out = {}
    if ends.get("entityId"):
        out["entityId"] = ends["entityId"]
    if ends.get("acsUrl"):
        out["acsUrl"] = ends["acsUrl"]
    return out


_sp = None
_sp_lock = threading.Lock()
sessions: dict[str, dict] = {}
account_sets: dict[str, list[str]] = {}
listeners: dict[str, set] = {}
sequence = 0
verifications_asked: dict[str, str] = {}
stream_status = None
receiver = None
live_events: list[dict] = []
receiver_state = (
    "not configured (signals are off)" if SIGNALS_OFF
    else "starting" if SSF
    else "not configured (no ssf block in the configuration file)"
)
secure_cookies = True


def service_provider() -> ServiceProvider:
    global _sp
    with _sp_lock:
        if _sp is None:
            _sp = ServiceProvider.from_file(CONFIG, port_overrides())
            start_receiver(_sp)
        return _sp


def _drop_sp() -> None:
    global _sp
    with _sp_lock:
        _sp = None


def end_session(sid: str) -> None:
    found = sessions.pop(sid, None)
    if not found:
        return
    left = [item for item in account_sets.get(found["set_id"], []) if item != sid]
    if left:
        account_sets[found["set_id"]] = left
    else:
        account_sets.pop(found["set_id"], None)


def tell(sid: str, event: str, data, event_id: int | None = None) -> None:
    dead = []
    for stream in list(listeners.get(sid, ())):
        prefix = f"id: {event_id}\n" if event_id is not None else ""
        try:
            stream.write(f"{prefix}event: {event}\ndata: {json.dumps(data)}\n\n")
        except Exception:
            dead.append(stream)
        if event == "signed-out":
            stream.close()
    for stream in dead:
        listeners.get(sid, set()).discard(stream)
    if event == "signed-out":
        listeners.pop(sid, None)


def short_type(uri: str) -> str:
    return uri.rsplit("/event-type/", 1)[-1]


def family_of(uri: str) -> str:
    if "/caep/" in uri:
        return "CAEP"
    if "/risc/" in uri:
        return "RISC"
    return "SSF"


def log_for(sid: str, entry: dict) -> None:
    found = sessions.get(sid)
    if not found:
        return
    found["signals"].insert(0, entry)
    del found["signals"][LOG_SIZE:]
    tell(sid, "signal", entry, entry["id"])


def start_receiver(sp: ServiceProvider) -> None:
    global receiver, receiver_state
    if getattr(sp.config, "signals", None) is False:
        receiver_state = "not configured (signals are off)"
        return
    if not SSF or receiver is not None:
        return
    tls = {}
    if getattr(sp.config, "idp_ca", None):
        tls["ca"] = sp.config.idp_ca
    tls["cert"] = sp.config.certificate_pem
    tls["key"] = sp.config.private_key_pem

    def on_end(ids, event):
        for sid in ids:
            end_session(sid)
            reason = event.payload.get("reason_user") if isinstance(event.payload, dict) else None
            if reason is None and isinstance(event.payload, dict):
                reason = event.payload.get("reason_admin", event.payload.get("reason"))
            tell(sid, "signed-out", {"type": short_type(event.type), "reason": reason})
        print(f"ssf: {short_type(event.type)} ended {len(ids)} local session(s)")

    built = SignalsReceiver(
        transmitter=SSF["transmitter"],
        on_end_sessions=on_end,
        tls=tls,
        description=f"saml2-sp demo ({sp.config.entity_id})",
        poll_interval_ms=SSF.get("pollIntervalMs") or 5000,
    )

    def on_event(event):
        global sequence, stream_status
        live_events.append({"type": event.type, "jti": event.jti})
        sequence += 1
        subject = event.subject or {}
        entry = {
            "id": sequence,
            "at": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "type": event.type,
            "family": family_of(event.type),
            "ended": event.ended,
            "about": "session",
            "subject": ", ".join(item for item in (
                subject.get("person"), subject.get("email"),
                f"IdP session {subject['idp_session']}" if subject.get("idp_session") else None,
            ) if item),
            "members": event.payload if isinstance(event.payload, dict) else {},
            "jti": event.jti,
        }
        if event.type == EVENT["verification"]:
            state = str((event.payload or {}).get("state") or "")
            asker = verifications_asked.pop(state, None)
            if asker:
                entry["about"] = "stream"
                log_for(asker, entry)
            print(f"ssf: verification received{'' if asker else ' (asked by no session here)'}")
            return
        if event.type == EVENT["stream_updated"]:
            stream_status = {"status": str((event.payload or {}).get("status") or ""), "reason": (event.payload or {}).get("reason"), "at": entry["at"]}
            for sid in list(listeners):
                tell(sid, "stream", stream_status)
            return
        if not event.ended:
            for sid in event.sessions:
                log_for(sid, entry)

    built.on("*", on_event)
    receiver = built

    def run() -> None:
        global receiver, receiver_state
        try:
            built.start()
            stream = built.stream or {}
            receiver_state = f"polling stream {stream.get('stream_id')} at {SSF['transmitter']}"
        except Exception as err:
            receiver_state = f"not running: {err}"
            if receiver is built:
                receiver = None
            print(f"ssf: the receiver did not start: {err}")

    threading.Thread(target=run, daemon=True).start()


def esc(value) -> str:
    return str("" if value is None else value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")


def _mac(value: str) -> str:
    return base64.urlsafe_b64encode(hmac.new(SECRET, value.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()


def sealed(value) -> str:
    body = base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{body}.{_mac(body)}"


def unseal(token: str | None):
    if not token or "." not in token:
        return None
    body, tag = token.split(".", 1)
    if not hmac.compare_digest(_mac(body), tag):
        return None
    pad = "=" * ((4 - len(body) % 4) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(body + pad))
    except Exception:
        return None


def cookies_of(header: str | None) -> dict[str, str]:
    out = {}
    for part in (header or "").split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        out[name.strip()] = urllib.parse.unquote(value.strip())
    return out


def cookie(name: str, value: str, path: str = "/", max_age: int | None = None, same_site: str = "Lax") -> str:
    parts = [f"{name}={urllib.parse.quote(value, safe='-_.!~*()')}", f"Path={path}", "HttpOnly", f"SameSite={same_site}"]
    if secure_cookies:
        parts.append("Secure")
    if max_age is not None:
        parts.append(f"Max-Age={max_age}")
    return "; ".join(parts)


def accounts_of_set(set_id: str | None) -> list[dict]:
    out = []
    for sid in list((account_sets.get(set_id) if set_id else None) or []):
        found = sessions.get(sid)
        if not found:
            continue
        if found["expires"] <= time.time() * 1000:
            end_session(sid)
            if receiver is not None:
                receiver.untrack(sid)
            continue
        out.append({"sid": sid, "session": found})
    return out


def account_of(header: str | None, account: str):
    return next((item for item in accounts_of_set(cookies_of(header).get("aset")) if item["session"]["account"] == account), None)


def same_person(a, b) -> bool:
    return a.issuer == b.issuer and a.name_id == b.name_id and (a.name_id_format or "") == (b.name_id_format or "")


def page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title><link rel="stylesheet" href="/styles.css"></head>
<body><header><a href="/">saml2-sp demo</a></header><main>
{body}
</main><footer>A traditional web application signing in with SAML 2.0.</footer></body>
</html>
"""


def tabs(base: str, active: str, count: int = 0) -> str:
    def tab(name: str, label: str) -> str:
        current = ' aria-current="page"' if name == active else ""
        return f'<a class="page-tab" role="tab" href="{base}/?tab={name}" aria-selected="{str(name == active).lower()}"{current}>{label}</a>'
    shown = f'<span class="count" id="signal-count">{count or ""}</span>'
    return f'<nav class="page-tabs" role="tablist" aria-label="Sections">{tab("identity", "Identity")}{tab("events", "CAEP &amp; RISC events " + shown)}</nav>'


def member(value) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        values = list(value.values())
        if values and all(isinstance(item, str) for item in values):
            return " / ".join(values)
        return json.dumps(value)
    return str(value)


def log_item(entry: dict) -> str:
    rows = "".join(
        f"<tr><th>{esc(key)}</th><td>{esc(member(value))}</td></tr>"
        for key, value in entry["members"].items() if key != "subject"
    )
    outcome = "about the stream: the verification this session asked for" if entry["about"] == "stream" else "ended this session" if entry["ended"] else "recorded; this session continues"
    subject = f'<p><small>Subject: {esc(entry["subject"])}</small></p>' if entry["subject"] else ""
    table = f'<table class="facts members">{rows}</table>' if rows else ""
    ended = " ended" if entry["ended"] else ""
    return (
        f'<li class="log-item" data-id="{entry["id"]}"><div class="log-top">'
        f'<span class="badge {entry["family"].lower()}">{entry["family"]}</span> <strong>{esc(short_type(entry["type"]))}</strong> '
        f'<time>{esc(entry["at"])}</time></div><p class="log-outcome{ended}">{esc(outcome)}</p>{subject}{table}'
        f'<p><small>jti {esc(entry["jti"])}</small></p></li>'
    )


def events_panel(base: str, session: dict, notice: str | None) -> str:
    stream = (receiver.stream if receiver is not None else None) or None
    delivered = (stream or {}).get("events_delivered") or []
    last_id = session["signals"][0]["id"] if session["signals"] else 0
    status = f'{stream_status["status"]} ({stream_status["at"]})' if stream_status else "enabled"
    stream_rows = ""
    if stream:
        badges = "<br>".join(f'<span class="badge {family_of(item).lower()}">{family_of(item)}</span> {esc(short_type(item))}' for item in delivered) or "(nothing yet)"
        stream_rows = (
            f'<tr><th>Stream</th><td>{esc(stream.get("stream_id"))}<br><small>poll delivery (RFC 8936) at {esc((stream.get("delivery") or {}).get("endpoint_url"))}</small></td></tr>'
            f"<tr><th>Authentication</th><td>mutual TLS with this service provider's own certificate</td></tr>"
            f"<tr><th>Delivers</th><td>{badges}</td></tr>"
        )
    notice_row = f'<p class="notice">{esc(notice)}</p>' if notice else ""
    verify = f'<form method="post" action="{base}/signals/verify" class="inline" id="verify-form"><button type="submit">Request verification event</button></form>' if stream else ""
    hidden = "" if session["signals"] else ""
    empty_hidden = " hidden" if session["signals"] else ""
    return f"""<section class="card"><h2>Shared Signals stream</h2>{notice_row}
<table class="facts"><tr><th>Receiver</th><td>{esc(receiver_state)}</td></tr>
<tr><th>Stream status</th><td id="stream-status">{esc(status)}</td></tr>{stream_rows}
<tr><th>Ends this session on</th><td>session-revoked, account-disabled, account-purged, credential-compromise, sessions-revoked</td></tr></table>
{verify}</section><section class="card"><h2>Event log</h2>
<p><small>The CAEP and RISC events about this session or its person, newest first, and the verification events this session asked for. Each appears here within moments of the receiver getting it: <span id="live-state">connecting…</span></small></p>
<ol class="log" id="log" data-last-id="{last_id}">{''.join(log_item(item) for item in session["signals"])}</ol>
<p class="empty" id="log-empty"{empty_hidden}>No CAEP or RISC event about this session yet. At the identity provider, change this person's password (credential-change), sign them out (session-revoked), or disable them (account-disabled), and watch this tab.</p>
<form method="post" action="{base}/signals/clear" class="inline"><button type="submit" class="secondary">Clear this session's log</button></form></section>"""


def account_bar(accounts: list[dict], current: dict) -> str:
    items = []
    for item in accounts:
        name = esc(item["session"]["login"].name_id)
        if item["session"] is current:
            items.append(f'<li aria-current="true"><strong>{name}</strong></li>')
        else:
            items.append(f'<li><a href="/u/{esc(item["session"]["account"])}/">{name}</a></li>')
    all_out = '<form method="post" action="/logout" class="inline"><button type="submit" class="secondary small">Sign out of all accounts</button></form>' if len(accounts) > 1 else ""
    return f'<nav class="accounts" aria-label="Accounts in this browser"><span class="accounts-label">Signed in here:</span> <ul>{"".join(items)}</ul><a class="button small" href="/login?add=1">Add another account</a>{all_out}</nav>'


def home(session, sp, problem, tab="identity", notice=None, accounts=None, gone=None) -> str:
    accounts = accounts or []
    if session:
        base = f'/u/{session["account"]}'
        login = session["login"]
        rows = "".join(
            f'<tr><th>{esc(login.attribute_friendly_names.get(name) or name)}'
            f'{f"<br><small>{esc(name)}</small>" if login.attribute_friendly_names.get(name) else ""}</th>'
            f'<td>{"<br>".join(esc(value) for value in values)}</td></tr>'
            for name, values in login.attributes.items()
        )
        instant = login.authn_instant.strftime("%Y-%m-%dT%H:%M:%S.") + f"{login.authn_instant.microsecond // 1000:03d}Z" if login.authn_instant else ""
        encrypted = "arrived encrypted (EncryptedAssertion), decrypted with this service provider's key" if login.encrypted else "arrived in clear"
        identity = f"""<table class="facts">
<tr><th>NameID</th><td>{esc(login.name_id)}<br><small>{esc(login.name_id_format)}</small></td></tr>
<tr><th>Identity provider</th><td>{esc(login.issuer)}</td></tr>
<tr><th>Response binding</th><td>{esc(BINDING_LABEL.get(login.binding, login.binding))}</td></tr>
<tr><th>Authenticated</th><td>{esc(instant)}<br><small>{esc(login.authn_context_class_ref)}</small></td></tr>
<tr><th>Session index</th><td>{esc(login.session_index)}</td></tr>
<tr><th>Assertion</th><td>{esc(login.assertion_id)}<br><small>{encrypted}; signature verified</small></td></tr>
</table><h2>Attributes</h2>{f'<table class="facts">{rows}</table>' if rows else '<p>The identity provider released no attributes.</p>'}"""
        count = len(session["signals"])
        last = session["signals"][0]["id"] if session["signals"] else 0
        gone_row = f'<p class="notice">{esc(gone)}</p>' if gone else ""
        panel = events_panel(base, session, notice) if tab == "events" else identity
        return page("Signed in", f'<h1>Signed in as {esc(login.name_id)}</h1>{account_bar(accounts, session)}{gone_row}{tabs(base, tab, count)}'
                    f'<p id="signal-banner" class="problem" hidden></p><p id="signal-toast" class="notice" hidden></p>'
                    f'<div role="tabpanel" id="panel" data-base="{base}" data-tab="{tab}" data-last-id="{last}">{panel}</div>'
                    f'<form method="post" action="{base}/logout" class="inline"><button type="submit">Sign out of this account</button></form><script src="/app.js"></script>')
    request_binding = "(configuration not loaded)"
    entity = "the identity provider"
    if sp is not None:
        request_binding = "HTTP-POST" if sp.config.request_binding == "post" else "HTTP-Redirect"
        entity = sp.idp.entity_id
    buttons = "\n".join(
        f'<a class="button{" primary" if sp is not None and binding == sp.config.response_binding else ""}" href="/login?binding={binding}">Sign in — response by {BINDING_LABEL[binding]}</a>'
        for binding in BINDINGS
    )
    problem_row = f'<p class="problem">{esc(problem)}</p>' if problem else ""
    return page("Sign in", f"<h1>Sign in with SAML 2.0</h1>{problem_row}"
                f"<p>Service provider-initiated single sign-on: this application sends a <strong>signed</strong> AuthnRequest on "
                f"<strong>{esc(request_binding)}</strong> to {esc(entity)}, and asks for the Response on the binding you pick.</p>"
                f'<p class="buttons">{buttons}</p><p><a href="/saml/metadata">This service provider\'s metadata</a></p>')


class Stream:
    def __init__(self, handler: BaseHTTPRequestHandler) -> None:
        self.handler = handler
        self.closed = threading.Event()
        self.lock = threading.Lock()

    def write(self, text: str) -> None:
        with self.lock:
            if self.closed.is_set():
                return
            self.handler.wfile.write(text.encode())
            self.handler.wfile.flush()

    def close(self) -> None:
        self.closed.set()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def _body(self) -> str:
        length = int(self.headers.get("content-length") or 0)
        if length > MAX_BODY:
            raise ValueError("the request body is too large")
        return self.rfile.read(length).decode("utf-8", "replace") if length else ""

    def _send(self, status: int, body, headers: dict | None = None) -> None:
        payload = body if isinstance(body, bytes) else body.encode()
        merged = {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
            "referrer-policy": "no-referrer",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        }
        for key, value in (headers or {}).items():
            merged[key.lower()] = value
        self.send_response(status)
        cookies = []
        for key, value in list(merged.items()):
            if key == "set-cookie":
                cookies = value if isinstance(value, list) else [value]
                continue
            self.send_header(key, value)
        for item in cookies:
            self.send_header("set-cookie", item)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _redirect(self, location: str, headers: dict | None = None) -> None:
        merged = {"location": location, "cache-control": "no-store"}
        merged.update(headers or {})
        status = int(merged.pop("status", 303 if self.command == "POST" else 302))
        self.send_response(status)
        cookies = []
        for key, value in merged.items():
            if key == "set-cookie":
                cookies = value if isinstance(value, list) else [value]
                continue
            if key == "status":
                continue
            self.send_header(key, value)
        for item in cookies:
            self.send_header("set-cookie", item)
        self.send_header("content-length", "0")
        self.end_headers()

    def _handle(self) -> None:
        try:
            self._route()
        except Exception as err:
            print(err)
            if not self.wfile.closed:
                try:
                    self._send(500, page("Error", f'<h1>Something went wrong</h1><p class="problem">{esc(err)}</p><p><a href="/">Home</a></p>'))
                except Exception:
                    pass

    def _route(self) -> None:
        global stream_status
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        method = self.command
        if path == "/healthz":
            self._send(200, "ok", {"content-type": "text/plain"})
            return
        if path == "/live-status" and method == "GET":
            self._live_status()
            return
        if path == "/styles.css":
            self._send(200, STYLES, {"content-type": "text/css; charset=utf-8", "cache-control": "max-age=300"})
            return
        if path == "/app.js":
            self._send(200, APP_JS, {"content-type": "text/javascript; charset=utf-8", "cache-control": "max-age=300"})
            return
        import re
        scoped = re.fullmatch(r"/u/([A-Za-z0-9_-]{6,32})(/.*)?", path)
        here = account_of(self.headers.get("cookie"), scoped.group(1)) if scoped else None
        sub = (scoped.group(2) or "/") if scoped else None
        if scoped and here is None:
            if sub == "/api/signals":
                self._send(401, json.dumps({"signedIn": False}), {"content-type": "application/json", "cache-control": "no-store"})
                return
            if sub == "/events":
                self._send(204, "")
                return
            self._redirect("/?gone=1", {"status": 303})
            return
        if here and sub == "/events" and method == "GET":
            self._events(here, query)
            return
        if here and sub == "/api/signals" and method == "GET":
            after = int((query.get("after") or ["0"])[0] or 0)
            events = [item for item in reversed(here["session"]["signals"]) if item["id"] > after]
            last = here["session"]["signals"][0]["id"] if here["session"]["signals"] else after
            self._send(200, json.dumps({"signedIn": True, "events": events, "lastId": last, "streamStatus": stream_status}), {"content-type": "application/json", "cache-control": "no-store"})
            return
        if path == "/" and method == "GET":
            first = accounts_of_set(cookies_of(self.headers.get("cookie")).get("aset"))
            if first:
                gone = "?gone=1" if query.get("gone") else ""
                self._redirect(f"/u/{first[0]['session']['account']}/{gone}", {"status": 303})
                return
        if (path == "/" or (here and sub == "/")) and method == "GET":
            session = here["session"] if here else None
            problem = None
            sp = None
            try:
                sp = service_provider()
            except Exception as err:
                _drop_sp()
                problem = f"The service provider is not configured yet: {err}. Run the setup script (python scripts/configure_iya_sts.py)."
            tab = "events" if (query.get("tab") or [""])[0] == "events" else "identity"
            verify = (query.get("verify") or [""])[0]
            notice = "Verification event requested; it shows in the log within a few seconds." if verify == "sent" else "The identity provider refused the verification request; see the demo's log." if verify == "failed" else None
            gone = "The account you opened is no longer signed in here." if query.get("gone") else None
            headers = {}
            if session:
                headers["content-security-policy"] = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
            self._send(200, home(session, sp, gone if gone and not session else problem, tab, notice, accounts_of_set(cookies_of(self.headers.get("cookie")).get("aset")), gone), headers)
            return
        if path == "/saml/metadata" and method == "GET":
            try:
                sp = service_provider()
            except Exception:
                _drop_sp()
                raise
            self._send(200, sp.metadata(), {"content-type": "application/samlmetadata+xml"})
            return
        if path == "/login" and method == "GET":
            self._login(query)
            return
        if path == "/saml/acs" and method in ("GET", "POST"):
            self._acs()
            return
        if here and sub == "/signals/verify" and method == "POST":
            self._verify(here)
            return
        if here and sub == "/signals/clear" and method == "POST":
            here["session"]["signals"] = []
            self._redirect(f"/u/{here['session']['account']}/?tab=events", {"status": 303})
            return
        if here and sub == "/logout" and method == "POST":
            end_session(here["sid"])
            if receiver is not None:
                receiver.untrack(here["sid"])
            tell(here["sid"], "signed-out", {})
            self._redirect("/", {"status": 303})
            return
        if path == "/logout" and method == "POST":
            for item in accounts_of_set(cookies_of(self.headers.get("cookie")).get("aset")):
                end_session(item["sid"])
                if receiver is not None:
                    receiver.untrack(item["sid"])
                tell(item["sid"], "signed-out", {})
            self._redirect("/", {"status": 303, "set-cookie": cookie("aset", "", max_age=0)})
            return
        self._send(404, page("Not found", "<h1>Not found</h1>"))

    def _live_status(self) -> None:
        now = time.time() * 1000
        alive = [found for found in sessions.values() if found["expires"] > now]
        subject = None
        if alive:
            name = getattr(alive[0]["login"], "name_id", None)
            subject = name if isinstance(name, str) and name else None
        body = {
            "signedIn": bool(alive),
            "subject": subject,
            "receiver": receiver_state,
            "events": [{"type": item["type"], "jti": item["jti"]} for item in list(live_events)],
        }
        self._send(200, json.dumps(body), {"content-type": "application/json"})

    def _events(self, here: dict, query: dict) -> None:
        sid = here["sid"]
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-store")
        self.send_header("x-accel-buffering", "no")
        self.end_headers()
        after_header = self.headers.get("last-event-id")
        after = int(after_header or (query.get("after") or ["0"])[0] or 0)
        stream = Stream(self)
        try:
            stream.write("retry: 2000\n\n")
            for entry in reversed(here["session"]["signals"]):
                if entry["id"] > after:
                    stream.write(f"id: {entry['id']}\nevent: signal\ndata: {json.dumps(entry)}\n\n")
            if stream_status:
                stream.write(f"event: stream\ndata: {json.dumps(stream_status)}\n\n")
            listeners.setdefault(sid, set()).add(stream)
            while not stream.closed.wait(20):
                stream.write(": keep-alive\n\n")
        except Exception:
            stream.close()
        finally:
            found = listeners.get(sid)
            if found is not None:
                found.discard(stream)
                if not found:
                    listeners.pop(sid, None)
        self.close_connection = True

    def _login(self, query: dict) -> None:
        sp = service_provider()
        asked = (query.get("binding") or [None])[0]
        response_binding = asked if asked in BINDINGS else None
        nonce = base64.b64encode(secrets.token_bytes(16)).decode()
        again = account_of(self.headers.get("cookie"), (query.get("account") or [""])[0]) if query.get("account") else None
        add = (query.get("add") or [""])[0] == "1"
        request = sp.login(
            relay_state="/",
            nonce=nonce,
            response_binding=response_binding,
            force_authn=bool(add or again),
            subject_hint=again["session"]["login"].name_id if again else None,
            subject_hint_format=again["session"]["login"].name_id_format if again and again["session"]["login"].name_id_format else None,
        )
        jar = cookies_of(self.headers.get("cookie"))
        before = (unseal(jar.get("saml_pending")) or {}).get("ids") or []
        set_now = jar.get("aset")
        pending_body = {"ids": [request.id, *before][:3]}
        if set_now and set_now in account_sets:
            pending_body["set"] = set_now
        pending = cookie("saml_pending", sealed(pending_body), path=urllib.parse.urlsplit(sp.config.acs_url).path or "/", max_age=600, same_site="None")
        if request.binding == "redirect":
            self._redirect(request.url, {"status": 302, "set-cookie": pending, "referrer-policy": "no-referrer"})
            return
        origin = urllib.parse.urlsplit(request.url)
        self._send(200, request.html, {
            "set-cookie": pending,
            "content-security-policy": f"default-src 'none'; script-src 'nonce-{nonce}'; form-action {origin.scheme}://{origin.netloc}; frame-ancestors 'none'; base-uri 'none'",
        })

    def _acs(self) -> None:
        sp = service_provider()
        body = self._body() if self.command == "POST" else None
        pending = unseal(cookies_of(self.headers.get("cookie")).get("saml_pending")) or {}
        clear = cookie("saml_pending", "", path=urllib.parse.urlsplit(sp.config.acs_url).path or "/", max_age=0, same_site="None")
        try:
            login = sp.acs(self.command, self.path, body, request_id=pending.get("ids"))
            now = time.time() * 1000
            if len(sessions) >= MAX_SESSIONS:
                for key, value in list(sessions.items()):
                    if value["expires"] <= now:
                        sessions.pop(key, None)
            if len(sessions) >= MAX_SESSIONS:
                raise RuntimeError("too many sessions")
            sid = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
            cap = login.session_not_on_or_after.timestamp() * 1000 if login.session_not_on_or_after else float("inf")
            until = min(now + SESSION_MS, cap)
            old_set = pending.get("set") or cookies_of(self.headers.get("cookie")).get("aset")
            accounts = accounts_of_set(old_set)
            existing = next((item for item in accounts if same_person(item["session"]["login"], login)), None)
            account = existing["session"]["account"] if existing else base64.urlsafe_b64encode(secrets.token_bytes(9)).rstrip(b"=").decode()
            if existing:
                end_session(existing["sid"])
                if receiver is not None:
                    receiver.untrack(existing["sid"])
                tell(existing["sid"], "replaced", {})
            set_id = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
            order = [sid if item["sid"] == (existing["sid"] if existing else None) else item["sid"] for item in accounts]
            if not existing:
                order.append(sid)
            if old_set:
                account_sets.pop(old_set, None)
            account_sets[set_id] = order
            for item in order:
                if item != sid and item in sessions:
                    sessions[item]["set_id"] = set_id
            sessions[sid] = {"login": login, "expires": until, "signals": [], "set_id": set_id, "account": account}
            if receiver is not None:
                from datetime import datetime, timezone
                receiver.track(sid, login, datetime.fromtimestamp(until / 1000, timezone.utc))
            print(f"signed in {login.name_id} by {login.binding} (assertion {login.assertion_id}); {len(order)} account(s) in this browser")
            longest = max(sessions[item]["expires"] for item in order)
            self._redirect(f"/u/{account}/", {"status": 303, "set-cookie": [clear, cookie("aset", set_id, max_age=max(0, int((longest - now) / 1000)))]})
        except Exception as err:
            what = f"{err.code}: {err}" if isinstance(err, SamlError) else str(err)
            print(f"sign-in refused: {what}")
            self._send(400, page("Sign-in failed", f'<h1>Sign-in failed</h1><p class="problem">{esc(what)}</p><p><a href="/">Start again</a></p>'), {"set-cookie": clear})

    def _verify(self, here: dict) -> None:
        outcome = "failed"
        if receiver is not None and receiver.stream:
            try:
                state = base64.urlsafe_b64encode(secrets.token_bytes(12)).rstrip(b"=").decode()
                verifications_asked[state] = here["sid"]
                if len(verifications_asked) > 1000:
                    verifications_asked.pop(next(iter(verifications_asked)))
                receiver.verify(state)
                outcome = "sent"
            except Exception as err:
                print(f"ssf: verification request refused: {err}")
        if "application/json" in (self.headers.get("accept") or ""):
            self._send(202 if outcome == "sent" else 502, json.dumps({"outcome": outcome}), {"content-type": "application/json", "cache-control": "no-store"})
            return
        self._redirect(f"/u/{here['session']['account']}/?tab=events&verify={outcome}", {"status": 303})


def _secure_from_config() -> None:
    global secure_cookies
    try:
        acs = urllib.parse.urlsplit(port_overrides().get("acsUrl") or f"http://localhost:{PORT}/")
        secure_cookies = acs.scheme == "https" or acs.hostname in ("localhost", "127.0.0.1")
    except Exception as err:
        print(f"cannot read {CONFIG}: {err}")


def main() -> None:
    _secure_from_config()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"saml2-sp demo on port {PORT}, configuration {CONFIG}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if receiver is not None:
            receiver.stop()
        server.server_close()


if __name__ == "__main__":
    main()
