# saml2-sp

Server-side SAML 2.0 service provider for Python. It sends a signed `AuthnRequest` on HTTP-Redirect or HTTP-POST, accepts a `Response` on HTTP-POST, HTTP-Redirect, or HTTP-Artifact, verifies XML signatures, decrypts encrypted assertions, and can poll a Shared Signals transmitter for CAEP and RISC events.

Version 0.1.0. License: MIT. `develop` and `main` are one commit. Publishing to PyPI is not set up.

## Usage

```python
from saml2_sp import ServiceProvider

sp = ServiceProvider.from_file("saml.json")
request = sp.login(relay_state="/home")
# request.binding is "redirect" (a URL) or "post" (request.html, an auto-posting form)
who = sp.acs(method, url, body, request_id=request.id)
```

`saml.json` uses the same keys as the Node service provider: `entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, and the optional `requestBinding`, `responseBinding`, `idpCa`, `idpEntityId`, `nameIdFormat`, `clockSkewSeconds`, `wantAssertionsSigned`, `wantAssertionsEncrypted`, `allowUnsolicited`, and `signals`. A value may be PEM text, a file path, or an `env:` / `file:` placeholder. `signals` omitted or `true` leaves the Shared Signals receiver available. `false` turns it off and does not require transmitter metadata. Any other value is a configuration error: `signals must be true or false`. The resolved configuration omits `signals` when the receiver is on and includes `signals: false` when it is off. SAML does not send OAuth scopes, so the flag does not change the `AuthnRequest`.

```bash
saml2-sp generate-keys --config demo/saml.json
saml2-sp metadata --config demo/saml.json
```

## Shared Signals

```python
from saml2_sp import SignalsReceiver

receiver = SignalsReceiver(transmitter="https://idp.example", on_end_sessions=end)
receiver.track(local_id, login)
receiver.start()
```

The receiver discovers the transmitter, keeps one poll stream (`urn:ietf:rfc:8936`), and verifies each Security Event Token against the published JWKS. By default a session ends on `session-revoked`, `account-disabled`, `account-purged`, `credential-compromise`, and `sessions-revoked`.

## Tests

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The tests sign, encrypt, and decrypt with `cryptography` and exclusive canonicalization from `lxml`. They include a stub identity provider and a stub transmitter. They do not need a live iya-sts.

## Layout

- `src/saml2_sp/` the library (`ServiceProvider`, metadata, bindings, signatures, encryption, the replay cache, `ssf/`)
- `tests/` pytest, including the stub identity provider
- `demo/` the stdlib `http.server` application
- `scripts/configure_iya_sts.py` registers that demo with iya-sts
- `Dockerfile` and `docker-compose.yml` run the demo (`network_mode: host`, `PORT` defaults to 3000)

## Demo

```bash
python demo/app.py
```

`PORT` defaults to 3000. `GET /healthz` returns `200` and the body `ok` even when the identity provider metadata is not on disk yet. The home page offers sign-in. `/login` answers a signed AuthnRequest (redirect, or a POST form). `/saml/acs` is the assertion consumer. `/saml/metadata` is this service provider's metadata. A loopback `entityId` and assertion consumer URL follow `PORT`. Any other host stays as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path; the default `http://localhost:3000` is not treated as an explicit public URL.

`demo/saml.json` points at `file:` paths under `demo/generated/` and does not contain a key. Generate the key pair and, against a running iya-sts, register the application with:

```bash
python scripts/configure_iya_sts.py
```

The container's `PORT` wins over the shell's `PORT` when that script chooses the entityID and assertion consumer URL. The shipped demo leaves `signals` unset, so the receiver stays on when `ssf.transmitter` is set.
