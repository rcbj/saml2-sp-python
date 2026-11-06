# saml2-sp

Server-side SAML 2.0 service provider for Python. It sends a signed `AuthnRequest` on HTTP-Redirect or HTTP-POST, accepts a `Response` on HTTP-POST, HTTP-Redirect, or HTTP-Artifact, verifies XML signatures, decrypts encrypted assertions, and can poll a Shared Signals transmitter for CAEP and RISC events.

License: MIT. `develop` and `main` are one commit. A pull request merged into `main` publishes the package to PyPI after the test workflow succeeds on that commit. A direct push does not. There is no API token: PyPI Trusted Publishing trades the workflow's GitHub OIDC token for a short-lived upload token, from the `pypi` environment, and PyPI holds the publisher for this repository and `publish.yml`. A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published.

## Usage

```python
from saml2_sp import ServiceProvider

sp = ServiceProvider.from_file("saml.json")
request = sp.login(relay_state="/home")
# request.binding is "redirect" (a URL) or "post" (request.html, an auto-posting form)
who = sp.acs(method, url, body, request_id=request.id)
```

`saml.json` uses the same keys as the Node service provider: `entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, and the optional `requestBinding`, `responseBinding`, `idpCa`, `idpEntityId`, `nameIdFormat`, `clockSkewSeconds`, `wantAssertionsSigned`, `wantAssertionsEncrypted`, `allowUnsolicited`, and `signals`. A value may be PEM text, a file path, or an `env:` / `file:` placeholder. `signals` omitted or `true` leaves the Shared Signals receiver available. `false` turns it off and does not require transmitter metadata. Any other value is a configuration error: `signals must be true or false`. The resolved configuration omits `signals` when the receiver is on and includes `signals: false` when it is off. SAML does not send OAuth scopes, so the flag does not change the `AuthnRequest`.

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  saml2-sp-python-demo \
  saml2-sp generate-keys --config demo/saml.json
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  saml2-sp-python-demo \
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
docker build --target test .
```

The suite runs in a container.

The tests sign, encrypt, and decrypt with `cryptography` and exclusive canonicalization from `lxml`. They include a stub identity provider and a stub transmitter. Those stub tests do not start iya-sts.

`python3 scripts/live_iya_sts.py` is the live half. It starts the latest main branch of iya-sts in memory mode with persistence and clustering off when `IYA_STS_URL` is unset, runs the install script in a scratch copy of this checkout (which registers the demo and writes the `idpCa` chain), then builds this demo image from it, checks the image carries the chain and no key, starts the demo with no CA mount, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It uses two high ports (defaults 18546 and 18646, `LIVE_STS_PORT` and `LIVE_DEMO_PORT`) and never binds 3000, 8081 or 18481-18495. The nightly workflow runs the unit suite and this script once every 24 hours.

## Layout

- `src/saml2_sp/` the library (`ServiceProvider`, metadata, bindings, signatures, encryption, the replay cache, `ssf/`)
- `tests/` pytest, including the stub identity provider
- `demo/` the stdlib `http.server` application
- `scripts/configure_iya_sts.py` registers that demo with iya-sts and writes the listener CA trust chain to the file `idpCa` names. A password iya-sts generates for the test user is never printed: it goes to `demo/generated/<user>.password`, mode 0600, and only the path is printed
- `scripts/trust_chain.py` holds `save_trust_chain()` and refreshes that file
- `scripts/live_iya_sts.py` signs the demo in to iya-sts and checks `GET /live-status`
- `.github/workflows/nightly.yml` runs the unit suite and the live script once every 24 hours
- `Dockerfile` and `docker-compose.yml` run the demo (`network_mode: host`, `PORT` defaults to 3000)

## The iya-sts trust chain (`idpCa`)

`idpCa` in `demo/saml.json` names the iya-sts TLS listener CA trust chain the library trusts for the IdP metadata URL, artifact resolution and the Shared Signals transmitter. The default is `file:generated/idp-ca.pem`, relative to `demo/`. The value may also be a plain path, `env:<NAME>`, or the PEM itself. The library loads every certificate in it into the default trust store (`ssl` `load_verify_locations(cadata=...)`), so the whole chain works and OpenSSL ends the path at the self-signed Root.

`scripts/configure_iya_sts.py`, the install script, writes that file on every run (`scripts/trust_chain.py`, `save_trust_chain()`). It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image, and rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`: the SP key, certificate and metadata stay out of the image (compose still mounts `demo/generated` read-only for them). A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `idpCa` file.

**Plain http (#13).** Identity-provider metadata from a URL, artifact resolution and every Shared Signals transmitter call (configuration, JWKS, stream and poll) use https. A plain `http://` URL is refused before any connection unless its host is loopback (`127.0.0.0/8`, `::1`, `localhost`), because metadata carries the signing keys, an `ArtifactResolve` returns the assertion, and Shared Signals carry SETs and the bearer token. A redirect to such a URL is refused the same way. A URL with userinfo is never loopback. The `SamlError` keeps the fetch's code (`metadata`, `artifact`, `ssf`) and names the scheme and host only. There is no opt-out. The service provider's own entityID and ACS URL may stay http; they are never fetched.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, both BuildKit and the classic builder fail. A directory COPY of `demo/` (which always exists) succeeds in both. `python scripts/trust_chain.py --config demo/saml.json --idp <iya-sts URL>` refreshes the file by hand.

## Demo

```bash
docker compose up --build
```

`PORT` defaults to 3000. `GET /healthz` returns `200` and the body `ok` even when the identity provider metadata is not on disk yet. The home page offers sign-in. `/login` answers a signed AuthnRequest (redirect, or a POST form). `/saml/acs` is the assertion consumer. `/saml/metadata` is this service provider's metadata. `GET /live-status` does not need an account id. It is JSON: `signedIn` (true when any local account session exists), `subject`, the receiver state, and the Shared Signals events this process has accepted (`type` and `jti` only). A loopback `entityId` and assertion consumer URL follow `PORT`. Any other host stays as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path; the default `http://localhost:3000` is not treated as an explicit public URL. The live script never binds port 3000 or 8081.

`demo/saml.json` points at `file:` paths under `demo/generated/` and does not contain a key. Generate the key pair and, against a running iya-sts, register the application with:

```bash
python scripts/configure_iya_sts.py
```

The container's `PORT` wins over the shell's `PORT` when that script chooses the entityID and assertion consumer URL. The shipped demo leaves `signals` unset, so the receiver stays on when `ssf.transmitter` is set.
