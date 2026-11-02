# saml2-sp

Python service provider for SAML 2.0 Web Browser SSO, plus a Shared Signals poll receiver. Version 0.1.0. MIT. `develop` and `main` are one commit. A pull request merged into `main` publishes the package to PyPI after the test workflow succeeds on that commit. A direct push does not. There is no API token: PyPI Trusted Publishing trades the workflow's GitHub OIDC token for a short-lived upload token, from the `pypi` environment, and PyPI holds the publisher for this repository and `publish.yml`. A version already on PyPI stays there; the next release is a new `version` in `pyproject.toml` (and `VERSION`).

## Usage

`ServiceProvider.from_file("saml.json")`, then `login(relay_state=...)` and `acs(method, url, body, request_id=...)`. JSON keys match the Node configuration (`entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, bindings, `signals`, `ssf`). Methods on the Python API are snake_case (`from_file`, `login`, `acs`, `resolve_config`, `read_config_file`, `post_form_html`).

`signals` omitted or `true` keeps the receiver available and is omitted from the resolved configuration. `false` does not start a receiver and does not require transmitter metadata, and the resolved configuration includes `signals: false`. A non-boolean raises `signals must be true or false`. The flag does not change the AuthnRequest: SAML does not send OAuth scopes.

Request bindings are `redirect` and `post`. Response bindings are `post`, `redirect`, and `artifact`. Artifact resolution is a signed SOAP `ArtifactResolve`. HTTP-Redirect query signatures use RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`). Success is `urn:oasis:names:tc:SAML:2.0:status:Success`. `saml2-sp generate-keys` writes a self-signed RSA certificate.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `pip install --no-cache-dir ".[dev]" && pytest` in `python:3.11-slim`. GitHub Actions uses that command. Do not run pytest on the host. The demo image does not run the suite.

Signatures and decryption are real (`cryptography`, `lxml` exclusive canonicalization). The stub identity provider is in `tests/stub_idp.py`. The stub tests do not start iya-sts. `python3 scripts/live_iya_sts.py` does: it runs the install script in a scratch copy of this checkout (writing the `idpCa` chain), then builds the demo image (which carries the chain), starts it with no CA mount, signs the demo in and checks credential-change and session-revoked on `GET /live-status`. The nightly workflow runs the unit suite and that script once every 24 hours. Neither binds port 3000, 8081 or 18481-18495; the live defaults are 18546 and 18646. `tests/test_trust_chain.py`: the install script writes the whole chain to `idpCa`'s path every run, and the library trusts an HTTPS IdP through that file.

## Layout

`src/saml2_sp/` library, `src/saml2_sp/ssf/` receiver, `tests/`, `demo/app.py`, `scripts/configure_iya_sts.py`, `scripts/trust_chain.py`, `Dockerfile`, `docker-compose.yml`. The image name is `saml2-sp-python-demo`. Compose uses `network_mode: host`, service `saml-demo`, and `ENV PORT=3000` in the image. The health check is `http://127.0.0.1:${PORT}/healthz`.

## The iya-sts trust chain (`idpCa`)

`idpCa` in `demo/saml.json` names the iya-sts TLS listener CA trust chain the library trusts for the IdP metadata URL, artifact resolution and the Shared Signals transmitter. The default is `file:generated/idp-ca.pem`, relative to `demo/`. The value may also be a plain path, `env:<NAME>`, or the PEM itself. The library loads every certificate in it into the default trust store (`ssl` `load_verify_locations(cadata=...)`), so the whole chain works and OpenSSL ends the path at the self-signed Root.

`scripts/configure_iya_sts.py`, the install script, writes that file on every run (`scripts/trust_chain.py`, `save_trust_chain()`). It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

Scripts never print a secret: a generated test-user password goes to `demo/generated/<user>.password` (created 0600, `tests/test_password_file.py`) and only the path is printed; no trace line carries a URL or value derived from a password; secrets reach `docker run` as `-e NAME`; every `ssl.SSLContext` sets `minimum_version = TLSv1_2`.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image, and rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`: the SP key, certificate and metadata stay out of the image (compose still mounts `demo/generated` read-only for them). A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `idpCa` file.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, both BuildKit and the classic builder fail. A directory COPY of `demo/` (which always exists) succeeds in both. `python scripts/trust_chain.py --config demo/saml.json --idp <iya-sts URL>` refreshes the file by hand.

## Demo

`docker compose up --build`. `GET /healthz` is `200` with body `ok`. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, logout of one account or every account, metadata, and per-account Shared Signals events. `GET /live-status` does not need an account id. It is JSON: `signedIn` is true when any local account session exists, plus `subject`, the receiver state, and accepted events (`type` and `jti` only). Loopback entityID and assertion-consumer URLs follow `PORT`. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`. The live script and the nightly workflow never bind port 3000 or 8081.

## Signals

With an `ssf` block and without `"signals": false`, the demo starts one poll receiver on the service provider's certificate (mutual TLS). `scripts/configure_iya_sts.py` registers the SP metadata, pins AES-256-GCM / RSA-OAEP, turns on multiple accounts, and, unless signals are off, grants `ssf.manage`. The container `PORT` wins over the shell `PORT` at registration.
