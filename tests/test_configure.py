# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The setup script's plan, offline: what it registers, and where."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from configure_iya_sts import (
    ENCRYPTION,
    MULTIPLE_ACCOUNTS,
    demo_port,
    endpoints_for,
    files_of,
    idp_metadata_url,
    metadata_for,
    on_port,
    parse_args,
    plan_for,
    realm_of,
    ssf_calls,
)
from saml2_sp.x509util import create_self_signed_key_pair


@pytest.fixture(scope="module")
def directory(tmp_path_factory):
    folder = tmp_path_factory.mktemp("saml-setup")
    config = folder / "saml.json"
    config.write_text(json.dumps({
        "entityId": "http://localhost:3000/saml/metadata",
        "acsUrl": "http://localhost:3000/saml/acs",
        "privateKey": "generated/sp.key",
        "certificate": "generated/sp.crt",
        "idpMetadata": "generated/idp-metadata.xml",
        "idpCa": "generated/idp-ca.pem",
    }), encoding="utf-8")
    return folder


def test_resolves_the_configurations_files_next_to_it(directory):
    files = files_of(str(directory / "saml.json"))
    assert files.key == str(directory / "generated" / "sp.key")
    assert files.sp_metadata == str(directory / "generated" / "sp-metadata.xml")
    assert files.idp_ca == str(directory / "generated" / "idp-ca.pem")


def test_registers_from_the_metadata_document(directory):
    files = files_of(str(directory / "saml.json"))
    plan = plan_for(files, "https://localhost:8081", "saml-demo-user", "<md:EntityDescriptor/>")
    create = plan[0]
    assert create["path"].endswith("/admin-api/applications/create")
    assert create["body"] == {
        "identifier": "http://localhost:3000/saml/metadata",
        "name": "saml2-sp demo",
        "protocols": ["saml2"],
        "fields": {"samlSpMetadata": "<md:EntityDescriptor/>"},
    }
    assert plan[1]["path"].endswith("/admin-api/saml2/upload-metadata")
    sets = [call["body"] for call in plan if call["path"].endswith("/applications/set")]
    assert {item["attribute"]: item["value"] for item in sets} == ENCRYPTION
    assert any(call["path"] == "https://localhost:8081/saml2/metadata/http%3A%2F%2Flocalhost%3A3000%2Fsaml%2Fmetadata" for call in plan)
    assert next(call["body"] for call in plan if call["path"].endswith("/admin-api/config/set")) == MULTIPLE_ACCOUNTS
    assert plan[-1]["path"].endswith("/users/create")
    assert not any(call["path"].endswith("/users/create") for call in plan_for(files, "https://localhost:8081", "", "x"))


def test_ssf_block_grants_shared_signals_access(directory):
    with_ssf = directory / "saml-ssf.json"
    raw = json.loads((directory / "saml.json").read_text(encoding="utf-8"))
    raw["ssf"] = {"transmitter": "https://localhost:8081"}
    with_ssf.write_text(json.dumps(raw), encoding="utf-8")
    files = files_of(str(with_ssf))
    assert files.ssf_transmitter == "https://localhost:8081"
    calls = ssf_calls(files, "https://localhost:8081", "PEM")
    assert [call["path"].replace("https://localhost:8081/admin-api", "") for call in calls] == [
        "/applications/add", "/roles/add-member", "/tls/trust/add", "/applications/add-certificate",
    ]
    assert calls[0]["body"] == {"application": "http://localhost:3000/saml/metadata", "attribute": "oauthAllowedScope", "value": "ssf.manage"}
    assert calls[1]["body"] == {"role": "SSF_MANAGE", "kind": "application", "member": "http://localhost:3000/saml/metadata"}
    assert any(call["path"].endswith("/applications/add-certificate") for call in plan_for(files, "https://localhost:8081", "", "x"))
    plain = files_of(str(directory / "saml.json"))
    assert not any(call["path"].endswith("/applications/add-certificate") for call in plan_for(plain, "https://localhost:8081", "", "x"))


def test_signals_false_skips_shared_signals_access(directory):
    raw = json.loads((directory / "saml.json").read_text(encoding="utf-8"))
    off = directory / "saml-signals-off.json"
    off.write_text(json.dumps({**raw, "signals": False, "ssf": {"transmitter": "https://localhost:8081"}}), encoding="utf-8")
    files = files_of(str(off))
    assert files.ssf_transmitter is None
    assert files.entity_id == "http://localhost:3000/saml/metadata"
    assert not any(re_path(call["path"]) for call in plan_for(files, "https://localhost:8081", "", "x"))
    bare = directory / "saml-signals-off-no-tx.json"
    bare.write_text(json.dumps({**raw, "signals": False, "ssf": {}}), encoding="utf-8")
    assert files_of(str(bare)).ssf_transmitter is None
    bad = directory / "saml-signals-bad.json"
    bad.write_text(json.dumps({**raw, "signals": "no", "ssf": {"transmitter": "https://localhost:8081"}}), encoding="utf-8")
    with pytest.raises(SystemExit, match="signals must be true or false"):
        files_of(str(bad))


def re_path(path: str) -> bool:
    import re
    return re.search(r"/applications/add$|/roles/add-member|/tls/trust/add|/applications/add-certificate", path) is not None


def test_keeps_a_realms_base_and_refuses_any_other_path():
    assert realm_of("https://idp.test/realm/acme") == {"origin": "https://idp.test", "base": "https://idp.test/realm/acme"}
    with pytest.raises(SystemExit, match="realm"):
        realm_of("https://idp.test/saml2")
    assert idp_metadata_url("https://idp.test/realm/acme", "urn:x") == "https://idp.test/realm/acme/saml2/metadata/urn%3Ax"


def test_takes_its_options_and_refuses_plain_http():
    parsed = parse_args(["--idp", "https://idp.test/", "--public-url", "http://app.test/", "--no-test-user", "--dry-run"], {})
    assert parsed.idp == "https://idp.test"
    assert parsed.public_url == "http://app.test"
    assert parsed.public_url_given is True
    assert parse_args([], {}).public_url_given is False
    assert parse_args([], {"PUBLIC_URL": "http://demo.test"}).public_url_given is True
    assert parsed.test_user == ""
    assert parsed.dry_run is True
    with pytest.raises(SystemExit, match="https"):
        parse_args(["--idp", "http://idp.test"], {})
    with pytest.raises(SystemExit, match="empty"):
        parse_args(["--public-url", ""], {})
    with pytest.raises(SystemExit, match="Unknown argument"):
        parse_args(["--bogus"], {})


def test_registers_a_loopback_entity_on_the_demo_port(directory):
    file = {"entityId": "http://localhost:3000/saml/metadata", "acsUrl": "http://localhost:3000/saml/acs"}
    moved = endpoints_for(file["entityId"], file["acsUrl"], {"public_url_given": False, "port": 3001})
    assert moved["entityId"] == "http://localhost:3001/saml/metadata"
    assert moved["acsUrl"] == "http://localhost:3001/saml/acs"
    assert on_port("http://127.0.0.1:3000/saml/acs", 3001) == "http://127.0.0.1:3001/saml/acs"
    assert on_port("http://[::1]:3000/saml/acs", 3001) == "http://[::1]:3001/saml/acs"
    published = endpoints_for("https://app.example/saml/metadata", "https://app.example/saml/acs", {"public_url_given": False, "port": 3001})
    assert published == {"entityId": "https://app.example/saml/metadata", "acsUrl": "https://app.example/saml/acs"}
    explicit = endpoints_for(file["entityId"], file["acsUrl"], {"public_url": "http://app.test:9", "public_url_given": True, "port": 3001})
    assert explicit == {"entityId": "http://app.test:9/saml/metadata", "acsUrl": "http://app.test:9/saml/acs"}
    assert demo_port("3000", "3001") == 3001
    assert demo_port("3001", "") == 3001
    assert demo_port("3000", "nope") == 3000
    assert demo_port("", None) is None
    assert demo_port("nope", None) is None
    files = files_of(str(directory / "saml.json"))
    endpoints = endpoints_for(files.entity_id, files.acs_url, {"public_url_given": False, "port": 3001})
    files.entity_id = endpoints["entityId"]
    files.acs_url = endpoints["acsUrl"]
    plan = plan_for(files, "https://localhost:8081", "", "<md:EntityDescriptor/>")
    assert plan[0]["body"]["identifier"] == "http://localhost:3001/saml/metadata"
    assert any(call["path"] == idp_metadata_url("https://localhost:8081", endpoints["entityId"]) for call in plan)
    pair = create_self_signed_key_pair("localhost", 30, 2048)
    key = directory / "sp.key"
    cert = directory / "sp.crt"
    key.write_text(pair.private_key_pem, encoding="utf-8")
    cert.write_text(pair.certificate_pem, encoding="utf-8")
    meta = directory / "saml-port.json"
    meta.write_text(json.dumps({
        "entityId": file["entityId"], "acsUrl": file["acsUrl"],
        "privateKey": str(key), "certificate": str(cert),
        "idpMetadata": "https://idp.example/metadata",
        "ssf": {"transmitter": "https://localhost:8081", "pollIntervalMs": 3000},
    }), encoding="utf-8")
    xml = metadata_for(str(meta), endpoints["entityId"], endpoints["acsUrl"])
    assert 'entityID="http://localhost:3001/saml/metadata"' in xml
    assert 'Location="http://localhost:3001/saml/acs"' in xml
    assert "localhost:3000" not in xml
    registered = plan_for(files, "https://localhost:8081", "", xml)[0]["body"]
    assert registered["fields"]["samlSpMetadata"] == xml
    assert json.loads(meta.read_text(encoding="utf-8"))["ssf"]["pollIntervalMs"] == 3000
    assert isinstance(Path, type)
