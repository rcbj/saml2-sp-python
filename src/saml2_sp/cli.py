# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""saml2-sp's command line: a key pair, and this service provider's metadata."""

from __future__ import annotations

import json
import os
import sys

from saml2_sp.config import resolve_config
from saml2_sp.service_provider import ServiceProvider
from saml2_sp.x509util import create_self_signed_key_pair

USAGE = """Usage:
  saml2-sp generate-keys --config <saml.json> [--cn <name>] [--days <n>] [--bits <n>] [--force]
  saml2-sp generate-keys --key <file> --cert <file> [--cn <name>] [--days <n>] [--bits <n>] [--force]
      A new RSA key and a self-signed certificate, written where the configuration's privateKey and
      certificate point (or to --key and --cert). Refuses to replace existing files without --force.
      The common name defaults to the host of the configuration's entityId.

  saml2-sp metadata --config <saml.json> [--out <file>] [--entity-id <url>] [--acs-url <url>]
      This service provider's SAML metadata, from the configuration and its certificate. Written to
      --out, or to standard output. --entity-id and --acs-url replace the file's values for this run."""


def parse_args(argv: list[str]) -> tuple[str | None, dict]:
    command = argv[0] if argv else None
    rest = argv[1:]
    args: dict = {}
    index = 0
    while index < len(rest):
        item = rest[index]
        if not item.startswith("--"):
            raise SystemExit(f"unexpected argument {item}\n\n{USAGE}")
        key = item[2:]
        if key in ("force", "help"):
            args[key] = True
        else:
            if index + 1 >= len(rest) or rest[index + 1].startswith("--"):
                raise SystemExit(f"--{key} needs a value\n\n{USAGE}")
            args[key] = rest[index + 1]
            index += 1
        index += 1
    return command, args


def _str(value) -> str | None:
    return value if isinstance(value, str) else None


def key_paths(args: dict) -> dict:
    config_path = _str(args.get("config"))
    key = _str(args.get("key"))
    cert = _str(args.get("cert"))
    common_name = _str(args.get("cn"))
    if config_path:
        with open(config_path, encoding="utf-8") as handle:
            raw = json.load(handle)
        base = os.path.dirname(os.path.abspath(config_path))

        def at(path: str | None, what: str) -> str:
            if not path or "-----BEGIN " in path:
                raise SystemExit(f"{config_path}'s {what} must be a file path for generate-keys to write to")
            value = path[5:] if path.startswith("file:") else path
            if value.startswith("env:"):
                raise SystemExit(f"{config_path}'s {what} must be a file path for generate-keys to write to")
            return value if os.path.isabs(value) else os.path.abspath(os.path.join(base, value))

        key = key or at(raw.get("privateKey"), "privateKey")
        cert = cert or at(raw.get("certificate"), "certificate")
        if not common_name and raw.get("entityId"):
            from urllib.parse import urlparse
            try:
                common_name = urlparse(raw["entityId"]).hostname or raw["entityId"]
            except Exception:
                common_name = raw["entityId"]
    if not key or not cert:
        raise SystemExit(f"generate-keys needs --config, or --key and --cert\n\n{USAGE}")
    return {"key": os.path.abspath(key), "cert": os.path.abspath(cert), "common_name": common_name or "saml2-sp service provider"}


def _write(path: str, text: str, mode: int) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def main(argv: list[str] | None = None) -> None:
    command, args = parse_args(list(sys.argv[1:] if argv is None else argv))
    if not command or args.get("help") or command == "help":
        print(USAGE)
        return
    if command == "generate-keys":
        paths = key_paths(args)
        if not args.get("force") and (os.path.exists(paths["key"]) or os.path.exists(paths["cert"])):
            which = paths["key"] if os.path.exists(paths["key"]) else paths["cert"]
            raise SystemExit(f"{which} already exists; pass --force to replace the key pair.\n"
                             "Replacing it means giving the identity provider the new metadata before the next sign-in.")
        days = int(args["days"]) if _str(args.get("days")) else None
        bits = int(args["bits"]) if _str(args.get("bits")) else None
        if days is not None and days <= 0:
            raise SystemExit("--days must be a positive whole number")
        if bits is not None and bits not in (2048, 3072, 4096):
            raise SystemExit("--bits must be 2048, 3072 or 4096")
        pair = create_self_signed_key_pair(paths["common_name"], days or 1095, bits or 3072)
        _write(paths["key"], pair.private_key_pem, 0o600)
        _write(paths["cert"], pair.certificate_pem, 0o644)
        print(f"Wrote the private key  {paths['key']} (mode 600)")
        print(f"Wrote the certificate  {paths['cert']}")
        print(f"  subject   CN={paths['common_name']}")
        print(f"  valid to  {pair.valid_to}")
        print(f"  sha256    {pair.fingerprint256}")
        return
    if command == "metadata":
        config_path = _str(args.get("config"))
        if not config_path:
            raise SystemExit(f"metadata needs --config\n\n{USAGE}")
        with open(config_path, encoding="utf-8") as handle:
            raw = json.load(handle)
        raw.pop("idpCa", None)
        if _str(args.get("entity-id")):
            raw["entityId"] = args["entity-id"]
        if _str(args.get("acs-url")):
            raw["acsUrl"] = args["acs-url"]
        xml = ServiceProvider(resolve_config(raw, os.path.dirname(os.path.abspath(config_path))), None).metadata()
        target = _str(args.get("out"))
        if target:
            os.makedirs(os.path.dirname(os.path.abspath(target)) or ".", exist_ok=True)
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(xml)
            print(f"Wrote the service provider metadata to {os.path.abspath(target)}")
        else:
            sys.stdout.write(xml)
        return
    raise SystemExit(f"unknown command {command}\n\n{USAGE}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit as err:
        if err.code not in (None, 0):
            sys.stderr.write(f"{err.code if isinstance(err.code, str) else err}\n")
            raise SystemExit(1) from err
        raise
