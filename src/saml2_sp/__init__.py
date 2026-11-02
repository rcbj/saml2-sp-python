# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""saml2-sp: a server-side SAML 2.0 service provider."""

from saml2_sp.bindings import post_form_html
from saml2_sp.config import read_config_file, resolve_config
from saml2_sp.errors import SamlError, SamlStatus
from saml2_sp.replay import MemoryReplayCache
from saml2_sp.service_provider import ServiceProvider
from saml2_sp.ssf.events import CAEP_EVENTS, DEFAULT_ENDING_EVENTS, DEFAULT_EVENTS_REQUESTED, EVENT, RISC_EVENTS, subject_of
from saml2_sp.ssf.receiver import SignalEvent, SignalsReceiver
from saml2_sp.ssf.session_index import DEFAULT_SUBJECT_ATTRIBUTE, MemorySessionIndex, tracked_from
from saml2_sp.x509util import create_self_signed_key_pair

__all__ = [
    "CAEP_EVENTS",
    "DEFAULT_ENDING_EVENTS",
    "DEFAULT_EVENTS_REQUESTED",
    "DEFAULT_SUBJECT_ATTRIBUTE",
    "EVENT",
    "MemoryReplayCache",
    "MemorySessionIndex",
    "RISC_EVENTS",
    "SamlError",
    "SamlStatus",
    "ServiceProvider",
    "SignalEvent",
    "SignalsReceiver",
    "create_self_signed_key_pair",
    "post_form_html",
    "read_config_file",
    "resolve_config",
    "subject_of",
    "tracked_from",
]
