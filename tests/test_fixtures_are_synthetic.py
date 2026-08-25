"""Enforce that nothing under tests/ carries real-world data.

Every fixture here is invented, but until now only by discipline. Probity's whole
premise is that evidence files contain hostnames, account ids and secrets worth
protecting, and contributors are asked to attach excerpts of theirs to bug
reports. A pasted-in real fixture would be published forever in the git history,
so the rule is checked, not trusted.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

TESTS_DIR = Path(__file__).parent
FIXTURES_DIR = TESTS_DIR / "fixtures"

# Reserved for documentation and testing, so they can never belong to anyone:
# RFC 2606 (example.*, .invalid, .test, .localhost) and RFC 6762 (.local).
RESERVED_SUFFIXES = (
    ".example.com",
    ".example.org",
    ".example.net",
    ".example",
    ".invalid",
    ".test",
    ".localhost",
    ".local",
)
RESERVED_EXACT = frozenset({"example.com", "example.org", "example.net", "localhost"})

DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Shapes that are a secret whatever domain they sit next to.
CREDENTIAL_SHAPES = {
    "AWS access key id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "JSON web token": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."),
}


def source_files() -> list[Path]:
    return sorted(p for p in TESTS_DIR.rglob("*") if p.is_file() and p.suffix in {".py", ".json"})


def is_reserved(domain: str) -> bool:
    lowered = domain.lower()
    return lowered in RESERVED_EXACT or lowered.endswith(RESERVED_SUFFIXES)


def is_documentation_address(text: str) -> bool:
    """True for addresses that cannot route to a real host."""
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError:
        return True  # Not an address at all (a version string, a date).
    return not address.is_global


def offending_domains(text: str) -> list[str]:
    return sorted({match for match in DOMAIN.findall(text) if not is_reserved(match)})


def offending_addresses(text: str) -> list[str]:
    return sorted({match for match in IPV4.findall(text) if not is_documentation_address(match)})


def test_fixtures_name_only_reserved_domains() -> None:
    for path in sorted(FIXTURES_DIR.rglob("*")):
        if not path.is_file():
            continue
        found = offending_domains(path.read_text(encoding="utf-8"))
        assert not found, f"{path.name} names real domains {found}; use example.com"


def test_fixtures_hold_no_routable_addresses() -> None:
    for path in sorted(FIXTURES_DIR.rglob("*")):
        if not path.is_file():
            continue
        found = offending_addresses(path.read_text(encoding="utf-8"))
        assert not found, f"{path.name} holds routable addresses {found}; use 192.0.2.0/24"


def test_no_credential_shapes_anywhere_in_tests() -> None:
    for path in source_files():
        text = path.read_text(encoding="utf-8")
        for name, pattern in CREDENTIAL_SHAPES.items():
            assert not pattern.search(text), f"{path.name} looks like it carries a {name}"


def test_the_check_recognises_a_real_domain() -> None:
    assert offending_domains('{"host": "mail.acme-corp.es"}') == ["mail.acme-corp.es"]
    assert offending_domains('{"host": "api.example.com"}') == []


def test_the_check_recognises_a_routable_address() -> None:
    assert offending_addresses('"ip": "8.8.8.8"') == ["8.8.8.8"]
    assert offending_addresses('"ip": "10.0.0.4", "tls": "1.3"') == []


def test_the_check_recognises_a_credential() -> None:
    fake_key = "AKIA" + "Q" * 16
    assert CREDENTIAL_SHAPES["AWS access key id"].search(fake_key)
