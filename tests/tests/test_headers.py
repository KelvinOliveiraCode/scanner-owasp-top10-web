"""Testes da verificação de cabeçalhos de segurança (headers.py)."""

from __future__ import annotations

from scanner_owasp.headers import check_headers
from scanner_owasp.models import Finding

from .conftest import FakeResponse, assert_findings


def test_missing_all_security_headers_produces_six_findings() -> None:
    """Sem nenhum cabeçalho de segurança, deve haver um achado por cabeçalho."""

    response = FakeResponse(text="ok", headers={})
    findings = check_headers(response, "http://example.com/")

    assert_findings(findings, expected_check="missing-header", min_count=6)
    titles = {f.title for f in findings}
    assert "HSTS ausente" in titles
    assert "Content-Security-Policy ausente" in titles
    assert "X-Frame-Options ausente" in titles
    assert "X-Content-Type-Options ausente" in titles
    assert "Referrer-Policy ausente" in titles
    assert "Permissions-Policy ausente" in titles
    for f in findings:
        assert f.url == "http://example.com/"
        assert f.cwe == "CWE-16"
        assert f.owasp == "OWASP A05:2021"


def test_all_security_headers_present_produces_no_header_findings() -> None:
    """Cabeçalhos presentes não geram achados de ausência."""

    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }
    response = FakeResponse(text="ok", headers=headers)
    findings = check_headers(response, "http://example.com/")

    assert not any(f.check == "missing-header" for f in findings)


def test_header_lookup_is_case_insensitive() -> None:
    """Nomes de cabeçalho são comparados ignorando maiúsculas/minúsculas."""

    response = FakeResponse(text="ok", headers={"Content-Security-Policy": "default-src 'self'"})
    findings = check_headers(response, "http://example.com/")

    assert not any("Content-Security-Policy" in f.title for f in findings)


def test_exposed_server_header_produces_finding() -> None:
    """Cabeçalho Server que expõe tecnologia gera achado de exposição."""

    response = FakeResponse(text="ok", headers={"Server": "nginx/1.2.3"})
    findings = check_headers(response, "http://example.com/")

    exposed = [f for f in findings if f.check == "exposed-header"]
    assert_findings(exposed, min_count=1)
    assert exposed[0].cwe == "CWE-200"
    assert "nginx/1.2.3" in exposed[0].evidence


def test_exposed_x_powered_by_header_produces_finding() -> None:
    """X-Powered-By exposto também gera achado."""

    response = FakeResponse(text="ok", headers={"X-Powered-By": "PHP/8.1"})
    findings = check_headers(response, "http://example.com/")

    exposed = [f for f in findings if f.check == "exposed-header"]
    assert_findings(exposed, min_count=1)
    assert "PHP/8.1" in exposed[0].evidence


def test_findings_are_frozen_dataclasses() -> None:
    """Achados são imutáveis (frozen), adequados a coleções e dedup."""

    response = FakeResponse(text="ok", headers={})
    findings = check_headers(response, "http://example.com/")
    assert isinstance(findings[0], Finding)
