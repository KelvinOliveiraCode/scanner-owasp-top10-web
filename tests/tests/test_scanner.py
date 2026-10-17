"""Testes de integração do motor Scanner (core.py)."""

from __future__ import annotations

from scanner_owasp.core import Scanner
from scanner_owasp.models import Finding

from .conftest import FakeResponse, RecordingGet


def make_scanner_with_fake(response: FakeResponse) -> tuple[Scanner, RecordingGet]:
    scanner = Scanner(timeout=1)
    fake = RecordingGet(response)

    def counted(url: str) -> FakeResponse:
        scanner.requests_made += 1
        return fake(url)

    scanner._get = counted  # substitui requisição real por falso determinístico
    return scanner, fake


def test_scan_without_params_runs_headers_and_cookies_only() -> None:
    """URL sem parâmetros de query varre cabeçalhos e cookies, sem SQLi/XSS."""

    response = FakeResponse(text="ok", headers={}, cookies=[])
    scanner, fake = make_scanner_with_fake(response)
    result = scanner.scan("http://example.com/")

    assert len(fake.urls) == 1
    assert scanner.requests_made == 1
    assert any(f.check == "missing-header" for f in result.findings)
    assert not any(f.check in ("sqli", "xss-reflected") for f in result.findings)


def test_scan_with_params_runs_sqli_and_xss() -> None:
    """URL com parâmetros também executa testes de SQLi e XSS."""

    body = "<html>mysql error<script>alert('scanner-xss-reflected')</script></html>"
    response = FakeResponse(text=body, headers={}, cookies=[])
    scanner, fake = make_scanner_with_fake(response)
    result = scanner.scan("http://example.com/item?id=10")

    urls = fake.urls
    assert any("id=" in url for url in urls), urls
    assert any(f.check == "sqli" for f in result.findings), result.findings
    assert any(f.check == "xss-reflected" for f in result.findings), result.findings


def test_scan_started_at_is_iso_timestamp() -> None:
    """started_at é um timestamp ISO 8601."""

    from datetime import datetime

    response = FakeResponse(text="ok", headers={}, cookies=[])
    scanner, _ = make_scanner_with_fake(response)
    result = scanner.scan("http://example.com/")

    datetime.fromisoformat(result.started_at)  # não levanta


def test_scan_result_is_deterministic_given_same_responses() -> None:
    """Mesmas respostas produzem o mesmo número de achados."""

    response = FakeResponse(text="ok", headers={}, cookies=[])
    r1 = make_scanner_with_fake(response)[0].scan("http://example.com/")
    r2 = make_scanner_with_fake(response)[0].scan("http://example.com/")

    assert len(r1.findings) == len(r2.findings)
    assert r1.by_severity() == r2.by_severity()


def test_finding_is_hashable_for_dedup() -> None:
    """Achados são hashable (frozen dataclass), podendo entrar em sets."""

    finding = Finding(
        check="sqli",
        title="T",
        description="d",
        severity="high",
        url="u",
        evidence="e",
        cwe="CWE-89",
        owasp="OWASP A03:2021",
    )
    assert len({finding, finding}) == 1
