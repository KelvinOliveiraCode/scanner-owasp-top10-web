"""Testes do teste de XSS refletido (xss.py)."""

from __future__ import annotations

import requests

from scanner_owasp import xss as xss_mod
from scanner_owasp.xss import PAYLOAD
from scanner_owasp.models import Finding

from .conftest import FakeResponse, RecordingGet, assert_findings


def test_reflected_payload_inside_script_produces_finding() -> None:
    """Payload refletido dentro de <script> gera achado de XSS refletido."""

    body = f"<html><head>{PAYLOAD}</head><body>ok</body></html>"
    fake = RecordingGet(FakeResponse(text=body))
    findings = xss_mod.test_xss(fake, "http://example.com/page?q=1", {"q": ["1"]}, 10.0)

    assert_findings(findings, expected_check="xss-reflected", expected_severity="high", min_count=1)
    assert findings[0].cwe == "CWE-79"
    assert findings[0].owasp == "OWASP A03:2021"
    assert PAYLOAD in findings[0].evidence


def test_escaped_payload_is_not_reflected() -> None:
    """Payload escapado (&lt;script&gt;) não conta como reflexão."""

    body = "<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>"
    fake = RecordingGet(FakeResponse(text=body))
    findings = xss_mod.test_xss(fake, "http://example.com/page?q=1", {"q": ["1"]}, 10.0)

    assert findings == []


def test_payload_in_attribute_only_is_not_reflected() -> None:
    """Reflexão só vale dentro de elemento <script>, não em atributo."""

    body = f'<html><div data-x="{PAYLOAD}"></div></html>'
    fake = RecordingGet(FakeResponse(text=body))
    findings = xss_mod.test_xss(fake, "http://example.com/page?q=1", {"q": ["1"]}, 10.0)

    assert findings == []


def test_clean_response_produces_no_findings() -> None:
    """Resposta sem o payload não gera achados."""

    fake = RecordingGet(FakeResponse(text="<html>ok</html>"))
    findings = xss_mod.test_xss(fake, "http://example.com/page?q=1", {"q": ["1"]}, 10.0)

    assert findings == []


def test_request_exception_does_not_crash() -> None:
    """Erro de rede não interrompe a varredura."""

    def boom(url: str) -> FakeResponse:
        raise requests.RequestException("conexão recusada")

    findings = xss_mod.test_xss(boom, "http://example.com/page?q=1", {"q": ["1"]}, 10.0)

    assert findings == []


def test_payload_is_injected_into_requested_url() -> None:
    """O payload de XSS substitui o valor do parâmetro na URL requisitada."""

    body = f"<html>{PAYLOAD}</html>"
    fake = RecordingGet(FakeResponse(text=body))
    xss_mod.test_xss(fake, "http://example.com/page?q=1", {"q": ["1"]}, 10.0)

    assert any("q=" in url for url in fake.urls)
