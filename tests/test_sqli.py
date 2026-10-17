"""Testes do teste simples de SQL Injection (sqli.py)."""

from __future__ import annotations

import requests

from scanner_owasp import sqli as sqli_mod
from scanner_owasp.models import Finding

from .conftest import FakeResponse, RecordingGet, assert_findings


def get_with_error(body: str) -> RecordingGet:
    return RecordingGet(FakeResponse(text=body))


def test_sqli_detects_sql_error_signature() -> None:
    """Corpo de resposta com erro de banco de dados gera achado de SQLi."""

    fake = get_with_error(
        "<html>You have an error in your SQL syntax near '...' at line 1</html>"
    )
    findings = sqli_mod.test_sqli(fake, "http://example.com/item?id=10", {"id": ["10"]}, 10.0)

    assert_findings(findings, expected_check="sqli", expected_severity="high", min_count=1)
    assert findings[0].cwe == "CWE-89"
    assert findings[0].owasp == "OWASP A03:2021"
    assert findings[0].evidence.startswith("assinatura SQL:")


def test_sqli_known_error_signatures() -> None:
    """Diversas assinaturas de erro de banco são detectadas."""

    signatures = [
        "ORA-00933: SQL command not properly ended",
        "Microsoft OLE DB Provider error",
        "ODBC Driver error",
        "PostgreSQL query failed",
        "Warning: pg_",
        "SQLite exception",
        "unclosed quotation mark",
        "quoted string not properly terminated",
    ]
    for signature in signatures:
        fake = get_with_error(f"<html>error: {signature}</html>")
        findings = sqli_mod.test_sqli(
            fake, "http://example.com/item?id=1", {"id": ["1"]}, 10.0
        )
        assert any(f.check == "sqli" for f in findings), signature


def test_sqli_clean_response_produces_no_findings() -> None:
    """Resposta sem erros de banco não gera achados."""

    fake = get_with_error("<html><body>ok</body></html>")
    findings = sqli_mod.test_sqli(fake, "http://example.com/item?id=10", {"id": ["10"]}, 10.0)

    assert findings == []


def test_sqli_one_finding_per_parameter() -> None:
    """Dois parâmetros vulneráveis geram um achado por parâmetro."""

    fake = get_with_error("<html>mysql error</html>")
    findings = sqli_mod.test_sqli(
        fake,
        "http://example.com/search?q=1&p=2",
        {"q": ["1"], "p": ["2"]},
        10.0,
    )

    assert len(findings) == 2, findings
    urls = {f.url for f in findings}
    assert len(urls) == 2


def test_sqli_request_exception_does_not_crash() -> None:
    """Erro de rede em um payload não interrompe a varredura dos demais."""

    def boom(url: str) -> FakeResponse:
        raise requests.RequestException("conexão recusada")

    findings = sqli_mod.test_sqli(boom, "http://example.com/item?id=10", {"id": ["10"]}, 10.0)

    assert findings == []


def test_sqli_payload_is_injected_into_requested_url() -> None:
    """O payload de SQLi substitui o valor do parâmetro na URL requisitada."""

    fake = get_with_error("<html>syntax error</html>")
    sqli_mod.test_sqli(fake, "http://example.com/item?id=10", {"id": ["10"]}, 10.0)

    assert any("id=1'%20OR%20'1'='1" in url or "id=%27" in url for url in fake.urls)
