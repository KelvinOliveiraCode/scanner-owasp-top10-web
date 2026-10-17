"""Testes dos relatórios JSON/HTML (report.py)."""

from __future__ import annotations

import json

from scanner_owasp.models import Finding, ScanResult
from scanner_owasp.report import generate_html, generate_json


def make_result() -> ScanResult:
    result = ScanResult(target="http://example.com/", started_at="2026-10-16T00:00:00+00:00")
    result.findings.append(
        Finding(
            check="sqli",
            title="SQL Injection possível",
            description="O parâmetro 'id' retornou erro de banco de dados.",
            severity="high",
            url="http://example.com/item?id=1'",
            evidence="assinatura SQL: sql syntax",
            cwe="CWE-89",
            owasp="OWASP A03:2021",
        )
    )
    result.findings.append(
        Finding(
            check="missing-header",
            title="HSTS ausente",
            description="O cabeçalho de segurança 'strict-transport-security' não foi enviado.",
            severity="medium",
            url="http://example.com/",
            evidence="resposta sem cabeçalho strict-transport-security",
            cwe="CWE-16",
            owasp="OWASP A05:2021",
        )
    )
    return result


def test_generate_json_is_valid_and_complete() -> None:
    """O JSON gerado pode ser parseado e contém todas as seções."""

    result = make_result()
    data = json.loads(generate_json(result))

    assert data["target"] == "http://example.com/"
    assert data["requests_made"] == 0
    assert len(data["findings"]) == 2
    assert data["summary"] == {"low": 0, "medium": 1, "high": 1, "critical": 0}
    assert data["findings"][0]["cwe"] == "CWE-89"


def test_generate_json_is_deterministic() -> None:
    """Mesmo resultado produz bytes idênticos (sort_keys determinístico)."""

    result = make_result()
    assert generate_json(result) == generate_json(result)


def test_generate_html_contains_finding_data() -> None:
    """O HTML contém título, severidade, CWE e OWASP de cada achado."""

    result = make_result()
    html = generate_html(result)

    assert "SQL Injection possível" in html
    assert "HSTS ausente" in html
    assert "CWE-89" in html
    assert "OWASP A03:2021" in html
    assert "high" in html
    assert "medium" in html


def test_generate_html_contains_summary_counts() -> None:
    """O HTML resume a contagem de achados por severidade."""

    result = make_result()
    html = generate_html(result)

    assert "High: <strong>1</strong>" in html
    assert "Medium: <strong>1</strong>" in html


def test_by_severity_counts() -> None:
    """by_severity conta corretamente achados por severidade."""

    result = make_result()
    assert result.by_severity() == {"low": 0, "medium": 1, "high": 1, "critical": 0}


def test_to_dict_is_serializable() -> None:
    """ScanResult.to_dict produz dicionário totalmente serializável."""

    result = make_result()
    data = result.to_dict()
    json.dumps(data)  # não deve levantar
