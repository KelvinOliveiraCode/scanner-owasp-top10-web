"""Testes simples de SQL Injection (MVP)."""

from __future__ import annotations

import re
from typing import Callable, Literal

import requests

from .models import Finding, Severity

# Payloads básicos de SQL Injection injetados em parâmetros de query.
PAYLOADS: tuple[str, ...] = (
    "'",
    "1' OR '1'='1",
    "1' OR 1=1--",
    "' UNION SELECT NULL,NULL,NULL--",
    "admin'--",
)

# Assinaturas de erro de banco de dados mais comuns (case-insensitive).
ERROR_SIGNATURES: tuple[str, ...] = (
    r"sql syntax",
    r"mysql",
    r"syntax error",
    r"unclosed quotation",
    r"ora-\d{3,5}",
    r"microsoft ole db",
    r"odbc ",
    r"postgresql",
    r"pg_",
    r"sqlite",
    r"quoted string not properly terminated",
)

_ERROR_RE = re.compile("|".join(ERROR_SIGNATURES), re.IGNORECASE)


def _inject(url: str, param: str, payload: str) -> str:
    """Devolve `url` com o valor do parâmetro `param` substituído por `payload`."""

    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_sqli(
    get: Callable[[str], requests.Response],
    url: str,
    params: dict[str, list[str]],
    timeout: float,
) -> list[Finding]:
    """Tenta payloads básicos de SQLi em cada parâmetro de query.

    Um achado por parâmetro vulnerável é suficiente no MVP.
    `get` é um callable que recebe uma URL e devolve uma resposta (permite
    testes off-line com requisições falsificadas).
    """

    findings: list[Finding] = []
    for param in params:
        for payload in PAYLOADS:
            test_url = _inject(url, param, payload)
            try:
                response = get(test_url)
            except requests.RequestException:
                continue
            body = response.text or ""
            match = _ERROR_RE.search(body)
            if match:
                findings.append(
                    Finding(
                        check="sqli",
                        title="SQL Injection possível",
                        description=(
                            f"O parâmetro '{param}' retornou erro de banco de dados "
                            f"com o payload '{payload}'."
                        ),
                        severity="high",
                        url=test_url,
                        evidence=f"assinatura SQL: {match.group(0)}",
                        cwe="CWE-89",
                        owasp="OWASP A03:2021",
                    )
                )
                break
    return findings
