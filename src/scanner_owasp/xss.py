"""Testes de XSS refletido (MVP)."""

from __future__ import annotations

from typing import Callable, Literal

import requests
from bs4 import BeautifulSoup

from .models import Finding, Severity

# Marcador único injetado para detectar reflexão bruta do payload.
MARKER = "scanner-xss-reflected"
PAYLOAD = f"<script>alert('{MARKER}')</script>"


def _inject(url: str, param: str, payload: str) -> str:
    """Devolve `url` com o valor do parâmetro `param` substituído por `payload`."""

    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def test_xss(
    get: Callable[[str], requests.Response],
    url: str,
    params: dict[str, list[str]],
    timeout: float,
) -> list[Finding]:
    """Verifica se o payload de script é refletido bruto na resposta.

    Usa BeautifulSoup para confirmar que o marcador aparece dentro de um
    elemento <script>, reduzindo falsos positivos em atributos ou texto escapado.
    `get` é um callable que recebe uma URL e devolve uma resposta (permite
    testes off-line com requisições falsificadas).
    """

    findings: list[Finding] = []
    for param in params:
        test_url = _inject(url, param, PAYLOAD)
        try:
            response = get(test_url)
        except requests.RequestException:
            continue
        body = response.text or ""
        soup = BeautifulSoup(body, "html.parser")
        reflected = any(
            MARKER in (script.get_text() or "") for script in soup.find_all("script")
        )
        if reflected:
            findings.append(
                Finding(
                    check="xss-reflected",
                    title="XSS Refletido",
                    description=(
                        f"O parâmetro '{param}' reflete o payload de script sem codificação."
                    ),
                    severity="high",
                    url=test_url,
                    evidence=f"payload refletido: {PAYLOAD}",
                    cwe="CWE-79",
                    owasp="OWASP A03:2021",
                )
            )
            break
    return findings
