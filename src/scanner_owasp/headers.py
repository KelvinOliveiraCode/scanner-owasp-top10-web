"""Verificação de cabeçalhos de segurança HTTP."""

from __future__ import annotations

from typing import Literal

import requests

from .models import Finding, Severity

# (nome do cabeçalho, título, severidade, CWE, OWASP)
REQUIRED_HEADERS: tuple[tuple[str, str, Severity, str | None, str | None], ...] = (
    ("strict-transport-security", "HSTS ausente", "medium", "CWE-16", "OWASP A05:2021"),
    (
        "content-security-policy",
        "Content-Security-Policy ausente",
        "medium",
        "CWE-16",
        "OWASP A05:2021",
    ),
    ("x-frame-options", "X-Frame-Options ausente", "low", "CWE-16", "OWASP A05:2021"),
    (
        "x-content-type-options",
        "X-Content-Type-Options ausente",
        "low",
        "CWE-16",
        "OWASP A05:2021",
    ),
    ("referrer-policy", "Referrer-Policy ausente", "low", "CWE-16", "OWASP A05:2021"),
    ("permissions-policy", "Permissions-Policy ausente", "low", "CWE-16", "OWASP A05:2021"),
)

# Cabeçalhos de resposta que expõem detalhes da tecnologia do servidor.
EXPOSED_HEADERS: tuple[tuple[str, str, Severity], ...] = (
    ("server", "Server expõe tecnologia", "low"),
    ("x-powered-by", "X-Powered-By expõe tecnologia", "low"),
)


def _headers_map(headers) -> dict[str, str]:
    """Normaliza cabeçalhos para chaves minúsculas (busca insensível a caso)."""

    return {str(k).lower(): str(v) for k, v in headers.items()}


def check_headers(response: requests.Response, url: str) -> list[Finding]:
    """Retorna achados de cabeçalhos de segurança ausentes ou expositores."""

    found = _headers_map(response.headers)
    findings: list[Finding] = []

    for name, title, severity, cwe, owasp in REQUIRED_HEADERS:
        if name not in found:
            findings.append(
                Finding(
                    check="missing-header",
                    title=title,
                    description=(
                        f"O cabeçalho de segurança '{name}' não foi enviado na resposta de {url}."
                    ),
                    severity=severity,
                    url=url,
                    evidence=f"resposta sem cabeçalho {name}",
                    cwe=cwe,
                    owasp=owasp,
                )
            )

    for name, title, severity in EXPOSED_HEADERS:
        if name in found:
            findings.append(
                Finding(
                    check="exposed-header",
                    title=title,
                    description=(
                        f"O cabeçalho '{name}' expõe detalhes da tecnologia do servidor ({found[name]})."
                    ),
                    severity=severity,
                    url=url,
                    evidence=f"{name}: {found[name]}",
                    cwe="CWE-200",
                    owasp=None,
                )
            )

    return findings
