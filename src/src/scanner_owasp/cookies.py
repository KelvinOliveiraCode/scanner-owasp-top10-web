"""Verificação de flags de segurança em cookies."""

from __future__ import annotations

from typing import Literal

import requests

from .models import Finding, Severity

# (flag, título, descrição, severidade, CWE, OWASP)
FLAG_CHECKS: tuple[tuple[str, str, str, Severity, str | None, str | None], ...] = (
    (
        "secure",
        "Cookie sem Secure",
        "O cookie foi enviado sem o flag Secure; pode ser transmitido por HTTP.",
        "medium",
        "CWE-614",
        "OWASP A02:2021",
    ),
    (
        "httponly",
        "Cookie sem HttpOnly",
        "O cookie foi enviado sem o flag HttpOnly; é acessível por JavaScript.",
        "medium",
        "CWE-1004",
        "OWASP A07:2021",
    ),
    (
        "samesite",
        "Cookie sem SameSite",
        "O cookie foi enviado sem o flag SameSite; é enviado em requisições de outros sites.",
        "low",
        "CWE-352",
        "OWASP A01:2021",
    ),
)


_MISSING = object()


def _flag_value(cookie, flag: str):
    """Devolve o valor de um flag de cookie, ou _MISSING se o flag não existir.

    A presença do flag importa (mesmo com valor None), não o seu conteúdo.
    No requests, Secure fica em cookie.secure; HttpOnly/SameSite em cookie.rest.
    """

    if flag == "secure":
        return True if getattr(cookie, "secure", False) else _MISSING
    rest = getattr(cookie, "rest", {}) or {}
    for key in (flag, flag.capitalize(), flag.upper()):
        if key in rest:
            return rest[key]
    return _MISSING


def check_cookies(response: requests.Response, url: str) -> list[Finding]:
    """Retorna achados de cookies sem flags de segurança."""

    findings: list[Finding] = []
    for cookie in response.cookies:
        name = cookie.name
        for flag, title, description, severity, cwe, owasp in FLAG_CHECKS:
            if _flag_value(cookie, flag) is _MISSING:
                findings.append(
                    Finding(
                        check="cookie-flag",
                        title=f"{title} ({name})",
                        description=description,
                        severity=severity,
                        url=url,
                        evidence=f"cookie '{name}' sem flag {flag}",
                        cwe=cwe,
                        owasp=owasp,
                    )
                )
    return findings
