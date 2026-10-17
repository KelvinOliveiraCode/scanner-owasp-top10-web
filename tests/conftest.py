"""Fixtures e utilitários compartilhados pelos testes do scanner."""

from __future__ import annotations

import requests

from scanner_owasp.models import Finding


class FakeResponse:
    """Resposta HTTP falsa para testes off-line e determinísticos."""

    def __init__(self, text="", headers=None, cookies=()) -> None:
        self.text = text
        self.headers = dict(headers or {})
        self.cookies = list(cookies)


class FakeCookie:
    """Cookie falso compatível com requests.cookies.Cookie."""

    def __init__(
        self,
        name: str,
        value: str = "x",
        rest: dict | None = None,
        secure: bool = False,
    ) -> None:
        self.name = name
        self.value = value
        self.rest = dict(rest or {})
        self.secure = secure
        self.domain = "example.com"
        self.path = "/"


class RecordingGet:
    """Callable que grava as URLs requisitadas e devolve uma resposta fixa."""

    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.urls: list[str] = []

    def __call__(self, url: str) -> FakeResponse:
        self.urls.append(url)
        return self.response


def make_cookie(name: str, **kwargs) -> FakeCookie:
    return FakeCookie(name, **kwargs)


def assert_findings(
    findings: list[Finding],
    expected_check: str | None = None,
    expected_severity: str | None = None,
    min_count: int = 1,
) -> None:
    assert len(findings) >= min_count, findings
    if expected_check is not None:
        assert all(f.check == expected_check for f in findings), findings
    if expected_severity is not None:
        assert all(f.severity == expected_severity for f in findings), findings
