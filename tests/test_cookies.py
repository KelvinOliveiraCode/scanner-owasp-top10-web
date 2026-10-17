"""Testes da verificação de flags de cookie (cookies.py)."""

from __future__ import annotations

from scanner_owasp.cookies import check_cookies
from scanner_owasp.models import Finding

from .conftest import FakeCookie, FakeResponse, assert_findings, make_cookie


def test_cookie_without_any_flag_produces_three_findings() -> None:
    """Cookie sem Secure, HttpOnly nem SameSite gera um achado por flag."""

    response = FakeResponse(
        text="ok",
        cookies=[make_cookie("sessionid", rest={})],
    )
    findings = check_cookies(response, "http://example.com/")

    assert_findings(findings, expected_check="cookie-flag", min_count=3)
    titles = {f.title for f in findings}
    assert "Cookie sem Secure (sessionid)" in titles
    assert "Cookie sem HttpOnly (sessionid)" in titles
    assert "Cookie sem SameSite (sessionid)" in titles
    for f in findings:
        assert f.url == "http://example.com/"
        assert f.evidence.startswith("cookie 'sessionid' sem flag ")


def test_cookie_with_all_flags_produces_no_findings() -> None:
    """Cookie com Secure (atributo), HttpOnly e SameSite não gera achados."""

    cookie = make_cookie(
        "sessionid",
        rest={"httponly": None, "samesite": "Lax"},
        secure=True,
    )
    response = FakeResponse(text="ok", cookies=[cookie])
    findings = check_cookies(response, "http://example.com/")

    assert not findings


def test_secure_flag_is_read_from_cookie_secure_attribute() -> None:
    """Secure vem de cookie.secure; ausente gera achado mesmo com rest vazio."""

    cookie = make_cookie("sessionid", rest={"httponly": None, "samesite": "Lax"})
    response = FakeResponse(text="ok", cookies=[cookie])
    findings = check_cookies(response, "http://example.com/")

    assert any("sem Secure" in f.title for f in findings)
    assert not any("HttpOnly" in f.title for f in findings)
    assert not any("SameSite" in f.title for f in findings)


def test_cookie_flag_presence_not_value_counts_as_present() -> None:
    """Flag presente com valor None conta como definido (não gera achado)."""

    cookie = make_cookie(
        "sessionid",
        rest={"httponly": None},
        secure=True,
        # SameSite ausente propositalmente
    )
    response = FakeResponse(text="ok", cookies=[cookie])
    findings = check_cookies(response, "http://example.com/")

    assert len(findings) == 1, findings
    assert "SameSite" in findings[0].title


def test_multiple_cookies_are_checked_independently() -> None:
    """Cada cookie é avaliado sozinho; achados se acumulam por cookie."""

    response = FakeResponse(
        text="ok",
        cookies=[
            make_cookie("a", rest={}),
            make_cookie("b", rest={"samesite": "Lax"}, secure=True),
        ],
    )
    findings = check_cookies(response, "http://example.com/")

    assert len(findings) == 4, findings  # cookie 'a': 3 flags ausentes + cookie 'b': 1 (httponly)
    names = {f.evidence.split("'")[1] for f in findings}
    assert names == {"a", "b"}


def test_no_cookies_produces_no_findings() -> None:
    """Resposta sem cookies não gera achados."""

    response = FakeResponse(text="ok", cookies=[])
    findings = check_cookies(response, "http://example.com/")

    assert findings == []
