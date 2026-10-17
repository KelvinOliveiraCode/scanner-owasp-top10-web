"""Motor do scanner: orquestra verificações e agrega achados."""

from __future__ import annotations

from typing import Callable

import requests

from .cookies import check_cookies
from .headers import check_headers
from .models import Finding, ScanResult, Severity
from .sqli import test_sqli
from .xss import test_xss


class Scanner:
    """Executa as verificações do MVP contra um alvo."""

    def __init__(self, timeout: float = 10.0, user_agent: str | None = None) -> None:
        self.timeout = timeout
        self.user_agent = user_agent or (
            "scanner-owasp-top10-web/0.1.0 (security scanning)"
        )
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        self.requests_made = 0

    def _get(self, url: str) -> requests.Response:
        """Faz GET registrando o número de requisições (útil para testes)."""

        response = self.session.get(url, timeout=self.timeout)
        self.requests_made += 1
        return response

    def scan(self, target: str) -> ScanResult:
        """Varre `target` e retorna o resultado com todos os achados."""

        from datetime import datetime, timezone

        from urllib.parse import parse_qs, urlparse

        started_at = datetime.now(timezone.utc).isoformat()
        result = ScanResult(target=target, started_at=started_at)

        response = self._get(target)
        result.findings.extend(check_headers(response, target))
        result.findings.extend(check_cookies(response, target))

        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if params:
            result.findings.extend(test_sqli(self._get, target, params, self.timeout))
            result.findings.extend(test_xss(self._get, target, params, self.timeout))

        result.requests_made = self.requests_made
        return result
