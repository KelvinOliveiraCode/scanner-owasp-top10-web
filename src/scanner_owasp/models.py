"""Modelos de dados compartilhados pelo scanner (sem dependências de pacote)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Literal

Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Finding:
    """Um achado de vulnerabilidade produzido por uma verificação."""

    check: str
    title: str
    description: str
    severity: Severity
    url: str
    evidence: str
    cwe: str | None = None
    owasp: str | None = None


@dataclass
class ScanResult:
    """Resultado de uma varredura completa contra um alvo."""

    target: str
    started_at: str
    findings: list[Finding] | None = None
    requests_made: int = 0

    def __post_init__(self) -> None:
        # Evita mutable default: inicializa lista vazia quando não informada.
        if self.findings is None:
            self.findings = []

    def to_dict(self) -> dict:
        """Serializa o resultado para dicionário (pronto para JSON)."""

        return {
            "target": self.target,
            "started_at": self.started_at,
            "requests_made": self.requests_made,
            "findings": [asdict(f) for f in self.findings],
            "summary": self.by_severity(),
        }

    def by_severity(self) -> dict[Severity, int]:
        """Conta achados agrupados por severidade."""

        summary: dict[Severity, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for finding in self.findings:
            summary[finding.severity] += 1  # type: ignore[index]
        return summary
