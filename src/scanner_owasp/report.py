"""Relatórios de varredura em JSON e HTML."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from . import __version__
from .models import Finding, ScanResult

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def generate_json(result: ScanResult) -> str:
    """Serializa o resultado em JSON formatado e determinístico."""

    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def _severity_class(severity: str) -> str:
    return {"critical": "crit", "high": "high", "medium": "med", "low": "low"}.get(
        severity, "low"
    )


def generate_html(result: ScanResult) -> str:
    """Gera relatório HTML auto-contido e determinístico."""

    findings = sorted(
        result.findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.title, f.url),
    )

    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td class='sev {_severity_class(finding.severity)}'>{html.escape(finding.severity)}</td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td>{html.escape(finding.check)}</td>"
            f"<td>{html.escape(finding.url)}</td>"
            f"<td>{html.escape(finding.evidence)}</td>"
            f"<td>{html.escape(finding.description)}</td>"
            f"<td>{html.escape(finding.cwe or '-')}</td>"
            f"<td>{html.escape(finding.owasp or '-')}</td>"
            "</tr>"
        )

    summary = result.by_severity()
    summary_row = "".join(
        f"<td>{summary[sev]}</td>" for sev in ("critical", "high", "medium", "low")
    )

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title>Relatório de Varredura — scanner-owasp-top10-web</title>
<style>
body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 2rem; }}
h1 {{ font-size: 1.5rem; margin-bottom: 0.5rem; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; font-size: 0.9rem; }}
th {{ background: #f5f5f5; }}
.sev.critical {{ color: #b00; font-weight: bold; }}
.sev.high {{ color: #c40; font-weight: bold; }}
.sev.med {{ color: #970; }}
.sev.low {{ color: #666; }}
summary {{ display: flex; gap: 1rem; margin: 1rem 0; }}
.summary-item {{ border: 1px solid #ccc; padding: 0.5rem 1rem; border-radius: 0.5rem; }}
pre {{ background: #f8f8f8; padding: 1rem; overflow: auto; }}
</style>
</head>
<body>
<h1>Relatório de Varredura — scanner-owasp-top10-web</h1>
<p><strong>Alvo:</strong> {html.escape(result.target)}</p>
<p><strong>Iniciado em:</strong> {html.escape(result.started_at)}</p>
<p><strong>Requisições:</strong> {result.requests_made}</p>
<div class="summary">
<div class="summary-item">Critical: <strong>{summary['critical']}</strong></div>
<div class="summary-item">High: <strong>{summary['high']}</strong></div>
<div class="summary-item">Medium: <strong>{summary['medium']}</strong></div>
<div class="summary-item">Low: <strong>{summary['low']}</strong></div>
</div>
<table>
<thead>
<tr>
<th>Severidade</th><th>Título</th><th>Verificação</th><th>URL</th><th>Evidência</th><th>Descrição</th><th>CWE</th><th>OWASP</th>
</tr>
</thead>
<tbody>
{''.join(rows) if rows else '<tr><td colspan="8">Nenhum achado.</td></tr>'}
</tbody>
</table>
<p><em>Gerado por scanner-owasp-top10-web {__version__} — relatório de segurança, não é prova de exploração.</em></p>
</body>
</html>"""
