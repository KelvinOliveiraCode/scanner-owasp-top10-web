"""Interface de linha de comando do scanner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .core import Scanner
from .report import generate_html, generate_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner-owasp",
        description=(
            "Scanner de cabeçalhos de segurança, flags de cookie, "
            "SQL Injection simples e XSS refletido (OWASP Top 10 / CWE)."
        ),
    )
    parser.add_argument("target", help="URL alvo (ex.: https://example.com/page?id=1)")
    parser.add_argument(
        "--format",
        choices=("json", "html"),
        default="json",
        help="formato do relatório (padrão: json)",
    )
    parser.add_argument(
        "--outfile",
        type=Path,
        help="arquivo de saída (padrão: stdout)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="timeout de requisição em segundos (padrão: 10.0)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    scanner = Scanner(timeout=args.timeout)
    result = scanner.scan(args.target)

    report = generate_html(result) if args.format == "html" else generate_json(result)
    if args.outfile:
        args.outfile.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)

    print(
        f"{len(result.findings)} achado(s) em {result.target}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
