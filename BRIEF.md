# BRIEF — scanner-owasp-top10-web

**Projeto:** scanner-owasp-top10-web
**Área:** Cibersegurança
**Stack:** Python 3.10+, requests, beautifulsoup4, pytest
**Destino:** C:\Users\Kelvin\AppData\Local\Temp\opencode\github-staging\projects\scanner-owasp-top10-web\
**Autor:** Kelvin Oliveira

## O que foi entregue

- `src/scanner_owasp/__init__.py` — versão e metadados do pacote.
- `src/scanner_owasp/models.py` — Finding e ScanResult (dataclasses com tipos,
  docstrings, sem mutable defaults).
- `src/scanner_owasp/core.py` — Scanner: orquestra verificações, conta
  requisições, emite ScanResult.
- `src/scanner_owasp/headers.py` — HSTS, CSP, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy; expõe Server e
  X-Powered-By.
- `src/scanner_owasp/cookies.py` — flags Secure, HttpOnly, SameSite.
- `src/scanner_owasp/sqli.py` — SQL Injection simples com assinaturas de erro
  de banco de dados.
- `src/scanner_owasp/xss.py` — XSS refletido com BeautifulSoup (reflexão dentro
  de <script>).
- `src/scanner_owasp/report.py` — relatórios JSON e HTML determinísticos.
- `src/scanner_owasp/cli.py` — interface de linha de comando
  (`python -m scanner_owasp` ou `scanner-owasp`).
- `src/scanner_owasp/__main__.py` — entrada `python -m scanner_owasp`.
- `pyproject.toml` — dependências, entry point, config do pytest.
- `tests/` — 31 testes off-line (requisições falsificadas): cabeçalhos, cookies,
  SQLi, XSS, relatórios e integração do Scanner.
- `README.md` — bilíngue PT-BR + EN (título, descrição, como usar, testes,
  licença, autor).
- `LICENSE` — MIT.
- `BRIEF.md` — este arquivo.

## Critérios de aceitação (PLANO_50_PROJETOS.md)

| Critério | Status |
|---|---|
| Stack Python + requests + BeautifulSoup | OK |
| Escopo MVP: headers, cookies, SQLi simples, XSS refletido | OK |
| Relatório HTML e JSON | OK |
| Testes que passem | OK (veja abaixo) |
| README PT/EN completo | OK |

## Como verificar

1. Entre na pasta do projeto:
   ```
   cd C:\Users\Kelvin\AppData\Local\Temp\opencode\github-staging\projects\scanner-owasp-top10-web
   ```
2. Rode a suíde de testes:
   ```
   python -m pytest -q
   ```
   Resultado esperado: todos os testes passam (31 passed), sem erros e sem
   avisos.
3. Execute o scanner contra um alvo de teste local (exemplo):
   ```
   python -m scanner_owasp http://localhost:8000/pagina?id=1 --format json
   ```
   Saída: JSON com achados, severidades, CWE e OWASP.
4. Gere relatório HTML:
   ```
   python -m scanner_owasp http://localhost:8000/pagina?id=1 --format html --outfile relatorio.html
   ```

## Observações de design

- Determinístico: sem `Math.random`/`Date.now`/relógio nos achados (apenas
  carimbo de início da varredura).
- Sem rede nos testes: todos usam `FakeResponse`/`RecordingGet`.
- Cada achado tem check, título, descrição, severidade, URL, evidência, CWE e
  OWASP (mapeamento de melhor esforço).

## Aviso de uso

Use apenas em alvos sobre os quais você tem permissão explícita para executar
testes de segurança. O scanner indica indícios, não prova exploração.
