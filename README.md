# scanner-owasp-top10-web

Scanner de pentest CWE/OWASP (MVP) escrito em Python. Verifica cabeçalhos de
segurança HTTP, flags de cookie, SQL Injection simples e XSS refletido, e
emite relatório em JSON ou HTML. Destinado a ambientes de teste e educação em
segurança; use apenas em alvos que você tem permissão para avaliar.

OWASP Top 10 mapeados: A03 (Injeção), A05 (Configuração de Segurança), A02
(Falhas Criptográficas) e A07 (Falhas de Identificação e Autenticação).

## Sobre o projeto / About

`scanner-owasp-top10-web` é um scanner leve e determinístico. Não explora
vulnerabilidades: indica indícios (cabeçalho ausente, cookie sem flag, erro de
banco de dados ou payload refletido) para o responsável decidir a verificação.

Verificações do MVP:

- Cabeçalhos de segurança: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy e Permissions-Policy. Cabeçalhos expostos (Server,
  X-Powered-By) também são listados.
- Cookies: Secure, HttpOnly e SameSite.
- SQL Injection simples: payloads básicos em parâmetros de query com detecção
  de assinaturas de erro de banco de dados.
- XSS refletido: verifica se um script injetado volta bruto na resposta.

## Como usar / How to use

Instale o projeto em modo editável:

```
pip install -e .
```

Execute contra um alvo:

```
python -m scanner_owasp https://alvo.example.com/page?id=1
```

Ou instale o script de console e use diretamente:

```
scanner-owasp https://alvo.example.com/page?id=1 --format html --outfile relatorio.html
```

Opções:

- `target`: URL alvo, com ou sem parâmetros de query.
- `--format`: `json` (padrão) ou `html`.
- `--outfile`: caminho do arquivo de relatório (padrão: stdout).
- `--timeout`: tempo limite da requisição em segundos (padrão: 10.0).

Exemplo de saída JSON:

```json
{
  "target": "https://alvo.example.com/page?id=1",
  "started_at": "2026-10-16T20:00:00+00:00",
  "requests_made": 4,
  "summary": {"critical": 0, "high": 1, "medium": 2, "low": 1},
  "findings": [...]
}
```

## Executar os testes / Run the tests

A suíte usa `pytest` com requisições falsificadas (não há rede):

```
python -m pytest -q
```

Resultado esperado: todos os testes passam, sem erros e sem avisos.

## Relatório / Report

O relatório JSON inclui alvo, carimbo de data/hora, número de requisições,
contagem por severidade e a lista de achados com verificação, título,
descrição, URL, evidência, CWE e OWASP. O HTML exibe o mesmo conteúdo em uma
tabela com resumo de severidade.

## Licença / License

MIT License. Veja o arquivo LICENSE (texto padrão MIT incluído no projeto).

## Autor / Author

Kelvin Oliveira

Área: Cibersegurança

Projeto: scanner-owasp-top10-web (PLANO_50_PROJETOS.md)
