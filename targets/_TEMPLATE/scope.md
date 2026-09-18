# Escopo — <Nome do Programa>

> CACHE INFORMATIVO, NÃO AUTORIZATIVO. Antes de qualquer tráfego, use
> `hive_get_context` no asset exato. Só `confirmed=true`, `status=authorized` e
> `action_allowed=true` liberam. Registre o recibo com `hive_scope_cache.py`.

Fonte canônica: Hive `programs/<program_id>/scope.json` aprovado pelo operador.
Última consulta: AAAA-MM-DD · scope_revision: <hash ou unknown>

## In scope

| Asset | Tipo | Observações |
|-------|------|-------------|
| `*.exemplo.com` | domínio | wildcard |
| `api.exemplo.com` | API | REST v4 |

## Out of scope

| Asset / classe | Observações |
|----------------|-------------|
| `blog.exemplo.com` | hospedado por terceiro |
| DoS / brute force  | proibido pela política |

## Regras relevantes

- Testes automatizados: permitido? limites de RPS?
- Necessário header/param de identificação? (ex.: `X-Bug-Bounty: <handle>`)
- Contas de teste: como obter.
- Divulgação: coordenada / proibida.

## Histórico de mudanças de escopo

| Data       | Mudança                          |
|------------|----------------------------------|
| AAAA-MM-DD | escopo inicial registrado        |
