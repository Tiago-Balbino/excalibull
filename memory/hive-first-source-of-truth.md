# Hive-first — decisão durável

Desde 2026-09-18, o Hive Mind é a única fonte canônica de conteúdo específico
de alvo no Excalibull: scope, policy, recon, ativos, endpoints, hipóteses,
resultados negativos, evidências, findings e próximos passos.

- `portfolio.md` é catálogo/EV, não base de conhecimento.
- `brain/` é write-ahead log local da sessão.
- `targets/` é scratch efêmero.
- Nenhum arquivo local autoriza tráfego.
- `hive_search` requer um `program_id` já escolhido.
- Só o veredito estruturado de `hive_get_context` com escopo confirmado e
  `action_allowed=true` libera um ativo.
- Fechamento exige nota no workspace Hive, ingestão sem falha, fila `idle` e
  read-back.

Não reintroduzir sync bidirecional ou uma segunda fonte canônica.
