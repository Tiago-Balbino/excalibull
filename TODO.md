# TODO — Excalibull

Lista de tarefas pra executar no futuro. Marque `[x]` ao concluir.

## Revisão

- [ ] **Revisar nomenclaturas e codes** — conferir se os nomes de comando (`code N`,
  `protocolo`, `modo`) e a numeração fazem sentido, estão consistentes e sem colisão.
  Estado atual: códigos 0–11; `code 7` = read/publish/status do Hive, brief=8,
  status=9, learn=10, quality=11. Taxonomia fixada:
  code=evento rápido · protocolo=fluxo ligável/desligável · modo=conjunto de protocolos que
  muda como o The Mind pensa. Validar se `code 7 send/find` e o resto
  seguem o padrão, ou se convém reorganizar.

## Construção do cérebro (pendente do plano de criação)

- [ ] `THE-MIND.md` — método (6 perguntas) + princípios sempre-ativos + roteador +
  brain persistente + log de decisões.
- [ ] `rules/` — destilar em PT: `never-submit.md`, `chain-table.md`, `identities.md`,
  `mistakes.md`, `techniques.md`, `waf-bypass.md`, `vendor-fingerprints.md`;
  copiar cru: `payloads.md`; + `rules/README.md` (índice).
- [ ] `tools/` — portar `brain.py` + `file_safety.py` + guards
  (`scope_hook`, `scope_check`, `validity_guard`, `file_path_guard`, `cvss_version_guard`)
  + `seal_gate.py`; criar `.claude/settings.json` (hooks).
- [x] `CODES.md` — modelo religado ao Hive/brain/rules/hooks.
- [ ] `memory/` — `patterns.md` (P1–P8), `arsenal.md`, `signals.md`, `sources.md`, `README.md`.
- [ ] Passe final — cross-refs, dry-run mental ponta a ponta, `git init` + 1º commit.

## Migração Hive Mind

- [x] Remover o board do runtime; Hive é a única fonte canônica por alvo.
- [x] Tornar o hook de escopo fail-closed com recibo de `hive_get_context`.
- [x] Adaptar `code 7`, Hunter, Selo, docs e templates.
- [ ] Migrar qualquer conteúdo legado restante para `programs/<program_id>/` no Hive e validar por read-back.

## Backlog — lacunas vs pentest-agents (trazer em iterações futuras)

Levantadas em 2026-09-08. O excalibull nasceu enxuto/coeso; estas capacidades do
pentest-agents ficaram de fora por escopo. Ordem por valor pro fluxo:

- [ ] **MCP `bounty-platforms`** — sync de escopo/policy/hacktivity + draft/submit via API
  (HackerOne/Bugcrowd/Intigriti/YesWeHack). Fonte: `pentest-agents/mcp-bounty-server/`.
  Roda via `uv` — adaptar pra `python3` ou instalar `uv`. Casaria com `code 10 learn` e o
  `protocolo report`.
- [ ] **MCP `writeup-search`** — busca (FAISS/SQLite) sobre corpus próprio de write-ups;
  alimentaria `modo dojo` e `code 6`. Fonte: `pentest-agents/mcp-writeup-server/` + `rag-builder/`.
- [ ] **Browser stealth (camofox)** — bypass de Cloudflare/Akamai/DataDome. Hoje só citado em
  `rules/techniques.md`; falta `tools/camofox_ctl.sh` + doc. Fonte: `pentest-agents/tools/camofox_ctl.sh`.
- [ ] **Suite SAST** — auditoria white-box de código-fonte (útil p/ alvos open-source como
  Matomo). Fonte: agents `sast-*` + skill `/sast` do pentest-agents. Grande; avaliar se cabe
  na filosofia single-agent.
- [ ] **Tools de automação** — avaliar portar: `intel_engine.py` (ranking de hacktivity),
  `recon-ranker`, `dedup_findings.py`, `journal.py`, `target_selector.py`.
- [ ] **Decisão consciente (NÃO trazer, salvo mudança de filosofia):** os 50 subagents +
  slash commands + `/autopilot` autônomo. Divergem do modelo single-agent/deliberado do sword.
  Registrar como escolha, não esquecimento.

## Ideias / backlog

- [ ] **Corrigir auto-load do cofre (`.secrets/autoload.sh`)** — a var não carrega
  automático na Bash tool: o guard por `$PWD` no `autoload.sh` não bate porque o `~/.zshrc`
  parece ser sourceado antes de o shell estar no dir do projeto (`BUGCROWD_USERNAME` sai
  vazio). Investigar PWD no source-time; opções: remover o guard de `$PWD`, casar por
  `$CLAUDE_PROJECT_DIR`, ou usar hook `chpwd` do zsh. Gatilho já está no `~/.zshrc:111`.
- [ ] (adicione aqui conforme surgirem)

## Protocolo backstage (modo offline) — a construir

Levantado em 2026-09-22. Fallback pra quando o Hive estiver fora do ar (ex.: MCP
`hive_mind`/`hive-mind` com `CONNECT_TIMEOUT`). Enquanto **backstage** estiver ATIVO,
o The Mind opera **local-first em `targets/`** e **não** consulta nem escreve no Hive.

Requisitos (do operador):
- [ ] **Ativação/desativação** — `protocolo backstage on` / `... off` (taxonomia: é
  protocolo = fluxo ligável/desligável). Ao ligar, imprime um banner de modo offline.
- [ ] **Escopo pelo jeito antigo** — ler escopo de `targets/<program_id>/` (o operador
  preenche `scope.md` + `target.yml`, como funcionava antes do Hive-first). Sem escopo
  preenchido, falha fechado (não inventar asset).
- [ ] **Escrita local ingerível** — recon/notas/findings gravados **dentro de
  `targets/<program_id>/`** no MESMO formato que o Hive ingere depois: frontmatter com
  `program_id`, `type`, `classification`, `source`, `timestamp`, `team/handle`,
  `asset_refs` (espelhar o schema de `tools/hive_workspace.py note` e o de
  `memory/hive-ingest-flow.md`). Objetivo: ingestão posterior sem retrabalho.
- [ ] **Roteamento offline** — enquanto ativo, todo passo que hoje chama Hive
  (`hive_search`/`hive_get_context`/`ingest_workspace`) vai pra `targets/` em vez do MCP.
- [ ] **Reconciliação ao voltar** — ao desligar backstage (ou Hive voltar), ingerir o
  delta acumulado em `targets/` para `programs/<program_id>/` no Hive e validar por
  read-back; marcar o que já foi sincronizado pra não duplicar.
- [ ] **DECISÃO DE POLÍTICA (bloqueante do design):** hoje `tools/scope_hook.py` é
  fail-closed e **só** aceita recibo do Hive (`tools/hive_scope_cache.py`); escopo local
  em `targets/` explicitamente NÃO autoriza tráfego (ver `CLAUDE.md`). Backstage colide
  com isso. Definir com o operador uma das opções: (a) backstage é **só leitura/planejamento**
  offline, sem liberar tráfego (mantém fail-closed); (b) criar um recibo local assinado
  pelo operador (flag explícita, TTL curto, trilha de auditoria) que o hook aceite apenas
  em backstage; (c) o hook passa a aceitar `targets/<program_id>/scope.md` como fonte de
  autorização enquanto backstage ativo. Não implementar até o operador escolher.
- [ ] **Nota de higiene** — continuar sem versionar recon cru/PoC/dados reais; sem
  credenciais/cookies/tokens/PII nos arquivos de `targets/`.

Arquivos prováveis: `CODES.md` (definir o protocolo), `THE-MIND.md` (roteador/estado),
`tools/scope_hook.py` + `tools/hive_scope_cache.py` (a decisão de política acima),
`targets/_TEMPLATE/` (formato ingerível), e um `tools/backstage.py` p/ ligar/desligar +
reconciliar.

## `modo backstorage` (Hive local) + `protocolo fechar a porta` — a construir

Levantado em 2026-09-22. Evolução do `backstage` acima: em vez de operar só em `targets/`
no formato antigo, o **`modo backstorage`** sobe um **hive_mind LOCAL** (instância/mirror
local do Hive) para o Excalibull funcionar com a **mesma interface MCP**
(`hive_search`/`hive_get_context`/`ingest_workspace`) **sem depender do servidor remoto/túnel**
(hoje `hive_instance/bin/hive-teste` fala com Qdrant remoto via `scripts/abrir-tunel.sh`,
porta 16334 — ver `memory/hive-ingest-flow.md`). No fim, o **`protocolo fechar a porta`**
sincroniza o local com o Hive canônico e **destrói o cérebro local**.

Requisitos (do operador):
- [ ] **`modo backstorage on/off`** (taxonomia: é *modo* = compõe protocolos + muda a postura).
  Ao ligar, sobe backend local (data dir local + vetor local: Qdrant embarcado/local ou
  fallback + Ollama já é local) e aponta as ferramentas MCP pro local; banner de modo. Ao
  desligar sem `fechar a porta`, mantém o local intacto (não sincroniza sozinho).
- [ ] **Mesma interface** — enquanto ativo, `hive_search`/`hive_get_context`/`ingest_workspace`
  batem no backend local, sem tunnel/`atlasgrid.site`. Escrita no **schema ingerível** (igual
  `tools/hive_workspace.py note`) pra sync limpo depois.
- [ ] **`protocolo fechar a porta`** — sequência de saída, nesta ordem: (1) sync/ingest do
  delta local → Hive canônico (remoto) + **read-back**; (2) confirmar `get_sync_status=idle`
  e 0 falhas; (3) **só então destruir o cérebro local** (apagar data dir/instância local +
  recibos do cache). **Nunca destruir antes de confirmar a publicação remota** (senão perde
  dado). Idempotente: se o remoto estiver fora, aborta a destruição e mantém o local.
- [ ] **DECISÃO DE POLÍTICA (mesma do backstage):** um Hive local **não** deve, por si,
  autorizar tráfego — `tools/scope_hook.py` segue exigindo escopo aprovado + recibo. Definir
  se o backend local pode emitir recibo (aprovação explícita do operador, TTL curto, auditoria)
  ou se `backstorage` é só leitura/planejamento offline. Não implementar até o operador escolher.
- [ ] **Higiene** — sem credenciais/cookies/tokens/PII no local; local não versionado; a
  destruição do `fechar a porta` cobre também qualquer scratch sensível da sessão.

Arquivos prováveis: `CODES.md` (`modo backstorage` + `protocolo fechar a porta`),
`THE-MIND.md` (estado/roteador offline↔online), `.mcp.json` (alternar backend local↔remoto),
`tools/backstage.py`/novo `tools/backstorage.py` (subir/derrubar + sync + tear-down),
`config/` local (data dir + vetor local).
