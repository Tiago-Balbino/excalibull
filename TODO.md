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
