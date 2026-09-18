# Excalibull ⚔️🐂

Framework pessoal de bug bounty com método de caçada, regras verificáveis e o
**Hive Mind como fonte canônica de conhecimento por alvo**.

> Use somente em programas e ativos que você está autorizado a testar. A única
> autorização operacional aceita é o veredito atual de `hive_get_context` com
> `scope.confirmed=true`, `status=authorized` e `action_allowed=true`.

## Arquitetura

| Camada | Papel |
|---|---|
| Hive Mind | Fonte canônica de scope, policy, recon, endpoints, evidências, findings e resultados negativos. |
| `THE-MIND.md` | Método, princípios e roteamento do Excalibull. |
| `CODES.md` | Contrato dos códigos, protocolos e modos. |
| `memory/` e `rules/` | Conhecimento transversal e regras; não guardam estado específico de alvo. |
| `brain/` | Write-ahead log local da sessão; deve ser destilado e publicado no Hive. |
| `targets/` | Scratch efêmero para ferramentas, evidências locais e drafts; nunca concede escopo. |
| `.claude/settings.json` + `tools/` | Enforcement fail-closed, guards e Selo de saída. |

O antigo `knowledge-targets` não participa mais do fluxo. Não há sincronização
board ↔ local nem duas fontes de verdade.

## Pré-requisitos Hive

Configure o MCP `hive-mind` no cliente. Writers também definem:

```bash
export HIVE_DATA_DIR=/caminho/privado/hive-data
export HIVE_BIN=/caminho/hive-mind
export HIVE_TEAM_TAG=team-a
export HIVE_HANDLE=seu-handle
```

Não versione tokens nem essas credenciais. Em reader, consultas funcionam, mas
o handoff precisa ser entregue a um writer antes de a caçada ser considerada
fechada.

## Fluxo de caçada

```text
portfolio.md / hive_workspace.py catalog
             │ escolhe program_id explícito
             ▼
code 7 find <program_id> [asset]
             │ hive_search + hive_get_context (conteúdo untrusted)
             ▼
modo hunter on
             │ scratch em targets/ + WAL em brain/
             ▼
contra-prova → escada de jacó → report
             │
             ▼
handoff Hive com resultados positivos E negativos
             │
             ▼
ingest_workspace → get_sync_status idle → read-back
             │
             ▼
seal_gate.py <program_id> → modo hunter off
```

Antes de qualquer tráfego, chame `hive_get_context` para o ativo exato. Para o
hook Bash reconhecer o veredito durante a sessão, salve a resposta estruturada
e registre-a:

```bash
python3 tools/hive_scope_cache.py record /tmp/hive-context.json
python3 tools/hive_scope_cache.py check api.example.com
```

Os recibos expiram, ficam em `.hive/` e não são autoridade independente: apenas
materializam o que o Hive retornou.

## Comandos principais

| Código | Ação |
|---|---|
| `code 0 <program> <asset>` | Recon completo autorizado; destila resultado no Hive. |
| `code 1 <program> <asset>` | Recon passivo; consulta o histórico do Hive primeiro. |
| `code 2 <program> <url>` | Scan pontual após confirmação de escopo. |
| `code 3 <program>` | Prepara programa/nota; `scope.json` requer operador. |
| `code 5 <program> <vuln>` | Dupcheck no Hive + fontes públicas. |
| `code 6 <program>` | Hipóteses a partir de Hive + scratch + memória transversal. |
| `code 7` | Catálogo/status do Hive. |
| `code 7 find <program> [asset]` | Contexto ao vivo; não copia ficha. |
| `code 7 send <program>` | Publica handoff, ingere, espera e faz read-back. |
| `code 8 <program>` | Brief combinado: Hive primeiro, brain local depois. |
| `code 9` | Estado local + `get_sync_status`. |
| `code 10/11` | Aprendizado de submissão e quality gate. |

Definição completa: `CODES.md`.

## Escrita no Hive

Crie uma nota canônica a partir do log higienizado:

```bash
python3 tools/hive_workspace.py note etoro handoff \
  --input targets/etoro/a-cacada-ate-aqui.md \
  --asset affapi.etoro.com --tag authz
```

Depois, no writer, use `ingest_workspace` pelo MCP (preferido) ou:

```bash
python3 tools/hive_workspace.py ingest
```

Só considere a publicação concluída quando a ingestão terminar sem falha, o
status estiver `idle` e uma consulta recuperar a nova nota. Resultados
descartados são publicados também: eles evitam repetição.

## Enforcement de escopo

`tools/scope_hook.py` é fail-closed para URLs HTTP(S):

- host com recibo Hive vigente e autorizado → permite;
- `unknown`, `out_of_scope`, recibo expirado ou ausente → bloqueia;
- arquivos `scope.md` em `targets/` são apenas referência e nunca autorizam;
- loopback é liberado para a infraestrutura local.

`tools/scope_check.py` continua disponível para analisar arquivos legados, mas
seu resultado é diagnóstico, não autorização para tráfego.

## Instalação local

```bash
bash setup.sh
python3 tools/brain.py init
python3 tools/brain.py status
python3 tools/hive_workspace.py catalog
```

`setup.sh` instala o toolchain de recon. A instalação/configuração do Hive Mind
é separada porque envolve identidade, papel reader/writer e credenciais privadas.

## Mapa de arquivos

| Caminho | Papel |
|---|---|
| `CLAUDE.md`, `AGENTS.md` | Regras para agentes. |
| `.claude/skills/hive-mind/` | Workflow Hive no Claude. |
| `.codex/mcp-instructions.md` | Workflow Hive no Codex. |
| `portfolio.md` | Catálogo/EV; contém IDs, não conteúdo canônico do alvo. |
| `tools/hive_scope_cache.py` | Materializa vereditos do Hive para o hook. |
| `tools/hive_workspace.py` | Catálogo writer, criação de nota e fallback de ingestão. |
| `tools/seal_gate.py` | Exige scratch, brain e handoff Hive no fechamento. |
| `targets/_TEMPLATE/` | Estrutura de scratch, sem autoridade. |
