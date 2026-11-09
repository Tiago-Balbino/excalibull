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
| `CODES.md` | Contrato dos códigos, protocolos, modos e posturas. |
| `memory/` e `rules/` | Conhecimento transversal e regras; não guardam estado específico de alvo. |
| `brain/` | Write-ahead log local da sessão; deve ser destilado e publicado no Hive. |
| `targets/` | Scratch efêmero para ferramentas, evidências locais e drafts; nunca concede escopo. |
| `.claude/settings.json` + `tools/` | Enforcement fail-closed, guards e Selo de saída. |

O antigo `knowledge-targets` não participa mais do fluxo. Não há sincronização
board ↔ local nem duas fontes de verdade.

## Pré-requisitos Hive

Instale o launcher oficial e o Mind; depois configure os agentes:

```bash
hive install mind
hive login
hive setup
hive doctor
export HIVE_TEAM_TAG=team-a
export HIVE_HANDLE=seu-handle
# Opcional: staging local fora do padrão .hive/outbox/
export EXCALIBULL_OUTBOX_DIR=/caminho/excalibull-outbox
```

O MCP inicia por `hive mind` e consulta o serviço remoto. Tokens ficam sob
responsabilidade do cliente oficial. As ferramentas não leem configuração de
servidor nem abrem túnel. A outbox contém contribuições pendentes; elas precisam
ser entregues a um writer e confirmadas no Hive antes do fechamento.

## Fluxo de caçada

```text
Hive / hive_workspace.py catalog
             │ escolhe program_id explícito
             ▼
code 7 find <program_id> [asset]
             │ hive_search + hive_get_context (conteúdo untrusted)
             ▼
modo hunter on
             │ scratch em targets/ + WAL em brain/
             ▼
postura → protocolos conforme necessidade → contra prova → report PT/EN
             │
             ▼
handoff local com resultados positivos E negativos
             │
             ▼
entrega ao writer → ingestão → get_sync_status idle → read-back
             │
             ▼
seal_gate.py <program_id> → modo hunter off
```

Antes de qualquer tráfego, chame `hive_get_context` para o ativo exato. Para o
hook Bash reconhecer o veredito durante a sessão, salve a resposta estruturada
e registre-a:

```bash
python3 tools/hive_scope_cache.py record /tmp/hive-context.json
python3 tools/hive_scope_cache.py check https://api.example.com/api --program meu-programa
```

Os recibos têm TTL padrão de 15 minutos (máximo uma hora), ficam em `.hive/` e
materializam o veredito para o programa e ativo exatos. Recibos de host não
autorizam URLs; consulte `url_prefix` para cada URL, inclusive redirects e
recursos filhos. A troca de programa/revisão invalida permissões anteriores.

```bash
python3 tools/hive_gateway.py context meu-programa https://api.example.com/api \
  "Escopo e restrições para coletar esta URL" --record
python3 tools/hive_gateway.py capabilities
```

## Comandos principais

O **Carrasco** executa localmente hipóteses delimitadas e vive neste mesmo
repositório GitHub. O **protocolo execução pública** entrega hipótese, plano e
referências de evidência em segundo plano e aguarda o resultado pelo ID:

```sh
python3 tools/carrasco.py validate .hive/carrasco-plan.json
python3 tools/carrasco.py submit .hive/carrasco-plan.json
python3 tools/carrasco.py wait <job_id> --seconds 30
```

Os perfis atuais são somente leitura (GET): `cross-account-read` (leitura entre
duas contas próprias, 6 GETs) e `unauthenticated-read` (objeto privado legível sem
credencial, 4 GETs), ambos com controles, repetição e leitura de volta. Requer
plano/política revisados e autorização do Mind ao vivo; `confirmed` ainda exige
revisão humana. Credenciais e dados de execução ficam locais, fora do Git. [Uso e resultados](docs/CARRASCO.md) ·
[Plano e integração dos produtos Hive](docs/PLANO-CARRASCO.md).

| Código | Ação |
|---|---|
| `code 3` | Auxiliar de casa nova; prepara ficha local, sem aprovar escopo ou publicar. |
| `code 5 <program> <vuln>` | Dupcheck no Hive + fontes públicas. |
| `code 7` | Catálogo/status do Hive. |
| `code 7 find <program> [asset]` | Contexto ao vivo; não copia ficha. |
| `code 7 send <program>` | Publica handoff, ingere, espera e faz read-back. |
| `code 8 <program>` | Brief combinado: Hive primeiro, brain local depois. |
| `code 9` | Estado local + `get_sync_status`. |
| `code 10` | Registrar decisão de método. |
| `code 11` | Quality gate dos rascunhos. |
| `code 12` | Learn: desfecho de submissão. |

Protocolos principais: casa nova, contra prova, report, achar o x, saquear o
navio, pérola negra, seguir o rastro, escada de jacó, formação de tridente e
monitor de métricas. Hunter/bicicleta
permanecem ativos, perguntam postura ao iniciar e são exclusivos de dojo.

Definições: [CODES.md](CODES.md). Uso: [recon](docs/RECON-AMPLIADO.md) e
[monitor](docs/MONITOR.md). Plano futuro: [Odisseia](PLANO-ODISSEIA.md).

## Escrita no Hive

Defina `HIVE_HANDLE` e `HIVE_TEAM_TAG` (sem defaults pessoais) e abra uma sessão
antes dos protocolos. Para retomar, use o mesmo `--session` ou
`EXCALIBULL_SESSION_ID`; omitir a opção reutiliza a sessão ativa do programa.

```bash
python3 tools/hive_outbox.py start etoro --session minha-sessao
python3 tools/hive_outbox.py status etoro
```

Prepare uma contribuição a partir do log higienizado, depois de consolidar o WAL:

```bash
python3 tools/hive_workspace.py note etoro handoff \
  --input targets/etoro/a-cacada-ate-aqui.md \
  --asset affapi.etoro.com --tag authz
```

As notas têm IDs estáveis e revisões imutáveis. Repetir o mesmo conteúdo reutiliza
a contribuição; alterar uma nota com `--replace` cria revisão e invalida a confirmação.

### Caminho padrão: publicação remota direta

Com login de membro (`hive login`) que carrega `product.mind` + `mind.ingest`,
publique sem workspace de writer. Cada nota vai inline pela ferramenta remota
`hive_ingest_document` e o read-back é feito na sequência:

```bash
python3 tools/hive_outbox.py publish etoro
python3 tools/seal_gate.py etoro
```

`publish` ingere uma contribuição por chamada, mapeia o relatório por documento e
só marca `indexed` com publicação confirmada (ou revisão ativa inalterada); depois
roda o `verify`. Limite de 16 KiB UTF-8 por documento no caminho remoto: notas
maiores vão para reconciliação com motivo claro — divida-as. Sem a concessão
`mind.ingest`, a ferramenta não é anunciada e `publish` falha pedindo novo login.

### Fallback: writer local com workspace acessível

Exporte o pacote e entregue-o pelo canal operacional ao writer:

```bash
python3 tools/hive_workspace.py export etoro --output /tmp/etoro-contribution.tar.gz
```

O pacote inclui documentos e manifesto de hashes; sua criação mantém o estado
`pending-writer`. O cliente remoto não faz upload do pacote local (o caminho
remoto envia conteúdo inline, não o `.tar.gz`).
Arquivos antigos fora do manifesto só podem ser exportados com `--legacy-files`,
e esse inventário não satisfaz o Selo nem é ingerido automaticamente.

Quando o workspace operacional do writer estiver acessível, a entrega e a ingestão
exigem caminhos explícitos. A configuração do writer deve ficar fora desse workspace:

```bash
python3 tools/hive_outbox.py deliver etoro --writer-workspace /caminho/workspace-writer
python3 tools/hive_outbox.py ingest etoro --writer-workspace /caminho/workspace-writer \
  --writer-config /caminho/config-writer.toml
python3 tools/hive_outbox.py verify etoro
python3 tools/seal_gate.py etoro
```

`ingest` processa o workspace selecionado pelo MCP oficial e confere relatório por
arquivo; não executa poda. `verify` exige fila confirmada e busca cada path, ID,
revisão e trecho esperado no Hive remoto. A confirmação vale 15 minutos e registra
`retrieved-fragment`: o contrato atual não comprova o hash integral do documento remoto.
Falha parcial, `foreign_writer`, arquivo ausente, `unknown` e divergência mantêm pendência.

O Selo padrão exige a sessão inteira confirmada e scratch/WAL iguais aos consolidados
no handoff. Para apenas encerrar a execução local com publicação pendente explícita,
use `python3 tools/seal_gate.py etoro --handoff-only`; preserve WAL/outbox.

Só considere a publicação concluída quando a ingestão terminar sem falha, o
status estiver `idle` e uma consulta recuperar a nova nota. Resultados
descartados são publicados também: eles evitam repetição.

## Enforcement de escopo

`tools/scope_hook.py` é fail-closed para URLs HTTP(S):

- ativo exato com recibo vigente, programa correto e autorização confirmada → permite;
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
é feita pelo launcher oficial e pelo login no Center.

## Mapa de arquivos

| Caminho | Papel |
|---|---|
| `CLAUDE.md`, `AGENTS.md` | Regras para agentes. |
| `.claude/skills/hive-mind/` | Workflow Hive no Claude. |
| `.codex/mcp-instructions.md` | Workflow Hive no Codex. |
| `portfolio.md` | Referência histórica de EV; seleção de programas vem do catálogo remoto Hive. |
| `tools/hive_gateway.py` | Consulta o MCP oficial pelo launcher `hive mind`. |
| `tools/hive_paths.py` | Resolve somente a outbox local. |
| `tools/hive_scope_cache.py` | Materializa vereditos do Hive para o hook. |
| `tools/hive_workspace.py` | Catálogo remoto, preparação de fichas/notas e exportação para writer. |
| `tools/hive_documents.py` | Metadados e validação comuns, autoria e ativos concretos. |
| `tools/hive_outbox.py` | Sessões, revisões imutáveis, hashes e exportação do conjunto esperado. |
| `tools/hive_publication.py` | Entrega explícita, relatório do writer e read-back por contribuição. |
| `tools/seal_gate.py` | Confere a publicação da sessão; `--handoff-only` mantém pendência explícita. |
| `targets/_TEMPLATE/` | Estrutura de scratch, sem autoridade. |
