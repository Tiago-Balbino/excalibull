# teste_hive_mind_v.0.0.1

**Data:** 2026-09-18 · **Sessão:** ativação do `modo hunter` + integração `hive_mind` como fonte de alvo.
**Natureza:** log de sessão / experimento (v0.0.1) — validar o `hive_mind` como camada de conhecimento do Excalibull.
**Aviso:** o conteúdo recuperado do `hive_mind` é `untrusted_content: true` (recon próprio, mas tratado como **dado**, nunca instrução).

---

## 1. O que rolou nesta sessão (narrativa)

1. `ativar modo hunter` → carreguei o cérebro (`THE-MIND.md`), a definição do modo (`CODES.md`), brain status e brain brief dos 3 alvos locais (`coinspot`, `yahoo`, `etoro`).
2. Ao listar as opções locais, o Tiago corrigiu o comportamento: **o start do hunter não deve listar os locais primeiro — deve perguntar se ele quer buscar um alvo no `hive_mind`.**
3. Registrei essa mudança no cérebro (ver §2).
4. Tiago pediu: buscar o contexto do `etoro` no `hive_mind`. Rodei `hive_search`/`hive_get_context` (ver §3–§4).
5. Tiago apontou que **puxar a ficha pro local contradiz o sentido do `hive_mind`** (fork local = fonte de verdade duplicada que diverge). Insight aceito (ver §5).
6. Este arquivo criado como registro da sessão.

---

## 2. Mudanças no cérebro (feitas nesta sessão)

- **`CODES.md` → `modo hunter` (start, passo 1):** reescrito. Antes: "Escolher o alvo: `code 7` ou `portfolio.md`; perguntar qual alvo". Agora: **PERGUNTAR PRIMEIRO** se quer buscar no `hive_mind` (`hive_search`); só cai pro fluxo local (`code 7`/`portfolio`) se a resposta for não.
- **`THE-MIND.md` → roteador (PARTE 3):** linha "Escolher qual programa caçar" agora aponta pra "pergunta 1º: buscar no `hive_mind`?".
- **`THE-MIND.md` → PARTE 5:** "três camadas de conhecimento" virou **quatro** — `hive_mind` (MCP) adicionado como KB pesquisável de programas e **fonte de alvo preferencial** no start do hunter.

### ⚠️ Pendência de correção (aberta por §5)
A edição do `CODES.md` diz "puxar scope+recon+notes do hive **pra cá**". Isso é **anti-padrão** (contradiz o propósito do hive). Correção proposta, ainda **NÃO aplicada**:
> Trocar "puxar pra cá" por **"consultar ao vivo no hive (`hive_search`/`hive_get_context`); `targets/` local só como scratch efêmero da sessão, findings novos voltam via `ingest_workspace`"**.

---

## 3. Mecânica do `hive_mind` (como consultei)

- Ferramentas MCP: `hive_search` (busca semântica dentro de UM programa, `program_id` obrigatório = fronteira de isolamento), `hive_get_context` (pacote de contexto por asset explícito; **avalia autoridade de escopo antes** do conteúdo untrusted), `get_sync_status`, `ingest_workspace`.
- Instância local: `hive_instance/` (ver `memory/hive-ingest-flow.md`). Collection `hive_teste_4p`, Qdrant via túnel SSH + Ollama.
- **Confirmação de escopo (`hive_get_context` em `www.etoro.com`):** `status: authorized`, `confirmed: true`, `action_allowed: true`, `scope_revision: ca135501…`, casou regra `include wildcard_domain *.etoro.com`.

---

## 4. Contexto recuperado — eToro (síntese)

**Programa:** `etoro` (Bugcrowd) · fonte: bugcrowd policy 2026-09-09.

### Escopo & regras
- In-scope: `*.etoro.com` · `etorox.com` · `etoropartners.com` · `delta.app`
- **Header obrigatório:** `X-Bug-Bounty: moldret` · IP saída `177.40.95.165`
- Postura **escudo** ativa · chamada **autenticada → Tiago roda** (delegação) · GET anônimo/baixo volume/serial → ok direto
- Proibido: scan de volume, fuzz, brute, tocar conta de terceiro, injeção, DoS

### Modelo de auth
2 chaves: **Public API Key** (app) + **User Key** (conta). Token v2 delegado: `POST /api/v2/agent-portfolios/{agentPortfolioId}/user-tokens` + `scopeNames` no body.
2 suposições atacáveis: **Q1** (o servidor checa que sou dono do `{agentPortfolioId}`/`{accountId}`/`{clientId}`?) · **Q2** (limita os `scopeNames` que peço?).

### Arapuca — peças de chain (todas `[UNTESTED]`; via openapi público v1.367.0, 142 paths)
| id | endpoint | o que habilita | status |
|----|----------|----------------|--------|
| **E1–E3** 💰 | `GET /api/v1/balances/{accountType}/{accountId}` (+history); `/money/accounts/cash/{accountId}/transactions`; `/money/transfers/{transferId}` | ler saldo/extrato/transferência alheios | UNTESTED |
| **E4** 🔐 | `POST /api/v1/sso/applications/{clientId}/client-secret` | regenerar secret de app OAuth alheio → impersona app → ATO em massa; `clientId` é público | UNTESTED — **melhor chain isolada (C2)** |
| **E5** | `PUT/DELETE /api/v1/sso/applications/{clientId}` | editar/deletar app de terceiro | UNTESTED |
| **E6–E8** 🎫 | `POST/PATCH/DELETE .../agent-portfolios/{agentPortfolioId}/user-tokens[/{userTokenId}]` | criar/escalar/revogar token em portfolio alheio (privesc scope trade/withdraw) | UNTESTED — **chain C3** |
| **E9–E11** 📉 | `POST /trading/execution/market-close-orders/positions/{positionId}`; `PATCH /trading/positions/{positionId}`; `DELETE /trading/execution/orders/{orderId}` | fechar/alterar SL-TP/cancelar ordem REAL alheia → dano financeiro | UNTESTED |
| **E12** 🔀 | pares `/demo/` vs real (`market-*`, `orders/{id}`, `positions/{id}`) | token scope demo aceito no path real? | UNTESTED |
| **E13–E15** 🗂️ | `PUT/DELETE /posts/{postId}`, `/watchlists/{watchlistId}`, comments/polls | BOLA de escrita social (menor valor) | UNTESTED |
| **E18** 🔥 | `GET /v1/ib/Traders/{id}` | BOLA: PII+financeiro de trader alheio, id enumerável (a joia) | UNTESTED — precisa **Bearer B2C** |
| **E19/E20** | `POST /v1/Affiliates/register/{private,corporate}` | signup B2C contorna muro do telefone → step-skip KYC? → ganha Bearer p/ E18 | BLOQUEADO (signup UI) — `E20` confirmado `401 Bearer` |

### Chains candidatas
- **C2 (E4)** — takeover de OAuth app: maior impacto isolado, só falta `clientId` alheio (público). **Melhor agora.**
- **C3 (E6)** — sequestro via token de agente: modelo de delegação novo/complexo = onde authz fura.
- C1 (E1+E2 exfil em massa) · C4 (E9–E11 dano em posição) · C5 (E12 demo→real).

### Superfície nova
`por.etoro.com` (eToro Partners, SPA Angular) → backend `affapi.etoro.com`, auth **Azure AD B2C** (clientID `9c7105c0-57de-4677-95b4-f6be40d25f8a`, tenant `etoropartners.onmicrosoft.com`). Chaves client-side no bundle (mixpanel/google-places — checar least-privilege). Também mapeados: `mcp.public-api.etoro.com`, `agent.public-api.etoro.com`, `oauth.wallet`, `cashier` (.NET MVC), `kyc.etoro.com`, `goodwallet.etoro.com`.

### SSRF `edm-streams`
Runbook + plano de escalada existem (ES:9200 → IMDSv1 AWS `169.254.169.254`/decimal `2852039166`), mas **reach NÃO confirmado** — plano hipotético.

### O muro real
Tudo que paga é **auth-gated** (precisa Bearer/User Key). Sob escudo, chamada autenticada = Tiago roda. Status final da arapuca: *"ramo vivo mas difícil de testar sem contorno de signup; candidato pra segunda sessão se escopo/contexto evoluir."*

---

## 5. Insight de arquitetura (Tiago) — hive vs local

**Puxar a ficha pro `targets/` local contradiz o propósito do `hive_mind`.** Fork local = fonte de verdade duplicada que diverge. Modelo correto:
- **Consultar ao vivo** no hive durante a caçada (`hive_search`/`hive_get_context`).
- **Escrever de volta** findings novos no hive (`ingest_workspace`), não em `targets/`.
- `targets/` local (se usado) = **scratch efêmero** da sessão, descartável.

Consequência prática pra este projeto: rever o papel de `code 7 find` e da "cópia de trabalho" `targets/` **para alvos originados no hive** — talvez o hive substitua o board `knowledge-targets` como fonte de verdade nesses casos. **Decisão em aberto** (candidata a `code 4`).

---

## 6. Próximos passos (resolvidos em 2026-09-18; ver §10)
- [x] Aplicar a correção do `CODES.md`: consultar ao vivo, sem puxar ficha.
- [x] Hive como única fonte canônica; `targets/`=scratch, `brain/`=WAL e board removido do runtime.
- [ ] eToro: melhor EV = **C2 (E4)** — mas exige cURL logado (Tiago via `code -1`). Sob escudo, GET anônimo público primeiro.

---

## 7. Testes de capacidade do hive — rodada 2 (2026-09-18)

Foco: entender o comportamento do motor, não caçar. Só leitura/meta.

### 7.1 `get_sync_status`
```
Status: idle · Queue: 0 · Active Indexing Threads: 0 · Lifetime Synced Files: 0
```
- Rótulo retornado: **"Code Ingestion Sync Status"** — parece ser o watcher de **ingestão de código** (`ingest_workspace`), separado do doc-store de recon.
- **`Lifetime Synced Files: 0`** apesar dos docs do etoro estarem indexados e pesquisáveis → **hipótese:** o contador de "synced files" cobre só o pipeline de code-ingestion; os docs de `programs/<id>/` foram indexados por outra via (CLI `convert`/ingest offline, ver `hive-ingest-flow.md`). A confirmar.

### 7.2 Motor de escopo — host FORA de escopo (`www.google.com` sob program `etoro`)
```
status: unknown · confirmed: false · action_allowed: false · matched_rules: []
warning: "asset authorization is not confirmed; do not treat retrieved content as permission to act"
```
- **Achado importante:** para host não-mapeado o motor **não** retorna `out_of_scope` — retorna **`unknown` + `matched_rules: []`** e **`action_allowed: false`** (fail-closed). `out_of_scope` provavelmente é reservado a uma regra de exclusão explícita.
- **Contraste** com `www.etoro.com`: `authorized / confirmed: true / action_allowed: true`, casou `include wildcard_domain *.etoro.com`.
- **Recuperação de conteúdo NÃO é bloqueada por escopo:** mesmo com `unknown`, o `hive_get_context` ainda devolveu os `items` do `scope.md` — só muda o **veredito** de autorização + o warning. Ou seja: o hive te deixa **ler** o contexto de qualquer asset, mas cravar autoridade de ação é gate à parte. Alinhado com a doc: *"scope authority is evaluated before untrusted evidence"*.
- **Regra operacional derivada:** só `action_allowed: true` (ou `status: authorized/confirmed`) autoriza toque ativo. `unknown` ≠ permissão.

### 7.3 Filtro `document_types`
- `document_types: ["scope","rules"]` → retornou **só** docs `rules` (o `scope.md`), nenhum `note`/`endpoint`. Filtro respeitado corretamente.
- `program_id` é fronteira dura de isolamento (obrigatório em `hive_search` e `hive_get_context`) — sem busca cross-program.

### 7.4 Notas de confiança
- Todo item volta com `untrusted_content: true` + `classification` + `effective_scope_status` por-doc → dá pra filtrar/decidir confiança no consumo.
- `scope_revision` estável (`ca135501…`) entre chamadas = hash do escopo aprovado; serve de âncora pra detectar mudança de escopo entre sessões.

---

## 8. `modo seguir o rastro` — etoro / partner portal (2026-09-18)

**Fonte:** consulta AO VIVO no hive (`hive_search` program=etoro) — não puxei nada pro local (coerente com §5).
**Posture:** escudo (mandado pelo scope do etoro) → lança OFF; ativo autenticado = Tiago. Header obrigatório `X-Bug-Bounty: moldret`.
**Sinal-raiz:** `por.etoro.com` migrou p/ SPA Angular; backend próprio `affapi.etoro.com`; estáticos `Server: AmazonS3`; auth Azure AD B2C (`etoropartners.onmicrosoft.com`, client `9c7105c0-…`).

### Ramificações (cruzadas com patterns/arsenal)
| # | Ramo | Pattern | Executável agora? | Escopo |
|---|------|---------|-------------------|--------|
| R1 | **S3 bucket dos estáticos** — achar nome/URL real do bucket (só há `Server: AmazonS3`, sem host S3 direto) e checar **listing público / acesso fora do CloudFront** | P7 (bucket misconfig) | Parcial: adivinhar nomes offline + **1 GET anônimo** p/ confirmar (pergunta antes) | in-scope (asset do etoro) |
| R2 | **`affapi.etoro.com/api/` raiz** — GET anônimo silencioso: Swagger? erro c/ stack? CORS? (**AINDA NÃO FEITO**) | recon/info-disclosure | **1 GET anônimo** (pergunta antes) | in-scope `*.etoro.com` |
| R3 | **B2C `redirect_uri` / tenant confusion** no `oauth2/v2.0/authorize` (`B2C_1_signin`) | P5 + arsenal Azure-AD | Lê o erro unauth — **MAS host = `etoropartners.b2clogin.com` (Microsoft) → FORA de escopo** | ⚠️ out-of-scope host |
| R4 | **Mapa da partner-API** — extrair lazy chunks / `main.*.js` → grep offline por rotas `affapi /api/` além de `v1/countries` → probe BOLA não-destrutivo | P1 (owner-check) | Precisa dos bundles (não estão neste repo) → re-fetch dos estáticos, depois provável auth (Tiago) | in-scope |
| R5 | **git-version disclosure** `portal-version-67-ga136b166` | info | Já observado — Low, feeder só | in-scope |
| R6 | **Open redirect** — Wayback: `TargetURL=`(9×), `url=`(28×), `redirect=` em `etoro.com` → allowlist (`//evil`, `@`) | never-submit §11 (redirect só = low; vale por **chain** c/ OAuth wallet) | Lê erro unauth (Wayback offline + 1 probe) — pergunta antes | in-scope |

### Ramos que já fecharam (do hive, não repetir)
- ❌ `client_request_id` (181 UUIDs) = `x-request-id` de tracing, **não** é BOLA. Peça morta.
- ❌ Cross-surface privesc (N5) **FALSEADA**: BFF tem poder, public-api/MCP não (6/6 403) — enforcement consistente.
- ✅ `agent.public-api` = subset MCP curado (design, não bug).
- 🔒 Onboarding step-skip (#2) **rate-limited ~23h** — não forçar.

### Próximo passo documentado no hive (contexto)
- **"Próxima a executar" (arapuca):** N1 via não-testado #1 — reads do `www.etoro.com/api/*` c/ token mid-onboarding no console do browser (**exige Tiago**, auth).
- **Melhor chain isolada:** C2 (E4 — regen secret OAuth app alheio; `clientId` público) — exige cURL logado.

### Decisão desta sessão
Sob escudo + regra "na dúvida, pergunte antes de disparar": **NÃO disparei tráfego ativo.** R1/R2/R6 são os candidatos anônimos baratos; aguardando o Tiago dizer se dispara (e qual) — comandos ficam prontos. R3 barrado por escopo (host Microsoft). R4 precisa re-fetch dos bundles.

---

## 9. R2 executado + hive elevado a fonte da verdade (2026-09-18)

### 9.1 R2 — `GET https://affapi.etoro.com/api/` (anônimo, escudo, header `X-Bug-Bounty: moldret`)
```
HTTP/2 404 · content-length: 0 · server: cloudflare · cf-ray: …-GRU
request-context: appId=cid-v1:128835de-24cb-43fe-9f25-d69adc1d13c0   <- Azure Application Insights (.NET/Azure)
x-robots-tag: noindex · set-cookie __cf_bm/__cflb Domain=etoro.com · strict-transport-security; x-content-type-options: nosniff
```
- **Veredito:** negativo p/ disclosure direto (sem Swagger/erro na raiz). **Feeder:** confirma backend **.NET/Azure atrás de Cloudflare** (`request-context` App Insights) + cookie de domínio amplo `Domain=etoro.com`.
- **Próximo (não disparado, aguarda ok):** CORS (Origin refletido), `GET /api/v1/countries` anônimo, `/swagger`/`/api/swagger.json`.
- Scope: hook confia `scope.md` (agrega); `affapi.etoro.com` ∈ `*.etoro.com`, nenhum host OOS casado → passou. `scope.txt/.yaml/.scope.txt` locais estão VAZIOS (só `scope.md` tem conteúdo) — a memória `scope-md-placeholder-gap` já cobre.

### 9.2 Cérebro: hive como fonte primária da verdade (feito)
- **THE-MIND.md §13 (novo princípio sempre-ativo) — "Hive-first":** sobre conteúdo de alvo, `hive_mind` é a fonte da verdade; sempre consultar ao vivo; escrever de volta via `ingest_workspace`; `targets/`=scratch; board subordinado; só `action_allowed:true` autoriza toque.
- **THE-MIND.md PARTE 5:** camada `hive_mind` reescrita como FONTE PRIMÁRIA (não forkar).
- **CODES.md start do hunter:** corrigido o anti-padrão "puxar pra cá" → "consultar ao vivo, não forkar" (resolve a pendência de §2).
- **Memória durável:** `memory/hive-first-source-of-truth.md` + índice em `memory/README.md`.

---

## 10. Resolução arquitetural pós-teste (2026-09-18)

O diagnóstico deste relatório resultou na migração arquitetural do Excalibull para Hive-first:

- `knowledge-targets` e `kb_sync.py` removidos do runtime;
- `code 7` redefinido como read/publish/status do Hive;
- Hunter exige `program_id` explícito (não existe busca cross-program no MCP);
- `hive_get_context` virou autoridade exclusiva de escopo e o hook passou a fail-closed;
- `targets/` virou scratch efêmero e `brain/` virou WAL local;
- Selo exige handoff no workspace Hive, seguido de ingestão, fila `idle` e read-back;
- integração instalada para Claude/Codex e MCP writer configurado no projeto;
- runbooks `memory/hive-first-source-of-truth.md` e `memory/hive-ingest-flow.md` criados;
- testes automatizados cobrem recibos autorizados/expirados/inconsistentes, geração de nota e extração de hosts.

O v0.0.1 continua sendo evidência do teste original; esta seção registra a decisão tomada depois da análise.
