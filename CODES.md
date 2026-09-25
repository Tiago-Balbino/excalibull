# CODES, PROTOCOLOS & MODOS — comandos do Excalibull

Três tipos de comando. Todos são **gatilhos que o Claude executa** quando o Tiago os invoca.
Este arquivo é a **fonte da verdade** dos comandos. **Tudo passa pelo [[THE-MIND]] (o cérebro)** —
antes de caçar, o cérebro é consultado e roteia (PARTE 3).

- **Códigos** (`code N`) — **eventos rápidos**: executam uma ação e acabam (uma tacada).
  Ex.: `code 7 send` publica o handoff da sessão no Hive Mind.
- **Protocolos** (`protocolo <nome>`) — **fluxos/funcionalidades nomeados que podem ser
  ligados ou desligados**. Uns rodam uma vez com um objetivo (ex.: `contra-prova`, `report`);
  outros ficam **vivos** enquanto ligados (ex.: `armar a arapuca` = inventário contínuo,
  `monitor` = vigília de mudanças). Ligar/desligar é explícito.
- **Modos** (`modo <nome>`) — um **conjunto de protocolos + fluxos que afeta diretamente
  como o The Mind pensa e opera** enquanto está ligado. Um modo compõe protocolos e muda a
  postura (ex.: `modo hunter` compõe contra-prova + escala + lança; `postura escudo` muda o
  que é permitido tocar).

> **Regra de ouro:** nenhum arquivo local autoriza tráfego. Antes de tocar no ativo, chamar
> `hive_get_context`; só `confirmed=true`, `status=authorized` e `action_allowed=true` liberam.
> `unknown` ou ausência falham fechados. Humano sempre submete.

---

## Códigos

| Código | Nome | Resumo |
|--------|------|--------|
| `code -1 <alvo>` | Salvar sessão viva | cola cookie/cURL autenticado colado pelo Tiago → grava em scratchpad (fora do repo) |
| `code 0 <program> <asset>` | Recon completo | consulta Hive → confirma escopo → recon em scratch → publica síntese |
| `code 1 <program> <asset>` | Recon passivo | consulta Hive antes da enumeração passiva e publica o delta |
| `code 2 <program> <url>` | Scan alvo único | confirma o asset no Hive e audita CORS/headers |
| `code 3 <program>` | Programa novo | prepara scratch/nota; scope canônico só pelo operador |
| `code 4 "<decisão>"` | Registrar decisão | adiciona bloco no [[THE-MIND]] (log) |
| `code 5 <program> <vuln>` | Dupcheck | Hive primeiro; depois brain local e hacktivity pública |
| `code 6 <program>` | Gerar hipóteses | casa Hive + scratch × memória transversal → leads `[UNTESTED]` |
| `code 7 send <program>` | Publish → Hive | nota focada → ingestão → fila idle → read-back |
| `code 7 find <program> [asset]` | Read ← Hive | contexto ao vivo; nunca cria fork local |
| `code 7` | Hive status/catalog | status MCP + catálogo explícito de `program_id` |
| `code 8 <program>` | Brief | Hive primeiro + WAL local (`brain.py brief`) |
| `code 9` | Status | `get_sync_status` + visão do brain local |
| `code 10 <report> <status> [--bounty $X]` | Learn | registra o desfecho de uma submissão no brain (alimenta EV futuro) |
| `code 11 <draft>` | Quality | pontua um rascunho de report antes de submeter (steelman do triager) |

### `code -1 <alvo>` — Salvar sessão viva (evento rápido, fora do repo)
Quando o Tiago cola uma sessão autenticada (cookie/cURL "Copy as cURL" do DevTools) pra eu usar no `formação de lança`, ela **nunca** vai pro repo — vai só pro scratchpad da sessão de trabalho.
1. Extrair o cookie/header relevante do que o Tiago colou.
2. Gravar em `$SCRATCHPAD/<alvo>_session.env` (a pasta scratchpad da sessão atual — fora do projeto, não versionada), `chmod 600`, formato `VARIAVEL='valor'` pra dar `source`.
3. **Nunca** escrever credenciais em `targets/`, `brain/`, `memory/`, Hive ou qualquer caminho do repo — só no scratchpad privado. Se já existir, substituir pela sessão nova.
4. Confirmar em 1 linha: caminho do arquivo + o que foi extraído (ex.: "cookie de sessão Yahoo, GUID X"). Nunca ecoar o valor bruto de volta no chat depois de salvo.
5. Toda request feita com essa sessão ainda carrega header/rate recuperado do Hive — a sessão salva não isenta policy nem nova confirmação do asset.
> Guardrail do `file_path_guard`/higiene: se alguma tentativa de escrita com token/cookie literal cair dentro de `targets/`, é a **regra de segurança** (CLAUDE.md) que barra, não este code — `code -1` é a válvula de escape correta pra esse dado.

### `code 0 <program> <asset>` — Recon completo
1. `hive_search` pelo asset, recon anterior, regras e negativos; não repetir trabalho.
2. `hive_get_context` no asset exato e cachear o veredito para o hook.
3. `python3 tools/recon.py <asset> --all --out targets/<program>/recon` e scanners complementares.
4. Manter bruto no scratch; destilar delta, endpoints e negativos em handoff Hive com `asset_refs`.
5. `code 7 send <program>` publica e verifica. O hook bloqueia ausência/expiração de autorização.

### `code 1 <program> <asset>` — Recon passivo
- Consultar o Hive primeiro; rodar `recon.py` sem probe/crawl em `targets/<program>/recon`; publicar apenas o delta útil.

### `code 2 <program> <url>` — Scan alvo único
- Confirmar o host por `hive_get_context`, cachear o recibo e rodar `cors_headers_scan.py` em scratch; publicar resultado positivo ou negativo.

### `code 3 <program>` — Programa novo
- Validar o `program_id`; criar scratch a partir de `targets/_TEMPLATE/` se necessário e preparar notas em `$HIVE_DATA_DIR/programs/<program>/`. `scope.json`/`rules.md` e aprovação de escopo pertencem ao operador; o agente nunca os inventa. Finalizar com ingestão e read-back.

### `code 4 "<decisão>"` — Registrar decisão
- Acrescentar bloco no [[THE-MIND]] PARTE 6 (Data · Decisão · Por quê · Status).

### `code 5 <program> <vuln>` — Dupcheck (evento rápido)
Checa se a vulnerabilidade **já foi reportada** antes de investir tempo.
1. **Hive:** `hive_search` por mecânica, endpoint, finding, descarte e sinônimos dentro do programa.
2. **WAL/local:** grep no `brain/` e scratch atual apenas para itens ainda não publicados.
3. **Público:** known-issues da policy recuperada e hacktivity pública por título/mecânica.
4. **Veredito:** `PROVÁVEL DUPLICATA` (com a referência) · `NOVO` · `INCERTO`. Duplicata → não reportar (ou só se demonstrar impacto novo). Registrar no brain se duplicata (`status duplicate`).
> Guardrail: só leitura/OSINT. Não dispara probe.

### `code 6 <program>` — Gerar hipóteses (motor de hipóteses)
Casa o **corpus de recon** do alvo contra `memory/signals.md` **e** as âncoras-feeder de
`rules/chain-table.md`, e produz leads `[UNTESTED]` **rankeados** no WAL/handoff.
1. Carregar o banco: `memory/signals.md` + `patterns.md` + `arsenal.md` + `rules/chain-table.md`.
2. Reunir o corpus: `hive_search` (ativos/endpoints/notas/evidências/descartes) + scratch ainda não publicado.
3. **Pass 1 — sinais únicos:** varrer o corpus contra cada `Sinal:` do `signals.md`. Cada hit → hipótese (sinal · pattern P# · hipótese · probe 🟢/🔴 · FP).
4. **Pass 2 — composição:** dos sinais acesos, quais pares/trios casam um gatilho de chain (`C-*` / âncora-feeder de `chain-table`) → hipótese de chain.
5. **Rankear** por (impacto × plausibilidade × probe barato). Probe 🟢 sobe.
6. **Escrever** os top-N como leads `[UNTESTED]` no WAL; publicar no Hive ao fechar.
7. **Resumo no chat:** quantos sinais acenderam, top-3, o que dá pra testar em silêncio.
> **Guardrail:** `code 6` só faz matching e leitura — nunca dispara o probe sozinho.

### `code 7 send|find [<program>]` — Interface Hive
- `code 7 find <program> [asset]`: `hive_search` por visão geral/estado/negativos; se houver asset, `hive_get_context`. Não copiar documentos para `targets/`.
- `code 7 send <program>`: higienizar e criar notas focadas com `tools/hive_workspace.py note`; chamar `ingest_workspace`; exigir relatório sem falhas, `get_sync_status=idle` e read-back da nova nota.
- `code 7`: chamar `get_sync_status` e listar IDs conhecidos de `portfolio.md`; em writer, confirmar com `python3 tools/hive_workspace.py catalog`.
> Não existe busca cross-program no MCP. Catálogo escolhe o ID; busca semântica começa depois.

### `code 8 <program>` — Brief combinado
- Consultar Hive por estado, endpoints, negativos e próximos passos; depois `brain.py brief <program>` para o WAL ainda não publicado. Divergência é resolvida em favor do Hive e o WAL deve ser reconciliado.

### `code 9` — Status Hive + WAL
- `get_sync_status` primeiro; depois `python3 tools/brain.py status`. Fila/ingestão com erro impede assumir que o Hive está atualizado.

### `code 10 <report> <status> [--bounty $X]` — Learn (evento rápido)
Registra o **desfecho de uma submissão** pra alimentar decisões de EV futuras (§10 "seguir o dinheiro").
Ex.: `code 10 report-idor-figma aceito --bounty 2000 --vuln-type IDOR`.
1. Gravar no brain: `python3 tools/brain.py record <alvo> <status> "submissão:<report>" "desfecho:<status> bounty:<$X> vuln:<tipo>"` (status: `confirmed` aceito · `duplicate` dup · `da-killed`/`policy` fechado).
2. Anexar 1 linha ao log de sessão: `python3 tools/brain.py log "learn: <report> → <status> (<$X>)"`.
3. Publicar o desfecho no programa correspondente do Hive; depois, se aceito/pago, destilar o padrão transversal em `memory/patterns.md`/`arsenal.md`.

### `code 11 <draft>` — Quality (evento rápido)
Pontua um **rascunho de report** antes do humano submeter — o "steelman do triager" (§ `rules/mistakes.md`).
Roda a checklist sobre o draft (`targets/<alvo>/report-*.md` ou `reports/*.md`) e dá uma nota + correções:
- Título específico (≤80 chars se H1) · severidade calibrada à rubrica · **versão de CVSS certa** (H1=3.1) ·
  PoC mínima com request+response · **impacto demonstrado, não teórico** (§4) · sem sinal never-submit sem chain ·
  duplicata verificada (`code 5`) · identidade por env-var, não literal · arquivos citados existem.
- Escrever a frase exata que um triador usaria pra fechar como N/A; se convence, o achado é fraco → voltar pro hunter.
Saída: `nota (A-F) · o que falta · pronto pra submeter? (sim/não)`. Não submete — o humano submete.

---

## Protocolos

> **Invariante (ver [[THE-MIND]] PARTE 5):** todo protocolo de recon **fecha no `hive_mind`** —
> superfície, endpoints, hipóteses `[UNTESTED]` e negativos viram nota com `asset_refs` →
> `ingest_workspace` → `idle` → read-back, ANTES de encerrar. Sem isso, o recon não está feito.

| Protocolo | Objetivo |
|-----------|----------|
| `casa-nova` | Pacote do coletor web → programa/notas no Hive |
| `contra-prova` | Dupla verificação pessimista de um achado — matar falso positivo |
| `report` | Rascunhar report de achado confirmado + checklist de submissão |
| `achar o x` | Recon **passivo** de superfície (OSINT puro, zero toque, **sem recibo**) → mapa da superfície + hipóteses no Hive |
| `ladrão de bancos` | **Usar as ferramentas**: recon ativo médio→completo em host autorizado (**exige recibo** `scope approve`+`record`); o nível 1 passivo delega ao `achar o x` |
| `saquear navios` | **Orquestrador de mineração**: um comando encadeia passive-delta → jsrecon (fingerprint→playbook) → merge no corpus de endpoints; agente fecha com recibo/hipóteses/browser |
| `One Piece` | Caçada da camada de **1 conta só** (self-state, tampering, race, escopo, step-skip) |
| `armar a arapuca` | **Arapuca no Hive**: SÓ peças encadeáveis/escaláveis (enablers, primitivas, sub-críticos) + passo de combinação → chain. Uma vez ligada, toda info que casa o critério entra nela (mesmo já estando no recon) |
| `monitor` | **Vigília ligável** de um alvo: baseline + checagens de mudança (superfície nova = alvo fresco) |
| `descobrir a roda` | Reconstruir o sistema a partir das peças → mapa do não-testado → cadeias |
| `escada de jacó` | Subir um `[ACHADO]` confirmado degrau a degrau até o pior caso (antes do report) |

### `protocolo casa-nova` — do coletor à ficha
Gatilho: o Tiago cola um pacote de dados passivos do alvo.
1. Identificar/validar `program_id`. 2. Consultar o Hive para não duplicar. 3. Higienizar e separar o pacote em notas/evidências focadas com `asset_refs`. 4. O operador cria/revisa `scope.json` se o programa for novo e o aprova fora do MCP. 5. Ingerir, aguardar fila e fazer read-back. `targets/` pode existir só como área de conversão.

### `protocolo contra-prova` — dupla verificação pessimista (anti-FP)
Objetivo: **matar falso positivo antes de reportar.** O Claude vira triador hostil e tenta
**derrubar** o achado. Carregar `rules/never-submit.md` + `rules/mistakes.md`.
Gatilho: o Tiago aponta um achado (endpoint + request/response + impacto alegado).
1. **Reafirmar** o achado em 1-2 linhas.
2. **Escopo:** repetir `hive_get_context` no ativo exato. Sem autorização confirmada → `FORA/ESCOPO DESCONHECIDO`, sem novo tráfego.
3. **Never-submit:** o achado está na lista de `rules/never-submit.md`? Se sim, só sobrevive com chain (§11/§12).
4. **Filtro de triagem — 5 perguntas** (qualquer "não" mata ou rebaixa):
   1. É comportamento padrão da aplicação? 2. Essa info deveria mesmo estar protegida? 3. Impacto real e demonstrável (§4, não teórico)? 4. Reproduzível sem o meu estado de sessão? 5. Já é conhecido/duplicado?
5. **Contra-argumentar a mecânica** (pessimista): ID adivinhável vs token de capacidade? self-XSS? público de propósito? só best-practice? Puxar os FP da classe em `memory/arsenal.md`.
6. **Antes de descartar: escalou?** Se não tentou chainar (§12 / `rules/chain-table.md`), o veredito não é final.
7. **Veredito** (vocabulário fixo): `ACHADO` · `FALSO POSITIVO` · `PADRÃO DA APLICAÇÃO` · `PÚBLICO POR DESIGN` · `INCONCLUSIVO (revisitar)` · `FORA DE ESCOPO`.
8. Registrar no brain (WAL) e publicar o veredito, inclusive falso positivo/descartado, no Hive.
Postura: **pessimista por padrão.** Melhor derrubar 3 achados fracos aqui do que queimar credibilidade.

### `protocolo matriz de exaustão` — não desistir cedo (§5) ⚔️
Objetivo: **garantir ataque de verdade** antes de marcar um lead como morto. Par do
`contra-prova` (anti-FP); este é o anti-desistência-precoce. Operacionaliza THE-MIND §5.
Gatilho: um lead PASS/candidato de uma classe (IDOR/BAC/XSS/SSRF/lógica/redirect…).
1. **Abrir** a matriz: `python3 tools/exhaustion.py open <program> <lead-id> --class <classe> --endpoint <ep> [--param <p>]`. Gera as células (posição × método × encoding × bypass).
2. **Atacar e marcar** cada célula (sob recibo): `mark <program> <lead-id> <cell> pass|fail|blocked|na`. `next` sugere as de maior valor; `status` mostra a cobertura.
3. **Fechar** só de dois jeitos: cobertura **≥80%** OU `fp <program> <lead-id> --reason "..."` (contra-prova = FP legítimo, ver §3.1: 3 re-enquadramentos + matriz cheia).
4. Só então `brain.py record <program> exhausted "<lead-id>: ..."`. O hook `giveup_guard` (estrito) **bloqueia** essa declaração enquanto a matriz do lead não estiver completa/FP.
Nota: a matriz é checklist/estado — **não emite tráfego**; cada célula é testada por você sob o gate de recibo. Estado em `brain/exhaustion/` (WAL).

### `protocolo report` — rascunho de report + checklist
Só para achado que passou no `contra-prova` como `ACHADO` (idealmente após `escada de jacó`).
1. Montar o report: título específico (≤80 chars se H1), resumo (2-3 linhas), severidade justificada
   pela rubrica (CVSS: **H1=3.1, resto=4.0** — o hook `cvss_version_guard` verifica), passos de repro,
   PoC mínima (request+response redigidos, **sem PII/token real**), impacto (demonstrado vs pior caso),
   mitigação. **Identidade do pesquisador via símbolo de env-var** de `rules/identities.md` (ex.:
   `${HACKERONE_EMAIL_ALIAS}`), nunca o valor literal.
2. Salvar em `targets/<alvo>/report-<slug>.md` ou `reports/`. Os hooks disparam sozinhos no Write:
   `file_path_guard` (arquivo citado existe?), `cvss_version_guard` (versão certa?), `validity_guard`
   (sinal never-submit sem chain?).
3. Checklist: escopo ok · repro sem meu estado · conta de teste minha · PII/token redigidos ·
   request+response do passo-chave · PoC mínima · severidade calibrada · duplicata verificada.
4. **Humano revisa e submete — o Claude nunca submete.**

### `protocolo achar o x` — recon passivo: achar a superfície (sem recibo) 🔍
Objetivo: descobrir a **superfície de ataque** de um alvo usando **só fontes de terceiros/OSINT** —
**zero toque no alvo, NÃO precisa de recibo do Hive** (nada de tráfego ativo passa pelo `scope_hook`;
não exige `scope approve` nem `record`, basta o `program_id` existir).
Gatilho: **"achar o x <program>"** / **"inicia achar o x"**. É o **nível 1 passivo** que o
`ladrão de bancos` costumava embutir, agora protocolo próprio.
1. **Hive pre-flight (leitura):** `hive_search` no programa por estado/superfície/negativos já conhecidos;
   `code 7 find`. Não duplicar o que já está mapeado.
2. **Coleta OSINT — só terceiros, NUNCA o alvo:**
   - CT logs (crt.sh), urlscan.io, Wayback/CDX, DNS passivo via DoH (não `dig` no host se não houver
     recibo), ASN/infra, Shodan/Censys.
   - GitHub/GitLab: repos da org, specs OpenAPI/Postman, dorks por segredo/endpoint/host.
   - JS/source maps **já arquivados por terceiros** (urlscan/Wayback) — não puxar do alvo.
3. **Destilar a superfície:** hosts/subdomínios (marcar in/out-scope e carve-outs), endpoints/rotas,
   APIs/specs, infra (CDN/WAF/cloud/k8s), stack/auth, e as **perguntas-pivô** que só o ativo fecha.
4. **Hipóteses semeadas** rankeadas (casa `memory/signals.md` + `rules/chain-table.md`), marcadas `[UNTESTED]`.
5. **Publicar no Hive:** nota de recon com `asset_refs` → ingestão → `idle` → read-back (fluxo `code 7 send`).
Guardrails: **100% passivo** (herda `postura escudo`); qualquer coisa que tocaria o alvo vira
`[REQUER AUTORIZAÇÃO]` e é **entregue ao `ladrão de bancos`**. **Sem recibo do Hive.**

### `protocolo ladrão de bancos` — usar as ferramentas: recon ATIVO (médio → completo)
Continuação ativa do `achar o x`. **Exige host autorizado + recibo** (`scope approve` do operador e
`record` do recibo pra liberar o `scope_hook`). Usa o ferramental de verdade contra o alvo.
1. **Listar IDs** pelo catálogo/`portfolio.md`; não fingir busca cross-program.
2. Tiago escolhe. `code 7 find <program> [asset]` consulta ao vivo; `code 8` completa o brief.
3. **Checar constraints do Hive ANTES de tocar** (rate, manual-only, closed scope, wildcard vs host-específico).
   Policy proíbe IA → PARAR. **Sem recibo `action_allowed=true` → PARAR** e devolver ao operador.
4. **Nível 1 Passivo** = rodar/consultar o **`achar o x`** (superfície já mapeada, sem recibo).
   **Nível 2 Médio** (só hosts in-scope, sem fan-out — httpx/curl/katana raso + `cors_headers_scan.py`).
   Ideal pra escopo host-específico. **Nível 3 Completo** (recon massivo — `code 0`; ideal pra wildcard).
   Otimização: pré-resolver com `dnsx`, httpx fast-fail.
5. **Sintetizar/filtrar/publicar**: cru no scratch, delta e leads no Hive. Registrar até que nível chegou e negativos.
Guardrails: só alvo autorizado **com recibo vigente**; respeitar escopo + constraints; cada nível herda os guardrails do anterior.

### `protocolo saquear navios` — orquestrador de mineração (1 comando) ⛴️
Encadeia o pipeline de "pegar tudo" e consolida no Hive. Gatilho: **"saquear navios <program>"**.
Ferramenta: `tools/saquear.py <program> --domains <d1,d2> --spa-hosts <h1,h2> --data-dir <hive-data>`.
1. **passive** (`passive.py`) — agrega hosts de fontes 3rd-party (crt.sh/OTX/HackerTarget/urlscan/
   Wayback + Censys/Shodan/VT/SecurityTrails por env) e faz **diff vs Hive** → só o delta PROD novo.
2. **jsrecon** por SPA host — endpoints ocultos (BFS de bundles) + **STACK FINGERPRINT→playbook**
   (Hasura/Auth0/Retool/Firebase/OIDC/Next → teste dirigido). Bundles salvos no scratch.
3. **endpoints** (`endpoints.py merge`) — mescla os endpoints no **corpus canônico** (`document_type:
   endpoint`, dedupe método-agnóstico) que o `code 6` consome via `hive_search(document_types=[endpoint])`.
4. **Saída**: hosts novos, endpoints novos, stacks+playbooks. Passos 1–2 tocam alvo (jsrecon) → **exigem
   recibo** (`record-scope` cobre o programa todo de uma vez); passive é 3rd-party.
Fecho do AGENTE (não automatizado): `record-scope` p/ hosts novos → semear hipóteses (`code 6`) →
captura de XHR autenticado via browser p/ endpoints atrás de login → `ingest_workspace` + read-back.
Guardrails: herda os do `ladrão de bancos`; nada de fan-out; só publica delta destilado.

### `protocolo One Piece` — a caçada com UMA conta só
Camada intermediária (nível 1) entre unauth (nível 0) e cross-account (nível 2). Testa tudo que dá pra
provar com **1 conta**: self-state manipulation · param/type tampering · race na própria conta · bypass de
escopo (RO→write; V1 vs V2) · step-skip em fluxo multi-etapa · "o check de dono existe?".
Loop por endpoint: 6 perguntas (foco Q2/Q4/Q6) → `formação de lança` constrói+executa → triagem cética
(atenção à #4) → escala (§12) → registrar no WAL e publicar no Hive. Guardrails: nunca rajada em login/reset/MFA;
race só na própria conta com valores mínimos; para-e-confirma antes de saque real.

### `protocolo armar a arapuca` — inventário de encadeamento (documento no Hive)
Ativação: **"arma a arapuca <program>"**. Desliga: **"desarma a arapuca <program>"**.
A **arapuca é um documento dedicado no Hive** (`programs/<program>/notes/*-arapuca-*.md`, `document_type:
note`, tag `arapuca`), **separado do recon**: o recon guarda TUDO que foi encontrado; a arapuca guarda
**SÓ o que pode ser encadeado ou escalar** uma vulnerabilidade. Serve pra, no futuro, gerar hipóteses
de escalada (`code 6` puxa dela).

**Ao ligar:** criar a arapuca com as peças já conhecidas do alvo (varrer recon/notas do Hive + WAL),
`ingest_workspace` → `idle` → read-back. `targets/<alvo>/arapuca.md` pode existir só como cache local.

**Critério de entrada (uma peça SÓ entra se casar ≥1):**
- **Enabler:** dá um pré-requisito/capacidade que outro bug precisa (ex.: leak de trace/ID/token,
  controle de estado, oráculo de erro, primitiva econômica).
- **Sub-crítico composável:** fraco isolado, mas plausivelmente combinável (par/trio) em High/Crit.
- **Escalador:** aumenta impacto/alcance/severidade de um `[ACHADO]` existente.
- **Primitiva reutilizável:** info/mecanismo que reaparece como elo em `rules/chain-table.md`.
> NÃO entra: recon puro sem relevância de chain (fica só no recon). Peça tem que ser **real/reproduzível**.

**Regra permanente (enquanto o alvo é caçado):** sempre que algo for **usado** num teste OU for uma
informação que **casa o critério acima** — **mesmo que já esteja guardada no recon** — **registrar
(também) na arapuca** e re-ingerir. A arapuca é a visão curada de encadeamento; duplicar do recon pra cá
é intencional.

**Formato:**
1. Tabela de **peças**: `id · peça · nível de acesso · severidade isolada · o que HABILITA · origem (nota/recon)`.
2. **Passo de combinação** (a cada 3-4 peças): par a par e em trios — "A dá o pré-requisito de B?
   saída de A = entrada de B?". Casar com `rules/chain-table.md`.
3. **Candidata a chain** → lead `[UNTESTED]` com os elos nomeados (na arapuca + próximo handoff).
4. Peça que envelhece sem combinar → `[dormant]`, não apagar.
5. Fechar sempre no Hive (ingest + read-back), como todo protocolo (ver [[THE-MIND]] PARTE 5).

### `protocolo monitor` — vigília ligável de mudanças no alvo
Ativação: **"liga o monitor <alvo>"** / **"monitora <alvo>"**. Desliga: **"desliga o monitor <alvo>"**.
Fluxo que fica **vivo enquanto ligado**: features novas têm a menor maturidade de segurança (§10
"new == unreviewed"), então vigiar mudança é ROI alto. Não caça — sinaliza onde caçar.
- **Baseline** (1ª vez): snapshot passivo do alvo → salva `targets/<alvo>/recon/monitor-baseline.txt`
  (subdomínios, hosts vivos, endpoints do JS, headers-chave). Usa `code 1`/`recon.py` (só passivo).
- **Check** (cada vez que o monitor está ligado e você retoma, ou quando pedir): re-roda o passivo e
  **diffa** contra o baseline. Toda adição (novo subdomínio/endpoint/feature/mudança de header) →
  lead `[UNTESTED]` no WAL + `brain.py record <alvo> recon "monitor-diff" "<o que mudou>"`; publicar o delta no Hive.
- **Estado:** o "ligado/desligado" e o baseline destilado moram no Hive; cópia local é cache; ligado =
  toda sessão de retomada roda um check antes de caçar.
Guardrails: **só passivo** (herda `postura escudo` de fato — zero toque ativo); respeita escopo.

### `protocolo descobrir a roda` — reconstruir a máquina a partir das peças
Pré-requisito: `targets/<alvo>/arapuca.md` com peças. Roda quando a caçada empaca ou a arapuca tem 8+ peças.
**Respaldado por `tools/target_model.py`** (modelo persistente em `brain/model/`, análise pura, sem tráfego):
1. **Reconstruir o sistema** (o modelo): `import-jsrecon`/`import-passive` (auto do `--json`) + `add-object/add-auth/add-boundary/add-component` (fatos curados: arquitetura, quem chama quem, fronteiras de confiança, camadas de auth, onde o estado vive). `show` renderiza a seção "Modelo do sistema" p/ a arapuca.
2. **Eng. reversa das suposições:** `enumerate` cruza componente × primitiva (catálogo de signals/arsenal/chain-table) → leads rankeados (§10 + pesos aprendidos + chains via capability-graph). `simulate <jwt|oauth|hmac|state>` decide quais ataques do mecanismo valem disparar.
3. **Mapa do não-testado:** `untested` — endpoint/param/método/fluxo/host do recon nunca sondado, por fragilidade.
4. **Cadeias narrativas:** leads marcados `chain` quando há enabler no capability-graph (A → habilita C).
5. **Priorizar e devolver** pro `modo hunter`/`lança`; `enumerate --seed-matrix` abre as matrizes de exaustão. Cada lead é hipótese `[UNTESTED]`.
**Aprende sozinho:** `record-verdict <lead> <achado|fp|...>` re-ajusta os pesos (FP rebaixa a classe; achado sobe + promove irmãos, §3) — o alvo ensina o modelo a priorizar o que paga ali.

### `protocolo escada de jacó` — subir um achado real até o teto
Pré-requisito: um `[ACHADO]` confirmado. Roda **antes do `report`**.
1. **Ancorar** o achado (impacto verificado, severidade atual). 2. **Desenhar a escada** da classe (do menos ao mais grave) — usar `rules/chain-table.md`. 3. Pra cada degrau acima, formular a hipótese concreta. 4. **Puxar elos** (peça da arapuca / chain do chain-table). 5. **Testar bottom-up** via `formação de lança`, para-e-confirma em ação mutante. 6. **Parar** quando a hipótese do próximo degrau é falsificada (teto confirmado) ou exige acesso que não temos (documentar como pior caso). 7. **Devolver pro report:** severidade no degrau mais alto CONFIRMADO + seção "demonstrado vs pior caso".

---

## Modos

### `modo hunter` — postura de caçador sênior
Ativação: **"modo hunter on"** / **"tá na hora da caçada"**. Desliga: **"modo hunter off"**.
Foco: **impacto real, zero falso positivo.** Nunca inflar trivial/público como grande achado.

**Ao ligar (start):**
1. **Escolher `program_id`:** usar `portfolio.md` ou o catálogo writer. Não existe `hive_search` global; perguntar qual programa se o ID não estiver explícito.
2. **Hive pre-flight obrigatório:** `hive_search` por estado, objetivo, evidências e descartes. Para cada asset que possa receber tráfego, `hive_get_context` + recibo no cache. Não forkar documentos para o local.
3. **`code 8 <program>`:** complementar com o brain/WAL local sem deixar que ele sobreponha o Hive.
4. **Carregar o cérebro:** [[THE-MIND]] + `memory/` (patterns/arsenal/signals) + as `rules/` relevantes (mistakes, techniques, waf-bypass, vendor-fingerprints).

**Loop de caçada:**
1. **6 perguntas do The Mind** em cada feature/endpoint (PARTE 1).
2. **Princípios sempre-ativos** (PARTE 2) o tempo todo — impacto-primeiro, sibling, A→B, HTTP 200≠impacto, matriz de exaustão.
3. **Triagem cética** (5 perguntas do `contra-prova`) em cada candidato.
4. **Escala obrigatória (§12):** todo PASS dispara chain-search (`rules/chain-table.md`) antes de cravar severidade.
5. **Tenacidade honesta:** "não achei" = "ainda não achei" — atravessar os 4 pontos de desistência (§3.1).
6. **Gravar no brain como WAL:** todo veredito → `brain.py record`; todo endpoint → `brain.py endpoint`; capacidade → `brain.py capability`. Isso não substitui publicação.
7. **Persistir conhecimento:** técnica nova → `memory/arsenal.md` (+ sinal em `signals.md`); bypass de WAF/FP novo → `rules/`.
8. Achado real → `contra-prova` → `escada de jacó` → `report`.

**Ao desligar (`modo hunter off`) — o Selo de saída (OBRIGATÓRIO):**
1. Consolidar o scratch: todo lead com status, endpoints novos, negativos, blockers e **"Próximo passo:"**.
2. Higienizar segredos/PII e dividir em notas/evidências focadas com `asset_refs`.
3. `code 7 send <program>`: escrever no workspace Hive, ingerir, aguardar `idle` e fazer read-back.
4. Aprendizado transversal → `memory/`/`rules/`; decisão de método → `code 4`.
5. Rodar `python3 tools/seal_gate.py <program>`; resolver falhas.
6. Só após relatório de ingestão sem falhas + read-back, resumir e declarar `modo hunter OFF`.

### `postura escudo` — postura silenciosa (não dispara flag) 🛡️
Ativação: **"postura escudo"** / **"levanta o escudo"**. Desliga: **"baixa o escudo"**.
Stealth defensivo: **toca a rede só com o que não dispara flag** (tráfego que parece legítimo, volume
baixíssimo, serial). **A régua:** "um WAF/rate-limit/blue-team distinguiria isto de um usuário normal?".
Sim → não faz, vira vitrine `[REQUER AUTORIZAÇÃO]`.
- **Permitido:** OSINT 100% passivo (crt.sh/Wayback/DNS/subfinder passivo/GitHub/dorks/Shodan), leitura de JS/source maps já servidos, `code 1`, no máx. 1 request manual legítima por endpoint.
- **Proibido:** scan ativo, fuzzing, enum em massa, brute/spray, qualquer toque em login/reset/MFA/pagamento, WAF probing, payload de injeção, paralelismo alto.
- **A vitrine (obrigatória):** por superfície, listar o teto marcado `[REQUER AUTORIZAÇÃO]` com 1 linha do que provaria e por que faz barulho.
- **Delegação ao operador ("nunca só não posso"):** toda ação evitada (🔴 do escudo OU bloqueio do classifier do runtime) vem com (1) o porquê em 1 linha, (2) o comando pronto pro Tiago rodar com a autorização/sessão dele (`!` no Claude Code / console do navegador), (3) o que o Claude vai interpretar no resultado.
- **Relação com os outros modos:** prioritário. **Baixa a lança automático** (opostos). Rebaixa o `modo hunter` ao subconjunto silencioso.

### `formação de lança` — execução ativa assistida (só dentro do `modo hunter`)
Ativação: **"forma a lança"**. Desliga: **"baixa a lança"**. Pré: `modo hunter` + alvo autorizado.
> **Incompatível com `postura escudo`** (levantar o escudo baixa a lança).
Por lead `[UNTESTED]`: 1. **Constrói** a request/PoC concreta. 2. **Reconfirma** o asset no Hive e executa nos limites da policy, nunca rajada em login/reset/MFA. 3. **Simula** o que não pode tocar → `[SIMULADO]`. 4. **Compara** com Hive + patterns/arsenal/rules. 5. **Triagem + escala**. 6. **Registra** no WAL e publica no Hive. **Para-e-confirma** antes de ação mutante.

### `formação tridente` — teste diferencial em 3 navegadores 🔱
Ativação: **"forma o tridente"**. Desliga: **"recolhe o tridente"**. **Compatível com o escudo** (é observação, não ataque).
Roda os fluxos por 3 engines (**Blink**/Gecko/WebKit) e diffa o comportamento — divergência = bug P5 client-side (CSP, SameSite, redirect/URL parsing, DOM/mutation-XSS, charset, WCD). Matriz por fluxo×engine em `targets/<alvo>/tridente.md`. Header obrigatório do programa vai em todos os engines. Blink via `claude-in-chrome`; Gecko/WebKit orientados ao Tiago.

### `seguir o rastro` — ramificar a partir de um sinal
Ativação: **"segue o rastro"**. Desliga: **"chega de rastro"**. Tenacidade dirigida: de um sinal (parser
esquisito, diferencial de erro, timing), **não parar na observação** — listar 3-8 ramificações concretas,
executar (via lança), cada ramificação que responde diferente vira novo sinal. Cruzar cada nível com
`memory/patterns.md` + `arsenal.md`. Registrar a árvore no WAL e no handoff Hive.

### `modo dojo` — treino: write-up → conhecimento retido 🥋
Ativação: **"abre o dojo"**. Desliga: **"fecha o dojo"**. O lado *entrada* de conhecimento (o hunter é a
saída). Estudo **ativo**: por write-up → 3 perguntas (qual suposição do dev caiu? qual sinal observável?
qual degrau de escalada?) → distilar no banco (`memory/<classe>.md` + `arsenal.md` + `signals.md` +
`_ingested.md`) → **recall** (reconstruir de memória, fonte fechada) → **aplicar** o sinal novo aos programas relevantes via consulta Hive
(`code 6` mental) → **agendar revisão espaçada** (1d→1sem→1mês) em `memory/dojo-log.md`. Guardrail: 2-3
write-ups/sessão (qualidade > volume).

### `modo sábado à tarde` — curadoria do portfólio
Ativação: **"modo sábado"**. Desliga: **"acabou o sábado"**. Cura `portfolio.md` apenas como catálogo de
`program_id` e EV. Conteúdo de alvo, scope e recon vão para o Hive; programa novo segue `code 3`, com
scope revisado/aprovado pelo operador. Não caça aqui — só organiza o funil.

### `modo bicicleta com rodinhas` — o cérebro como copiloto explícito
Ativação: **"põe as rodinhas"**. Desliga: **"tira as rodinhas"**. A cada passo o cérebro **sugere
proativamente qual comando ativar e por quê** antes de você pedir. Mesmo sem as rodinhas o roteamento
acontece (o [[THE-MIND]] é o cérebro) — as rodinhas só o tornam explícito.

---
_Novos comandos: copie o formato acima. Mantenha números (códigos) e nomes estáveis — o Tiago decora._
_Revisão de nomenclatura/numeração pendente: ver `TODO.md`._
