# CODES, PROTOCOLOS & MODOS — comandos do Excalibull

Três tipos de comando. Todos são **gatilhos que o Claude executa** quando o Tiago os invoca.
Este arquivo é a **fonte da verdade** dos comandos. **Tudo passa pelo [[THE-MIND]] (o cérebro)** —
antes de caçar, o cérebro é consultado e roteia (PARTE 3).

- **Códigos** (`code N`) — **eventos rápidos**: executam uma ação e acabam (uma tacada).
  Ex.: `code 7 send` envia os dados do alvo pro board de conhecimento.
- **Protocolos** (`protocolo <nome>`) — **fluxos/funcionalidades nomeados que podem ser
  ligados ou desligados**. Uns rodam uma vez com um objetivo (ex.: `contra-prova`, `report`);
  outros ficam **vivos** enquanto ligados (ex.: `armar a arapuca` = inventário contínuo,
  `monitor` = vigília de mudanças). Ligar/desligar é explícito.
- **Modos** (`modo <nome>`) — um **conjunto de protocolos + fluxos que afeta diretamente
  como o The Mind pensa e opera** enquanto está ligado. Um modo compõe protocolos e muda a
  postura (ex.: `modo hunter` compõe contra-prova + escala + lança; `postura escudo` muda o
  que é permitido tocar).

> **Regra de ouro:** só recon/scan/PoC em alvos **autorizados** (escopo do programa). Na dúvida,
> perguntar antes de disparar. Humano sempre submete. O hook `tools/scope_hook.py` bloqueia
> comando contra host fora de escopo automaticamente.

---

## Códigos

| Código | Nome | Resumo |
|--------|------|--------|
| `code 0 <alvo>` | Recon completo | recon + probe + crawl + gf + scan CORS/headers → ficha |
| `code 1 <alvo>` | Recon passivo | só enumeração passiva, sem tocar no alvo |
| `code 2 <url>` | Scan alvo único | audita CORS/headers de uma URL |
| `code 3 <alvo>` | Nova ficha | cria `targets/<alvo>/` no formato do board |
| `code 4 "<decisão>"` | Registrar decisão | adiciona bloco no [[THE-MIND]] (log) |
| `code 5 <vuln> [alvo]` | Dupcheck | checa se a vuln já foi reportada (local + hacktivity) antes de gastar tempo |
| `code 6 <alvo>` | Gerar hipóteses | casa recon × `memory/signals.md` + `rules/chain-table.md` → leads `[UNTESTED]` |
| `code 7 send <alvo>` | Sync → board | envia `targets/<alvo>/` → `knowledge-targets/<plataforma>/<slug>/` |
| `code 7 find <alvo>` | Sync ← board | busca `knowledge-targets/<plataforma>/<slug>/` → `targets/<alvo>/` |
| `code 7` | Diff board | lista/diffa board × `targets/` local |
| `code 8 <alvo>` | Brain brief | pre-flight: o que já foi testado/exausto no alvo |
| `code 9` | Brain status | visão geral do brain (alvos, exaustos, findings) |
| `code 10 <report> <status> [--bounty $X]` | Learn | registra o desfecho de uma submissão no brain (alimenta EV futuro) |
| `code 11 <draft>` | Quality | pontua um rascunho de report antes de submeter (steelman do triager) |

### `code 0 <alvo>` — Recon completo
1. `python3 tools/recon.py <alvo> --all --out targets/<alvo>/recon` (subfinder/amass/httpx/katana/gospider/gau/waybackurls + gf; cai pra Python puro no que faltar).
2. `python3 tools/cors_headers_scan.py -f targets/<alvo>/recon/live-hosts.txt --json targets/<alvo>/recon/cors.json`.
3. Atualizar `targets/<alvo>/README.md` (ficha) + `recon/notes.md`/`tech.md` resumindo hosts vivos, buckets do gf e destaques.
4. Resumo curto no chat.
> `scope_hook` roda antes de cada request; se um host cair fora de escopo, o comando é bloqueado.

### `code 1 <alvo>` — Recon passivo
- `python3 tools/recon.py <alvo> --out targets/<alvo>/recon` (sem probe/crawl). Só fontes de terceiros.

### `code 2 <url>` — Scan alvo único
- `python3 tools/cors_headers_scan.py <url> --json targets/<host>/recon/cors.json`.

### `code 3 <alvo>` — Nova ficha de alvo
- Copiar `targets/_TEMPLATE/` → `targets/<alvo>/` e preencher `target.yml` (plataforma+slug+score),
  `README.md` (ficha) e `scope.md`. Versão manual/rápida do `protocolo casa-nova`. Depois, `code 7 send`
  registra no board.

### `code 4 "<decisão>"` — Registrar decisão
- Acrescentar bloco no [[THE-MIND]] PARTE 6 (Data · Decisão · Por quê · Status).

### `code 5 <vuln> [alvo]` — Dupcheck (evento rápido)
Checa se a vulnerabilidade **já foi reportada** antes de investir tempo. Ex.: `code 5 "XSS em /search" figma`.
1. **Local:** grep em `brain/` (`brain.py record` anteriores), `targets/<alvo>/findings/*` e `a-cacada-ate-aqui.md` por vuln/endpoint iguais ou irmãos.
2. **Programa:** checar known-issues/exclusões da `scope.md`/policy do alvo; se der, buscar a hacktivity pública (WebFetch) por título parecido.
3. **Veredito:** `PROVÁVEL DUPLICATA` (com a referência) · `NOVO` · `INCERTO`. Duplicata → não reportar (ou só se demonstrar impacto novo). Registrar no brain se duplicata (`status duplicate`).
> Guardrail: só leitura/OSINT. Não dispara probe.

### `code 6 <alvo>` — Gerar hipóteses (motor de hipóteses)
Casa o **corpus de recon** do alvo contra `memory/signals.md` **e** as âncoras-feeder de
`rules/chain-table.md`, e cospe leads `[UNTESTED]` **rankeados** na ficha.
1. Carregar o banco: `memory/signals.md` + `patterns.md` + `arsenal.md` + `rules/chain-table.md`.
2. Reunir o corpus: `targets/<alvo>/recon/*`, a ficha, e qualquer output colado.
3. **Pass 1 — sinais únicos:** varrer o corpus contra cada `Sinal:` do `signals.md`. Cada hit → hipótese (sinal · pattern P# · hipótese · probe 🟢/🔴 · FP).
4. **Pass 2 — composição:** dos sinais acesos, quais pares/trios casam um gatilho de chain (`C-*` / âncora-feeder de `chain-table`) → hipótese de chain.
5. **Rankear** por (impacto × plausibilidade × probe barato). Probe 🟢 sobe.
6. **Escrever** os top-N como leads `[UNTESTED]` na ficha.
7. **Resumo no chat:** quantos sinais acenderam, top-3, o que dá pra testar em silêncio.
> **Guardrail:** `code 6` só faz matching e leitura — nunca dispara o probe sozinho.

### `code 7 send|find [<alvo>]` — Sync com o board knowledge-targets
Ver [[THE-MIND]] PARTE 5. O board é a fonte da verdade; `targets/` é cópia de trabalho.
- `code 7 find <alvo>` → `python3 tools/kb_sync.py find <alvo>` (puxa a ficha pra cá pra caçar).
- `code 7 send <alvo>` → `python3 tools/kb_sync.py send <alvo>` (devolve o estado + regenera RANKING).
- `code 7` (sem arg) → `python3 tools/kb_sync.py` (diffa board × local).
> Caminho do board via `$KNOWLEDGE_TARGETS_DIR` (default `../knowledge-targets`).

### `code 8 <alvo>` — Brain brief (pre-flight)
- `python3 tools/brain.py brief <alvo>` — mostra o que já foi testado, o que está exausto (com blocker), vetores efetivos, comportamento de WAF. **Roda no start do `modo hunter`.**

### `code 9` — Brain status
- `python3 tools/brain.py status` — visão geral (alvos, exaustos, findings, sessões).

### `code 10 <report> <status> [--bounty $X]` — Learn (evento rápido)
Registra o **desfecho de uma submissão** pra alimentar decisões de EV futuras (§10 "seguir o dinheiro").
Ex.: `code 10 report-idor-figma aceito --bounty 2000 --vuln-type IDOR`.
1. Gravar no brain: `python3 tools/brain.py record <alvo> <status> "submissão:<report>" "desfecho:<status> bounty:<$X> vuln:<tipo>"` (status: `confirmed` aceito · `duplicate` dup · `da-killed`/`policy` fechado).
2. Anexar 1 linha ao log de sessão: `python3 tools/brain.py log "learn: <report> → <status> (<$X>)"`.
3. Se aceito/pago, notar o padrão que pagou em `memory/patterns.md`/`arsenal.md` (o que vale repetir).

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

| Protocolo | Objetivo |
|-----------|----------|
| `casa-nova` | Pacote do coletor web → ficha de alvo em `targets/` |
| `contra-prova` | Dupla verificação pessimista de um achado — matar falso positivo |
| `report` | Rascunhar report de achado confirmado + checklist de submissão |
| `ladrão de bancos` | Escolher alvo → recon em 3 níveis (passivo→médio→completo) → sintetizar |
| `One Piece` | Caçada da camada de **1 conta só** (self-state, tampering, race, escopo, step-skip) |
| `armar a arapuca` | Inventário vivo de achados fracos + passo de combinação → chain |
| `monitor` | **Vigília ligável** de um alvo: baseline + checagens de mudança (superfície nova = alvo fresco) |
| `descobrir a roda` | Reconstruir o sistema a partir das peças → mapa do não-testado → cadeias |
| `escada de jacó` | Subir um `[ACHADO]` confirmado degrau a degrau até o pior caso (antes do report) |

### `protocolo casa-nova` — do coletor à ficha
Gatilho: o Tiago cola um pacote de dados passivos do alvo.
1. Ler o pacote/JSON. 2. Criar `targets/<alvo>/` a partir de `targets/_TEMPLATE/` (target.yml + README + scope.md + recon/). 3. `python3 tools/scope_check.py --list` pra conferir o escopo carregado. 4. Oferecer `code 0` pra enriquecer. 5. `code 7 send` pra registrar no board.

### `protocolo contra-prova` — dupla verificação pessimista (anti-FP)
Objetivo: **matar falso positivo antes de reportar.** O Claude vira triador hostil e tenta
**derrubar** o achado. Carregar `rules/never-submit.md` + `rules/mistakes.md`.
Gatilho: o Tiago aponta um achado (endpoint + request/response + impacto alegado).
1. **Reafirmar** o achado em 1-2 linhas.
2. **Escopo:** o ativo está mesmo in-scope? (`scope.md` + `scope_check.py`). Fora → provável inválido, diga na cara.
3. **Never-submit:** o achado está na lista de `rules/never-submit.md`? Se sim, só sobrevive com chain (§11/§12).
4. **Filtro de triagem — 5 perguntas** (qualquer "não" mata ou rebaixa):
   1. É comportamento padrão da aplicação? 2. Essa info deveria mesmo estar protegida? 3. Impacto real e demonstrável (§4, não teórico)? 4. Reproduzível sem o meu estado de sessão? 5. Já é conhecido/duplicado?
5. **Contra-argumentar a mecânica** (pessimista): ID adivinhável vs token de capacidade? self-XSS? público de propósito? só best-practice? Puxar os FP da classe em `memory/arsenal.md`.
6. **Antes de descartar: escalou?** Se não tentou chainar (§12 / `rules/chain-table.md`), o veredito não é final.
7. **Veredito** (vocabulário fixo): `ACHADO` · `FALSO POSITIVO` · `PADRÃO DA APLICAÇÃO` · `PÚBLICO POR DESIGN` · `INCONCLUSIVO (revisitar)` · `FORA DE ESCOPO`.
8. Registrar na ficha **e no brain**: `python3 tools/brain.py record <alvo> <status> "<técnica>" "<detalhe>"` (status casa o veredito: `confirmed`/`potential`/`da-killed`/`duplicate`/`policy`/`exhausted`).
Postura: **pessimista por padrão.** Melhor derrubar 3 achados fracos aqui do que queimar credibilidade.

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

### `protocolo ladrão de bancos` — recon em 3 níveis (passivo → médio → completo)
1. **Listar alvos** (`code 7` diffa board × local; ou ler `portfolio.md`).
2. Tiago escolhe. `code 7 find <alvo>` traz a ficha. `code 8 <alvo>` (brain brief).
3. **Checar constraints da ficha ANTES de tocar** (rate, manual-only, closed scope, wildcard vs host-específico). ⚠️ Ficha diz "IA proibida na busca" → PARAR, alvo é manual-only.
4. **Nível 1 Passivo** (sempre; zero toque — crt.sh/Wayback/urlscan/GitHub/dorks/Shodan). Ao terminar, perguntar "rodar tudo (médio+completo) ou nível a nível?".
   **Nível 2 Médio** (só hosts in-scope, sem fan-out — httpx/curl/katana raso + `cors_headers_scan.py`). Ideal pra escopo host-específico.
   **Nível 3 Completo** (recon massivo — `code 0`; ideal pra wildcard). Otimização: pré-resolver com `dnsx`, httpx fast-fail.
5. **Sintetizar/filtrar/registrar** sobre os níveis que rodaram. Cru em `recon/`, destilado na ficha, leads `[UNTESTED]` (via `code 6`). Registrar **até que nível chegou**.
Guardrails: só alvo autorizado; respeitar escopo + constraints; cada nível herda os guardrails do anterior.

### `protocolo One Piece` — a caçada com UMA conta só
Camada intermediária (nível 1) entre unauth (nível 0) e cross-account (nível 2). Testa tudo que dá pra
provar com **1 conta**: self-state manipulation · param/type tampering · race na própria conta · bypass de
escopo (RO→write; V1 vs V2) · step-skip em fluxo multi-etapa · "o check de dono existe?".
Loop por endpoint: 6 perguntas (foco Q2/Q4/Q6) → `formação de lança` constrói+executa → triagem cética
(atenção à #4) → escala (§12) → registrar na ficha + brain. Guardrails: nunca rajada em login/reset/MFA;
race só na própria conta com valores mínimos; para-e-confirma antes de saque real.

### `protocolo armar a arapuca` — juntar peças fracas até virar chain
Inventário vivo em `targets/<alvo>/arapuca.md` (não um loop). Cataloga cada achado **individualmente
fraco** e procura a combinação que vira High/Crit.
1. Tabela de **peças**: `id · peça · nível de acesso · severidade isolada · o que HABILITA`.
2. Todo sub-crítico do hunter/rastro/lança **entra como peça**, não é descartado.
3. **Passo de combinação** (a cada 3-4 peças): par a par e em trios — "A dá o pré-requisito de B? saída de A = entrada de B?". Casar com `rules/chain-table.md`.
4. **Candidata a chain** → lead `[UNTESTED]` na ficha com os elos nomeados.
5. Peça que envelhece sem combinar → `[dormant]`, não apagar.
Guardrail: peça só entra se for **real e reproduzível**.

### `protocolo monitor` — vigília ligável de mudanças no alvo
Ativação: **"liga o monitor <alvo>"** / **"monitora <alvo>"**. Desliga: **"desliga o monitor <alvo>"**.
Fluxo que fica **vivo enquanto ligado**: features novas têm a menor maturidade de segurança (§10
"new == unreviewed"), então vigiar mudança é ROI alto. Não caça — sinaliza onde caçar.
- **Baseline** (1ª vez): snapshot passivo do alvo → salva `targets/<alvo>/recon/monitor-baseline.txt`
  (subdomínios, hosts vivos, endpoints do JS, headers-chave). Usa `code 1`/`recon.py` (só passivo).
- **Check** (cada vez que o monitor está ligado e você retoma, ou quando pedir): re-roda o passivo e
  **diffa** contra o baseline. Toda adição (novo subdomínio/endpoint/feature/mudança de header) →
  lead `[UNTESTED]` na ficha + `brain.py record <alvo> recon "monitor-diff" "<o que mudou>"`.
- **Estado:** o "ligado/desligado" por alvo mora numa linha na ficha (`monitor: on|off`); ligado =
  toda sessão de retomada roda um check antes de caçar.
Guardrails: **só passivo** (herda `postura escudo` de fato — zero toque ativo); respeita escopo.

### `protocolo descobrir a roda` — reconstruir a máquina a partir das peças
Pré-requisito: `targets/<alvo>/arapuca.md` com peças. Roda quando a caçada empaca ou a arapuca tem 8+ peças.
1. **Reconstruir o sistema** (o modelo): de tudo descoberto → arquitetura, quem chama quem, fronteiras de confiança, camadas de auth, onde o estado vive. Seção "Modelo do sistema" na arapuca.
2. **Eng. reversa das suposições:** por componente/fronteira, rodar as 6 perguntas mirando a costura.
3. **Mapa do não-testado:** todo endpoint/param/método/fluxo/host que apareceu no recon e nunca foi sondado, rankeado por fragilidade.
4. **Cadeias narrativas:** multi-passo com história (A → estado B → habilita C → impacto D).
5. **Priorizar e devolver** pro `modo hunter`/`lança`. Cada inferência marcada como hipótese.

### `protocolo escada de jacó` — subir um achado real até o teto
Pré-requisito: um `[ACHADO]` confirmado. Roda **antes do `report`**.
1. **Ancorar** o achado (impacto verificado, severidade atual). 2. **Desenhar a escada** da classe (do menos ao mais grave) — usar `rules/chain-table.md`. 3. Pra cada degrau acima, formular a hipótese concreta. 4. **Puxar elos** (peça da arapuca / chain do chain-table). 5. **Testar bottom-up** via `formação de lança`, para-e-confirma em ação mutante. 6. **Parar** quando a hipótese do próximo degrau é falsificada (teto confirmado) ou exige acesso que não temos (documentar como pior caso). 7. **Devolver pro report:** severidade no degrau mais alto CONFIRMADO + seção "demonstrado vs pior caso".

---

## Modos

### `modo hunter` — postura de caçador sênior
Ativação: **"modo hunter on"** / **"tá na hora da caçada"**. Desliga: **"modo hunter off"**.
Foco: **impacto real, zero falso positivo.** Nunca inflar trivial/público como grande achado.

**Ao ligar (start):**
1. **Escolher o alvo:** `code 7` (diffa board × local) ou `portfolio.md`; perguntar "qual alvo?". `code 7 find <alvo>` traz a ficha.
2. **`code 8 <alvo>` (brain brief)** — o que já rolou, o que evitar (não re-atacar EXHAUSTED sem nova capacidade).
3. **Carregar o cérebro:** [[THE-MIND]] + `memory/` (patterns/arsenal/signals) + as `rules/` relevantes (mistakes, techniques, waf-bypass, vendor-fingerprints).

**Loop de caçada:**
1. **6 perguntas do The Mind** em cada feature/endpoint (PARTE 1).
2. **Princípios sempre-ativos** (PARTE 2) o tempo todo — impacto-primeiro, sibling, A→B, HTTP 200≠impacto, matriz de exaustão.
3. **Triagem cética** (5 perguntas do `contra-prova`) em cada candidato.
4. **Escala obrigatória (§12):** todo PASS dispara chain-search (`rules/chain-table.md`) antes de cravar severidade.
5. **Tenacidade honesta:** "não achei" = "ainda não achei" — atravessar os 4 pontos de desistência (§3.1).
6. **Gravar no brain no loop:** todo veredito → `brain.py record`; todo endpoint → `brain.py endpoint`; capacidade de chain → `brain.py capability`.
7. **Persistir conhecimento:** técnica nova → `memory/arsenal.md` (+ sinal em `signals.md`); bypass de WAF/FP novo → `rules/`.
8. Achado real → `contra-prova` → `escada de jacó` → `report`.

**Ao desligar (`modo hunter off`) — o Selo de saída (OBRIGATÓRIO):**
1. Flush pra ficha (`README.md`): todo lead com status; superfície/endpoints novos; tabela de achados.
2. Bloqueios explícitos por lead quente.
3. Bloco datado em `targets/<alvo>/a-cacada-ate-aqui.md` com **"Próximo passo:"**.
4. Aprendizado → `memory/`/`rules/`; decisão de rumo → `code 4`.
5. **Rodar `python3 tools/seal_gate.py <alvo>` — precisa passar.** Se falhar, resolver o que ele apontar (não desligar no seco).
6. `code 7 send <alvo>` devolve o estado pro board. Resumo de 3 linhas no chat. Só então "modo hunter OFF".

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
Por lead `[UNTESTED]`: 1. **Constrói** a request/PoC concreta. 2. **Executa** nos limites (escopo, `--rate` da ficha, nunca rajada em login/reset/MFA, sem exploit armado). 3. **Simula** o que não pode tocar → `[SIMULADO]` (nunca vira `[ACHADO]` sem execução real). 4. **Compara com o banco** (patterns/arsenal/rules). 5. **Triagem + escala** iguais ao hunter. 6. **Registra** na ficha + brain. **Para-e-confirma** antes de qualquer request que crie/altere/apague dado.

### `formação tridente` — teste diferencial em 3 navegadores 🔱
Ativação: **"forma o tridente"**. Desliga: **"recolhe o tridente"**. **Compatível com o escudo** (é observação, não ataque).
Roda os fluxos por 3 engines (**Blink**/Gecko/WebKit) e diffa o comportamento — divergência = bug P5 client-side (CSP, SameSite, redirect/URL parsing, DOM/mutation-XSS, charset, WCD). Matriz por fluxo×engine em `targets/<alvo>/tridente.md`. Header obrigatório do programa vai em todos os engines. Blink via `claude-in-chrome`; Gecko/WebKit orientados ao Tiago.

### `seguir o rastro` — ramificar a partir de um sinal
Ativação: **"segue o rastro"**. Desliga: **"chega de rastro"**. Tenacidade dirigida: de um sinal (parser
esquisito, diferencial de erro, timing), **não parar na observação** — listar 3-8 ramificações concretas,
executar (via lança), cada ramificação que responde diferente vira novo sinal. Cruzar cada nível com
`memory/patterns.md` + `arsenal.md`. Registrar a árvore na ficha.

### `modo dojo` — treino: write-up → conhecimento retido 🥋
Ativação: **"abre o dojo"**. Desliga: **"fecha o dojo"**. O lado *entrada* de conhecimento (o hunter é a
saída). Estudo **ativo**: por write-up → 3 perguntas (qual suposição do dev caiu? qual sinal observável?
qual degrau de escalada?) → distilar no banco (`memory/<classe>.md` + `arsenal.md` + `signals.md` +
`_ingested.md`) → **recall** (reconstruir de memória, fonte fechada) → **aplicar** o sinal novo nas fichas
(`code 6` mental) → **agendar revisão espaçada** (1d→1sem→1mês) em `memory/dojo-log.md`. Guardrail: 2-3
write-ups/sessão (qualidade > volume).

### `modo sábado à tarde` — curadoria do portfólio
Ativação: **"modo sábado"**. Desliga: **"acabou o sábado"**. Monta e cura o `portfolio.md` (e alimenta o
board). Por programa colado: extrair (nome/plataforma/escopo/reward/link), analisar atratividade (reward ×
escopo × fit BAC/IDOR+lógica × baixa saturação → prioridade), arquivar no `portfolio.md` sem duplicar. Se
o programa merece ficha, `code 3` + `code 7 send`. Não caça aqui — só organiza o funil.

### `modo bicicleta com rodinhas` — o cérebro como copiloto explícito
Ativação: **"põe as rodinhas"**. Desliga: **"tira as rodinhas"**. A cada passo o cérebro **sugere
proativamente qual comando ativar e por quê** antes de você pedir. Mesmo sem as rodinhas o roteamento
acontece (o [[THE-MIND]] é o cérebro) — as rodinhas só o tornam explícito.

---
_Novos comandos: copie o formato acima. Mantenha números (códigos) e nomes estáveis — o Tiago decora._
_Revisão de nomenclatura/numeração pendente: ver `TODO.md`._
