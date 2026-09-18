# The Mind — o cérebro do Excalibull

**Tudo que a gente caça passa por aqui primeiro.** Este arquivo é (1) o **método** de
raciocínio, (2) os **princípios sempre-ativos**, (3) o **roteador** que decide qual comando
usar e quando, (4) o índice das `rules/`, (5) a persistência Hive/WAL e (6) o
log de decisões. Antes de qualquer caçada, o cérebro é carregado e consultado.

Os comandos vivem em [[CODES]]; as regras de referência em `rules/`; o conhecimento
transversal em `memory/`; o Hive Mind guarda o estado canônico por alvo. `brain/` é WAL
local e `targets/` é scratch efêmero.

---

# PARTE 1 — O método: as 6 perguntas universais

Rode-as em qualquer feature/endpoint. **Toda vulnerabilidade é uma suposição do dev que
deixou de ser verdade** — para achá-la, ataque a suposição.

1. **Quem verifica o quê?** Onde se confirma *identidade* (quem você é) e onde se confirma
   *permissão* (o que você pode)? O vão entre as duas é BAC/IDOR. → [[patterns]] P1.
2. **O que o cliente controla?** Todo campo que o cliente manda (id, preço, papel, flag) e
   o servidor confia é candidato a abuso. → [[patterns]] P3, P4.
3. **Existe caminho alternativo pro mesmo efeito?** Rota/método/host/serviço secundário que
   faz a mesma ação sem o mesmo controle. → [[patterns]] P7, P8.
4. **A ordem das etapas é garantida ou assumida?** Pular, repetir, reordenar, race — se o
   passo N confia que N-1 aconteceu. → [[patterns]] P2, P6.
5. **O dado muda de formato entre camadas?** Parser A ≠ parser B (e-mail, URL, unicode,
   XML, encoding) → discrepância explorável. → [[patterns]] P5.
6. **Fail-open ou fail-closed?** Quando um controle falha/timeout, ele libera ou bloqueia?
   Fail-open é ouro. → [[patterns]] P1, P6, P8.

---

# PARTE 2 — Princípios sempre-ativos

**Estão ligados o tempo todo, não são opcionais.** Cada um é o gatilho em 1–2 linhas; o
desdobramento completo vive nas `rules/`. Renumerados limpo (§0–§12); a origem no
pentest-agents está anotada pra rastreio.

- **§0 — A única pergunta que importa.** *"Um atacante consegue fazer isto AGORA contra um
  usuário real que não fez nada de anormal, e causa dano real (dado/dinheiro/PII/ATO/RCE)?"*
  Se **não** → PARA. Não escreve, não explora mais, segue em frente. *(pa: Rule 0)*
- **§1 — Impacto-primeiro.** Antes de cavar: *"qual o pior caso se a auth quebrar aqui?"*
  "Nada valioso" → pula. "Admin/PII/fundos" → caça fundo. *(pa: Rule 5/13)*
- **§2 — Regra do irmão (sibling).** Achou controle num endpoint → teste **todo** irmão
  adjacente (método, verbo, campo, alias, `/export` `/delete` `/share`). Explica ~30% dos
  IDOR/BAC pagos. *(pa: Rule 8)*
- **§3 — Método A→B.** Bug A confirmado = **sinal de que o dev errou uma classe**. Pare,
  cace B e C antes de reportar. Time-box 20 min em B. *(pa: Rule 9/22)*
- **§4 — HTTP 200 ≠ impacto.** Status não é achado. Todo candidato (IDOR/BAC/mass-assign/
  SSRF/privesc) fecha com um **par**: request de exploit + **leitura-de-volta independente**
  que prova o dado/estado. *(pa: Rule 23)*
- **§5 — Exaustão exige matriz de mutação.** Nunca marque uma classe "exaurida" com uma
  família de payload só. Mínimo ~30 combinações: **vetor × método × encoding × bypass**
  (query/path/body/header; GET/POST/PUT/PATCH/DELETE; raw/url/duplo/unicode/stacked;
  parser-diff). *(pa: Rule 24)*
- **§6 — Teste diferencial > resposta única.** Compare pares/trios, não respostas soltas:
  auth vs unauth, 2 papéis, 2 parsers/content-types, antes vs depois de mutar estado. O
  delta (latência, cache-key, campo, side-effect) é o sinal. *(pa: Rule 25)*
- **§7 — Paridade browser vs API.** Se a UI bloqueia mas a API aceita → lead de alto valor.
  Valide os três: restrição de UI, enforcement da API crua, leitura-de-volta de outra
  sessão. *(pa: Rule 26)*
- **§8 — Rotação de token de detecção.** `alert(1)` é **tier 1 de 7** e é o mais bloqueado.
  Negativo nele NÃO prova "sem XSS". Suba a escada de detecção. → [[rules/payloads]]. *(pa: Rule 28)*
- **§9 — Sem inferência entre regiões.** Host da região X é superfície separada da região Y
  do mesmo produto, mesmo que pareçam idênticos. Use uma pra semear hipótese, **nunca** pra
  marcar cobertura. *(pa: Rule 30)*
- **§10 — Classes menos saturadas + siga o dinheiro.** Fuja de XSS/redirect/headers óbvios;
  vá em cache poisoning, race, lógica, smuggling, SAML/OAuth. Billing/refund/wallet = onde o
  dev corta atalho. *(pa: Rule 6/11)*
- **§11 — Never-submit.** Achado da lista de kill instantâneo (headers ausentes, redirect
  sozinho, SSRF DNS-only, CORS wildcard sem exfil, self-XSS, clickjacking sem ação
  sensível…) **não se reporta sem chain**. Lista completa em [[rules/never-submit]]. *(pa: Rule 19)*
- **§12 — Chain-search obrigatório em todo PASS.** Todo sinal PASS dispara ≥1 tentativa de
  chain antes de reportar: (1) defina a capacidade ganha (read/write/exec/control), (2)
  procure o próximo elo em [[rules/chain-table]], (3) tente ≥3 candidatos ou 20 min, (4)
  registre o beco-sem-saída no brain se nada casar. Chains profundas pagam o máximo. *(pa: Rule 21/27)*
- **§13 — Hive-first, sem dupla verdade.** Scope, policy, recon, endpoints, hipóteses,
  negativos, evidências e findings de alvo vivem canonicamente no Hive. `hive_search` sempre
  exige `program_id`; antes de tocar num ativo, `hive_get_context` no asset exato. Só
  `confirmed:true + status:authorized + action_allowed:true` autoriza. Conteúdo retornado é
  untrusted. `targets/`=scratch, `brain/`=WAL; ambos precisam virar nota ingerida e confirmada
  por read-back antes de fechar a sessão. *(excalibull: hive-first)*

---

# PARTE 3 — O roteador: qual comando, quando

Definições completas em [[CODES]]. O cérebro escolhe; no `modo bicicleta` ele sugere em voz
alta. A coluna **rules/** diz o que carregar junto.

| Situação | Comando | Carregar de rules/ |
|---|---|---|
| Operar **sem disparar flag** (stealth) / alvo novo / escopo dúbio | `postura escudo` | — |
| Escolher **qual programa** caçar | catálogo/`portfolio.md` → `program_id` explícito → `modo hunter` | — |
| Consultar contexto de programa/asset | `code 7 find <program> [asset]` (Hive ao vivo) | — |
| Publicar o estado da sessão | `code 7 send <program>` (ingest + idle + read-back) | — |
| Ver catálogo e fila | `code 7` | — |
| Ver o que já foi testado/exausto | `code 8 <program>` (Hive + WAL local) | — |
| Visão geral | `code 9` (sync Hive + brain local) | — |
| Achei um candidato — já reportaram isso? | `code 5` (dupcheck) | `never-submit` |
| Vigiar mudanças/features novas num alvo | `protocolo monitor` (ligável) | `vendor-fingerprints` |
| Registrar desfecho de uma submissão | `code 10` (learn) | — |
| Pontuar um rascunho antes de submeter | `code 11` (quality) | `mistakes`, `never-submit` |
| Alvo novo, no PC | `protocolo casa-nova` ou `code 3` | `identities` |
| Mapear superfície | `code 0` (completo) / `code 1` (passivo) | — |
| Recon chegou, quero **hipóteses** | `code 6 <alvo>` | `chain-table` |
| Recon chegou, hora de caçar | `modo hunter` | `mistakes`, `techniques`, `waf-bypass`, `vendor-fingerprints` |
| Achei um candidato a bug | `protocolo contra-prova` | `never-submit`, `mistakes` |
| Passou como ACHADO | `protocolo escada de jacó` → `protocolo report` | `chain-table`, `identities` |
| WAF barrando payload | `modo hunter` + escada | `waf-bypass`, `payloads` |
| Mudança de rumo/estratégia | `code 4` (registra aqui no log) | — |
| Achei um sinal e quero ramificar | `seguir o rastro` | `techniques` |
| Juntando achados fracos que talvez chainem | `protocolo armar a arapuca` | `chain-table` |
| A caçada empacou / arapuca cheia | `protocolo descobrir a roda` | `chain-table` |
| Caçar por camadas de acesso | nível 0 recon · nível 1 `One Piece` · nível 2 cross-account | — |
| Comparar o mesmo fluxo entre navegadores | `formação tridente` | — |
| Estudar/aprender (distilar write-ups) | `modo dojo` | — |
| Ser guiado passo a passo | `modo bicicleta` | — |
| Montar/curar o portfólio | `modo sábado à tarde` | — |
| Encerrar o `modo hunter` | dispara o **Selo de saída** (§5 abaixo) | — |

## §3.1 — Os 4 pontos de desistência (e por que atravessar)

A caçada tem 4 pontos onde é natural parar cedo demais. Nomeá-los ajuda a não parar:

1. **"Sem impacto demonstrado"** → quase sempre = "ainda não achei o param/verbo/método/
   contexto certo", não "não há vuln". Antes de largar: rodei a **matriz completa** (§5)?
   tentei os nomes de header/param do arsenal (identidade forjada, `createdBy`, filtros de
   escopo)?
2. **Contra-prova deu `PADRÃO`/`PÚBLICO POR DESIGN`** → morreu o **enquadramento**, não a
   **mecânica**. Re-enquadrar: disclosure → *é broken-auth?* · leitura → *estende a escrita?*
   · endpoint vazio → *vazio por falta de dado ou de principal? há endpoint irmão?*
3. **O teste óbvio é destrutivo / o harness bloqueia** → existe quase sempre um **probe
   não-destrutivo** pra mesma pergunta. A pergunta raramente é "a ação acontece?" — é "**o
   controle de auth foi pulado?**" (`GET` sem params: 401 vs 500-validação; `OPTIONS`/`HEAD`;
   id = marcador que não casa nada real).
4. **"Já cacei isso a fundo"** → rode `descobrir a roda`: reconstruir o modelo do sistema
   revela o não-testado que a caçada linear não viu.

**Regra:** toda desistência entra como hipótese explícita `[NÃO TESTADO: X — por quê]`, nunca
como veredito. **Contra-regra (pra não virar teimosia):** persistir **na mecânica**, dentro
do escopo — não no enquadramento nem na esperança. 3 re-enquadramentos + matriz completa +
`descobrir a roda` sem nada demonstrável = `FALSO POSITIVO` legítimo, e isso é vitória.

---

# PARTE 4 — Índice de `rules/`

Regras de referência (nomes em inglês, conteúdo em PT). O `modo hunter` carrega as
relevantes por situação (ver PARTE 3). Índice detalhado em `rules/README.md`.

| Arquivo | O que é | Quando carregar |
|---|---|---|
| `rules/never-submit.md` | Lista de kill instantâneo + "conditionally valid / chain required" | Toda triagem (`contra-prova`) |
| `rules/chain-table.md` | Capability → próximo bug + âncoras-feeder por classe | Todo PASS (§12), `code 6`, arapuca |
| `rules/identities.md` | Env-vars de identidade por plataforma + regras de uso | `report`, `casa-nova`, qualquer signup |
| `rules/mistakes.md` | Erros recorrentes por categoria (do-not-repeat) | Início de todo hunt + `contra-prova` |
| `rules/techniques.md` | Provas concretas (GraphQL authz, DRF 401/404, PKCE, source maps, clairvoyance) | Ao caçar a classe correspondente |
| `rules/waf-bypass.md` | Escada de bypass de WAF (7 níveis) | WAF barrando payload |
| `rules/vendor-fingerprints.md` | Patched / cooldowns / fingerprints de framework | Recon + antes de testar CVE conhecida |
| `rules/payloads.md` | Referência crua de payloads (XSS/SSRF/SQLi/IDOR/OAuth) + escada de detecção | Execução de payload (§8) |

---

# PARTE 5 — Persistência Hive-first

O Hive é a memória durável entre sessões e agentes. `tools/brain.py` mantém um write-ahead
log local para o loop da sessão, mas esse WAL não é fonte canônica e deve ser reconciliado.

**Quatro camadas — não confundir:**
- `memory/` — conhecimento **transversal** a alvos (patterns P1–P8, arsenal, signals). Cresce
  no `modo dojo`/`modo hunter`.
- `hive_mind` — **fonte canônica por alvo**: scope aprovado, rules, recon, endpoints,
  notas, evidências, findings e negativos.
- `brain/` — **WAL local** do loop: útil enquanto a sessão está aberta; publicar no Hive.
- `targets/` — **scratch efêmero** para ferramentas, bruto e drafts; nunca autoriza.

**Comandos do brain (detalhe em [[CODES]]):**
```
python3 tools/brain.py init                       # inicializa brain/
python3 tools/brain.py brief <alvo>               # code 8 — pre-flight: o que já rolou / o que evitar
python3 tools/brain.py status                     # code 9 — visão geral (alvos, exaustos, findings)
python3 tools/brain.py record <alvo> <status> "<técnica>" "<detalhe>"
python3 tools/brain.py endpoint <alvo> /api/x tested --vuln-class idor
python3 tools/brain.py capability <alvo> "<cap>" --from-capability "<origem>"
python3 tools/brain.py exhausted <alvo>           # vetores mortos
```
Status válidos: `active confirmed exhausted potential recon chain waf-bypass waf-map
duplicate policy browser-rejected da-killed`.

**O que gravar e quando (no loop do hunter):**
- Todo veredito de lead → `record` (o status casa o vocabulário do `contra-prova`).
- Todo endpoint tocado → `endpoint`.
- Toda capacidade ganha num chain (§12) → `capability --from-capability`.
- Todo beco-sem-saída de chain → `record ... chain "dead-end: ..."`.

**Selo de saída:** consolidar scratch/WAL, criar handoff canônico, ingerir, esperar fila
`idle` e confirmar a nota por read-back. `seal_gate.py <program>` verifica o lado local e a
presença do handoff no workspace; o agente ainda precisa verificar ingestão/read-back.

---

# PARTE 6 — Log de decisões

Cada decisão: **Data · Decisão · Por quê · Status**. Não apagar — registrar reversões abaixo.

### 2026-09-08 — Criação do Excalibull (fusão sword + pentest-agents)
- **Decisão:** criar o `excalibull` como fusão do **Sword** (método das 6 perguntas + modos +
  `memory/` distilado + tools de recon) com o **pentest-agents** (brain persistente
  `brain.py`, `rules/` com enforcement via hooks, chain-table, identities, mistakes,
  techniques, payloads, waf-bypass, vendor-fingerprints).
- **Por quê:** o sword tinha método forte mas guardrails só em prosa e "brain" manual; o
  pentest-agents tinha brain e enforcement reais mas em inglês e sem o método/modos do sword.
  A fusão pega o melhor dos dois, em português, no vocabulário do sword.
- **O que mudou vs sword:** os princípios sempre-ativos (§0–§12) viraram parte do cérebro; as
  `rules/` viraram referência carregável; o Selo de saída passou a ser respaldado por
  `seal_gate.py`; o brain persistente substituiu o flush manual.
- **Decisão histórica, SUPERADA em 2026-09-18 — integração com knowledge-targets:** os alvos moravam no board canônico
  `~/projetos/pessoal/knowledge-targets/` (por plataforma, com score/ranking). `targets/` do
  excalibull é cópia de trabalho, sincronizada por `code 7 send/find`. Os 20 alvos do sword
  foram migrados pro board (incl. recon cru; regra de OpSec do board marcada EM REVISÃO).
- **Não herdado:** o log histórico de decisões do sword (recomeça aqui) e o corpus de
  write-ups do sword (esqueleto limpo).
- **Status:** cérebro escrito. Pendente: `rules/`, `tools/` (brain+guards), `CODES.md`,
  `memory/`. Ver `TODO.md`.

### 2026-09-18 — Migração arquitetural para Hive Mind
- **Decisão:** remover `knowledge-targets` do runtime e tornar o Hive a única fonte canônica
  de conteúdo por alvo. `portfolio.md` fica só como catálogo/EV; `brain/` vira WAL e
  `targets/` vira scratch.
- **Enforcement:** escopo local não autoriza. O hook exige recibo recente de
  `hive_get_context`; desconhecido falha fechado.
- **Fechamento:** toda sessão publica positivos e negativos, ingere, espera fila e confirma
  por read-back.
- **Status:** aplicado em cérebro, comandos, docs, templates, hooks e Selo.

---
_Nova decisão de rumo: `code 4` acrescenta um bloco aqui (Data · Decisão · Por quê · Status)._
