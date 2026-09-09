# signals.md — Índice de gatilhos (o *matcher* do motor de hipóteses)

**Inverte o arsenal.** `arsenal.md` responde "como testo a classe X"; `patterns.md` "por que o
padrão P importa"; **este arquivo** responde: **"vi o sinal S no alvo → qual pattern acende, qual
hipótese, qual probe mais barato, qual FP antecipar."** É a camada de **matching** entre o recon e
o banco. Cada entrada é **greppável** (`grep S-IDOR`, `grep P1`, `grep 🟢`).

**Como usar:** `code 6 <alvo>` varre o corpus de recon contra os `Sinal:` daqui (+ âncoras-feeder de
`rules/chain-table.md`) e emite leads `[UNTESTED]` rankeados na ficha.

**Disciplina de sincronia:** toda entrada nova do `arsenal.md` com "Sinais" ganha uma linha aqui.

## Convenções
- **Sinal** = observável concreto (token/regex no JS ou response, nome de param, header, tech, comportamento).
- **Probe** = a confirmação **mais barata**. `🟢` = silencioso (ok na `postura escudo`); `🔴` = faz barulho (requer autorização).
- **Pattern** = P1–P8 do `patterns.md`. **Arsenal** = seção do `arsenal.md`.
- `id` = `S-<classe>-NN` (sinal único) ou `C-NN` (gatilho de chain / composição).

---

# Sinais únicos (Pass 1)

### S-IDOR-01 — id de objeto no path/body/query
- **Sinal:** `\b(id|uuid|account|file|invoice|order|booking|memberId|userId|profileId)\b` em request que **retorna/edita** dado.
- **Pattern:** P1, P3 · **Arsenal:** IDOR/BOLA
- **Hipótese:** authz confia no id do request → objeto de outra conta lido/escrito.
- **Probe:** 🟢 mapear onde o id aparece e se é sequencial/opaco · 🔴 2 contas (matriz A/B).
- **FP:** authz pelo token noutra camada; id decorativo; 200 p/ qualquer id mas filtra por dono.

### S-IDOR-02 — param de dono no body (mass-assignment)
- **Sinal:** `\b(userId|ownerId|memberId|accountId|createdBy|teamId|org(Id)?)\b` aceito no body de escrita.
- **Pattern:** P1, P4 · **Arsenal:** IDOR/BOLA
- **Hipótese:** injetar id de dono muda de quem o backend busca/escreve → escrita cross-account.
- **Probe:** 🔴 enviar com próprio id (baseline) vs id de teste; ver se o alvo muda + **ler de volta** (§4).
- **FP:** JWT+gateway recarrega o dono do token antes de escrever → tende a FP.

### S-BAC-01 — endpoint barrado por método/rota/header/referer
- **Sinal:** `401/403` que depende do verbo, do path exato, de `Referer`, ou rota admin adivinhável (`/admin`, `/internal`).
- **Pattern:** P3, P8 · **Arsenal:** Broken Access Control
- **Hipótese:** o controle casa só uma forma do request; variante passa.
- **Probe:** 🟢 `OPTIONS`/`HEAD` (só lê a política) · 🔴 trocar método, `X-Original-URL`/`X-Rewrite-URL`, `/ADMIN`, `%2e`.
- **FP:** best-practice sem impacto; rota que barra em todas as variantes.

### S-LOGIC-01 — campo de valor de negócio no request
- **Sinal:** `\b(price|amount|qty|quantity|discount|coupon|balance|role|isAdmin|plan|tier)\b` no body/query.
- **Pattern:** P4 · **Arsenal:** Lógica de negócio
- **Hipótese:** o servidor confia no valor do cliente → manipulação (preço/papel/quantidade).
- **Probe:** 🔴 valor absurdo (negativo/zero/gigante/papel elevado) + **ler de volta** o estado.
- **FP:** servidor recalcula server-side; toggle legítimo da UI.

### S-REDIR-01 — param de redirect
- **Sinal:** `\b(redirect|redirect_uri|returnTo|next|continue|url|dest|callback)\b` que controla pra onde vai.
- **Pattern:** P7, P8 · **Arsenal:** (feeder) · **Chain:** `rules/chain-table.md` → open-redirect
- **Hipótese:** redirect controlável → sozinho é never-submit; vale só chaineado (OAuth code / returnTo js / SAML).
- **Probe:** 🟢 ver se reflete o destino · 🔴 testar as âncoras-feeder de open-redirect.
- **FP:** redirect sozinho = never-submit (§11).

### S-HDR-01 — erro verboso vaza header interno de confiança
- **Sinal:** `x-user-id`, `x-envoy-*`, `x-forwarded-*`, api-key de serviço num stack trace; tech Envoy/Istio/gateway.
- **Pattern:** P5, P1 · **Arsenal:** (header injection)
- **Hipótese:** edge não strippa a versão client-supplied → forjar identidade/IP/role.
- **Probe:** 🟢 ler o erro e catalogar nomes/valores · 🔴 reenviar o header forjado e ver se muda.
- **FP:** edge bem configurado strippa tudo; api-key interna inútil se o gateway é interno.

### S-OSINT-CDX-01 — SPA com auth-service dedicado (fluxo recuperável no Wayback)
- **Sinal:** alvo SPA (`/_next/`, bundle opaco) + host de auth dedicado (`*-auth-service`, `/login`/`/token`); modelo de auth não confirmado só pelo bundle.
- **Pattern:** P7 (superfície) · **Arsenal:** OSINT — Wayback CDX auth-flow
- **Hipótese:** URLs `/login?...` arquivadas no Internet Archive vazam o **IdP real** (ex.: tenant Auth0 no `iss=`) + o **param de redirect** (`referrer_url`/`redirect_uri`) + shape do `?code=&state=`.
- **Probe:** 🟢 CDX API (`web.archive.org/cdx/search/cdx?url=<host>/*`), 100% passivo. Depois 🔴 testar o param de redirect (host arbitrário → leak de code).
- **FP:** codes arquivados expirados (não são sessão viva); IA intermitente; 0 capturas ≠ inexistente.

---

### S-HMAC-01 — API assinada por HMAC + nonce (sign do body)
- **Sinal:** doc/wrapper mostra `sign = HMAC-SHA512(secret, body)` + `nonce` monotônico (headers `key`+`sign`); ex. exchanges cripto.
- **Pattern:** P5 (parser A≠B), P6 (race) · **Arsenal:** API assinada por HMAC
- **Hipótese:** se assina **bytes crus** → dup-key smuggling / sign-A-send-B; se **canonical(parse)** → morto, sobra só divergência numérica + race do nonce.
- **Probe:** 🔴 (precisa 1 key) assino-A-envio-B num `/status`: espaço no body, dup-key colapsado, `\uXXXX` em chave; + burst paralelo de nonce idêntico (race) + reuso de nonce cross-endpoint (contador global?).
- **FP:** servidor canonicaliza antes do HMAC (comum) → C1/smuggle morrem; nonce atômico global → replay morto. Não marcar "exaurido" sem os 4 probes.

# Gatilhos de chain / composição (Pass 2)

### C-01 — info leak + id previsível → IDOR de leitura
- **Sinais:** S-HDR-01 (ou source map com endpoints) **+** S-IDOR-01 sequencial.
- **Chain:** o leak dá o formato/rota; o id previsível dá a enumeração → exfil (`chain-table` → info-disclosure/IDOR).

### C-02 — open redirect + OAuth → ATO
- **Sinais:** S-REDIR-01 **+** presença de fluxo OAuth (`client_id`, `redirect_uri`, `/authorize`).
- **Chain:** redirect controlável no `redirect_uri` → roubo de auth code → token (`chain-table` → open-redirect).

### C-03 — header de confiança + backend que confia sem re-verificar
- **Sinais:** S-HDR-01 **+** endpoint que muda comportamento com o header forjado.
- **Chain:** identidade forjada aceita → BAC/privesc cross-user (`chain-table` → privilege-escalation).

---
_Nova técnica no arsenal com "Sinais" → adicione o `S-*` aqui. Composição nova de 2+ sinais → um `C-*`._
