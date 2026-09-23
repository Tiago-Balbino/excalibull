# arsenal.md — Arsenal técnico por classe de vuln

Base **acionável na hora de caçar**, por classe: sinais · confirmação · escalada/chain ·
bypasses · FP comuns · fontes. Complementa `patterns.md` (o *porquê*) e `signals.md` (o
*quando dispara*). Carregue no início de toda caçada; o `modo hunter`/`modo dojo` alimentam aqui.

> **Limite (regra de escopo):** aqui moram *técnicas, sinais e passos* — **nunca** exploit
> armado pronto. PoC = evidência mínima, em alvo autorizado.
>
> **Sincronia com `signals.md`:** toda entrada com "Sinais" espelha uma linha `S-*`/`C-*` lá.
> **Não duplique `rules/`:** para payloads crus use [[rules/payloads]]; para bypass de WAF
> [[rules/waf-bypass]]; para escalada [[rules/chain-table]]; para técnicas com curl [[rules/techniques]].

Este arquivo começa com **seeds mínimos** das classes de prioridade (BAC/IDOR + lógica). Cresce
a cada caçada — adicione a classe quando caçá-la.

---

## IDOR / BOLA (Broken Object Level Authorization) — prioridade #1
- **Sinais:** id de objeto no path/body/query (numérico/UUID/hash); endpoint "por recurso"
  (fatura, perfil, reserva); resposta com PII/objeto sensível.
- **Confirmação:** 2 contas — A cria recurso, B tenta ler/editar pelo id de A. Matriz obrigatória:
  A-como-A · A-como-B · B-como-A · fake-como-A (ver `rules/mistakes.md`). Sequencial → enumeração;
  UUID → procurar onde vaza.
- **Bypasses (id validado):** array/wrapping `{"id":[111]}`; batch smuggling `[meu, vítima]`;
  mass-assignment de dono (`userId/ownerId/memberId`); duplicate key `{"id":"meu","id":"vítima"}`;
  método (GET→POST), content-type, sufixo `.json`.
- **Escalada:** IDOR de leitura → escrita (poisoning/ATO); enumeração → exfil em massa
  (`rules/chain-table.md` → IDOR).
- **FP comuns:** authz em outra camada (autoriza pelo token, não pelo id do body); 200 pra qualquer
  id mas filtra por dono no backend; campos de identidade no body **decorativos**. **§4:** HTTP 200
  ≠ impacto — sempre par exploit + leitura-de-volta.
- **Fontes:** OWASP API1:2023 · hacktricks IDOR.

## Broken Access Control — bypass por variação (P8)
- **Sinais:** `401/403` que depende do verbo, do path exato, de `Referer`, ou rota admin adivinhável.
- **Confirmação:** repita o request barrado trocando método, `X-Original-URL`/`X-Rewrite-URL`,
  `/ADMIN`, barra final, `%2e`. Diff de resposta = sinal.
- **Escalada:** BAC de leitura → escrita; admin endpoint alcançável → confirme DELETE/PATCH, não só GET.
- **FP comuns:** best-practice sem impacto; rota que barra em todas as variantes.

## Lógica de negócio — prioridade #1
- **Sinais:** fluxo com dinheiro/estado (preço, cupom, saldo, quota, refund); campos de valor no
  request; workflow multi-etapa.
- **Confirmação:** altere valor pra absurdo (negativo/zero/gigante); pule/reordene etapas; aplique
  cupom N vezes. **Quantifique o impacto em $** (senão é feeder — `rules/chain-table.md` → business-logic).
- **Escalada:** valor errado → item grátis → saldo negativo → crédito sacável (escada de jacó).
- **FP comuns:** o servidor recalcula server-side e ignora o valor do cliente; toggle legítimo da UI.

## FP: header de contexto cliente-controlado ≠ BOLA
- **Sinal que parece bug:** header tipo `AccountType: Demo|Real` / `X-Environment` / `X-Tenant`
  obedecido — trocar muda o id/dado.
- **Teste decisivo:** comparar com o comportamento **nativo da UI** pro mesmo toggle. UI troca
  igual/sem gate → `PADRÃO DA APLICAÇÃO` (FP). UI **bloqueia** mas o header direto passa → **achado**
  (enforcement só client-side; API permite o que a UI proíbe). Liga P1/P4.

## API assinada por HMAC — o servidor assina os bytes crus ou o canônico re-parseado?
- **Contexto:** API com `sign = HMAC(secret, body)` + `nonce`. Se assina os **bytes crus recebidos**,
  abre dup-key smuggling / sign-A-send-B (validador vê 1ª ocorrência, handler a última). Se
  **re-parseia e re-serializa canônico** antes do HMAC (e o handler usa o mesmo objeto), não há
  divergência — a classe inteira morre.
- **Teste decisivo (probe assino-A-envio-B, barato, num endpoint de leitura tipo `/status`):**
  1. Assino `{"nonce":T}` **canônico**, **envio** `{"nonce": T }` **com espaços** → **200** ⇒ o servidor
     canonicaliza (não são os bytes crus). Se fosse bytes crus, o espaço quebraria a assinatura.
  2. Controle: assino+envio **idêntico com** espaço → **401 failed signature** ⇒ confirma que ele
     re-serializa sem espaço.
  3. Dup-key: envio `{"z":"A","z":"B"}`, assino colapsado `{"z":"B"}` → **200**; assino `{"z":"A"}`
     → **401** ⇒ colapsa **last-wins antes** do check de sign, no mesmo parse do handler.
  4. Unicode em chave: envio `{"a":1,"a":2}`, assino `{"a":2}` → **200** ⇒ resolve `\uXXXX` no parse.
- **Sobrevivente:** se canonicaliza, só resta a **divergência numérica** (canonicalizador vs `float()`
  do handler): `1e-8` vs `"0.00000001"` — testar formas limítrofes num campo de `$`. (No CoinSpot:
  `amount` string e float ambos normalizam a `1e-05`, sem divergência observável.)
- **Nonce:** teste se o contador é **global por key** (reusar nonce baixo em outro endpoint/versão →
  `invalid nonce`?) e se o gate é **atômico** (burst de N requests idênticas em paralelo → quantas 200?
  >1 = racy → replay/N-execução). CoinSpot: global + atômico (1/30) = sólido.

## OSINT — recuperar fluxo de auth via Wayback CDX (SPA/OAuth) — passivo
- **Sinais:** alvo é SPA (Next.js/`/_next/` etc.) com login via serviço dedicado (`*-auth-service`, `/login`, `/token`); auth é opaca no bundle. Bundle diz "usa IdP X" mas sem confirmar.
- **Confirmação (100% passiva, sem tocar o alvo):** `curl "https://web.archive.org/cdx/search/cdx?url=<auth-host>/*&output=text&fl=original,timestamp,statuscode&collapse=urlkey&limit=2000"`. Minerar as URLs `/login?...`/`/callback?...` arquivadas: elas frequentemente embutem **o IdP real** (ex.: tenant Auth0 no `iss=`), o **param de redirect** (`referrer_url`/`redirect_uri`/`returnTo`) e o shape do `?code=&state=` (mesmo com codes expirados). Recupera o fluxo OAuth inteiro sem uma request ao alvo.
- **Escalada:** o param de redirect recuperado vira lead **open-redirect-em-login → leak de code/token** (testar host arbitrário → §12 chain com OAuth). O IdP revelado abre a superfície do IdP (mas cuidado: IdP terceiro/SaaS costuma ser OOS).
- **FP comuns:** codes/tokens arquivados são single-use e expirados (inúteis como cred viva — não confundir "achei um code no Wayback" com "tenho sessão"). IA fica "Temporarily Offline" intermitente → reprovar. 0 capturas ≠ inexistente.
- **Fontes:** Internet Archive CDX API. Espelhado em `signals.md` (`S-OSINT-CDX-01`). Caso real: Yahoo Lightyear CMS → Auth0 tenant + lead `referrer_url` (2026-09-08).

---

## L1/EVM — conservação de valor (gas/fee/mint/burn) 🔗

Classe para blockchain/L1 (ex.: Circle Arc). Alvo: **valor criado ou destruído do nada** na
camada de execução (fee accounting, reward do bloco, mint/burn de native coin).

- **Sinais:** custom `reward_beneficiary`/handler de fee que sobrescreve o comportamento do revm;
  "USDC-as-gas"/fee em token de N casas; base fee **redirecionada** em vez de queimada; precompile
  de mint/burn; EMA/smoothing de base fee; EIP-8037 reservoir/state-gas split.
- **Confirmação (o teste-chave):** montar a **equação de conservação** — `débito líquido do sender ==
  crédito do beneficiário`. Ler a **versão EXATA** do revm no `Cargo.lock` (não assumir): `Gas::used()`
  (= `spent - refunded`?), a ordem do `post_execution` (`refund → reimburse_caller → reward_beneficiary`),
  e o que o `reimburse_caller` devolve (`remaining + reservoir + refunded`). Diferença entre o custom e o
  stock = candidato a mint. Baixar o crate do crates.io (`static.crates.io/crates/<c>/<c>-<v>.crate`) p/
  ler o source — o operador clona (github/crates.io são barrados pelo scope_hook).
- **Escalada:** mint por-tx × nº de txs = inflação → A1 (Extreme). Mesmo **latente** (gated por spec/hardfork
  inativo, ex.: reservoir=0 em PRAGUE) vira nota de hardening — vira Extreme se o hardfork ativar.
- **FP comuns:** redirecionar base fee (não queimar) é **balanceado** se o sender pagou o mesmo — não é mint.
  `used()` do revm já é líquido de refund (não re-subtrair). mint/burn precompile costuma ser `checked_add` +
  caller-gated (apertado). Signer/consenso: verificação delegada a effect handler é **design**, não bypass.
- **Fontes:** clone dos repos in-scope (arc-node/malachite) + crate source do revm. Caso real: Circle Arc
  `reward_beneficiary` omite `used()-reservoir` (mint latente sob EIP-8037), 2026-09-22. Ver Hive `circle-arc`.

---
_Adicione uma classe quando caçá-la (auth/sessão, SSRF, SSTI, XSS, upload, race, oauth, graphql,
llm-ai…). Mantenha o esquema: Sinais · Confirmação · Bypasses · Escalada · FP · Fontes. Espelhe o
sinal em `signals.md`._
