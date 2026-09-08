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

## OSINT — recuperar fluxo de auth via Wayback CDX (SPA/OAuth) — passivo
- **Sinais:** alvo é SPA (Next.js/`/_next/` etc.) com login via serviço dedicado (`*-auth-service`, `/login`, `/token`); auth é opaca no bundle. Bundle diz "usa IdP X" mas sem confirmar.
- **Confirmação (100% passiva, sem tocar o alvo):** `curl "https://web.archive.org/cdx/search/cdx?url=<auth-host>/*&output=text&fl=original,timestamp,statuscode&collapse=urlkey&limit=2000"`. Minerar as URLs `/login?...`/`/callback?...` arquivadas: elas frequentemente embutem **o IdP real** (ex.: tenant Auth0 no `iss=`), o **param de redirect** (`referrer_url`/`redirect_uri`/`returnTo`) e o shape do `?code=&state=` (mesmo com codes expirados). Recupera o fluxo OAuth inteiro sem uma request ao alvo.
- **Escalada:** o param de redirect recuperado vira lead **open-redirect-em-login → leak de code/token** (testar host arbitrário → §12 chain com OAuth). O IdP revelado abre a superfície do IdP (mas cuidado: IdP terceiro/SaaS costuma ser OOS).
- **FP comuns:** codes/tokens arquivados são single-use e expirados (inúteis como cred viva — não confundir "achei um code no Wayback" com "tenho sessão"). IA fica "Temporarily Offline" intermitente → reprovar. 0 capturas ≠ inexistente.
- **Fontes:** Internet Archive CDX API. Espelhado em `signals.md` (`S-OSINT-CDX-01`). Caso real: Yahoo Lightyear CMS → Auth0 tenant + lead `referrer_url` (2026-09-08).

---
_Adicione uma classe quando caçá-la (auth/sessão, SSRF, SSTI, XSS, upload, race, oauth, graphql,
llm-ai…). Mantenha o esquema: Sinais · Confirmação · Bypasses · Escalada · FP · Fontes. Espelhe o
sinal em `signals.md`._
