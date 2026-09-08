# patterns.md — Padrões meta (o coração do banco)

Padrões que se repetem em dezenas de write-ups, cada um ligado a uma das 6 perguntas do
[[THE-MIND]] (PARTE 1). Se um alvo dispara um destes sinais, vá fundo. `memory/signals.md`
inverte isto (sinal → pattern → hipótese → probe); `rules/chain-table.md` diz como escalar.

---

## P1 — Autenticar ≠ Autorizar
**Mecânica:** o sistema confirma *quem* você é, mas não checa *se você pode* naquele recurso/ação.
**Onde aparece:** IDOR, escalada horizontal, "meu perfil" que aceita ID de outro usuário.
**Gatilho:** endpoint que recebe identificador de recurso (`id`, `uuid`, `account`, `file`) e
retorna/edita dado — troque pelo de outra conta e veja se barra.
→ *The Mind Q1 (quem verifica o quê) + Q6 (fail-open vs fail-closed).*

## P2 — Controle no passo N, ausente no passo N+1
**Mecânica:** o fluxo valida acesso/estado num passo, mas o seguinte confia que o anterior aconteceu.
**Onde aparece:** checkout multi-etapa, wizards, "confirmar" que aceita parâmetros sem revalidar,
pular etapa de pagamento.
**Gatilho:** processo com 2+ etapas — envie a etapa final direto, ou fora de ordem, com os
parâmetros que ela espera.
→ *The Mind Q4 (ordem de etapas garantida ou assumida).*

## P3 — ID previsível é IDOR até prova em contrário
**Mecânica:** referência direta a objeto com ID sequencial/adivinhável e sem checagem de dono.
**Onde aparece:** `?id=123`, `/invoice/1001.pdf`, UUIDs vazados em respostas anteriores.
**Gatilho:** ID incremental → enumere vizinhos. UUID → procure onde ele vaza (listagens, e-mails,
logs) pra reusar cross-account.
→ *The Mind Q2 (o que o cliente controla).*

## P4 — Cliente controla o que deveria ser server-side
**Mecânica:** preço, papel (`role`), quantidade, desconto, flag de permissão trafegam no request
e são confiados.
**Onde aparece:** `price=`, `isAdmin=true`, cupom aplicável N vezes, quantidade negativa gera crédito.
**Gatilho:** todo campo com valor de negócio no request → altere pra valor absurdo (negativo, zero,
gigante, papel elevado) e veja se o servidor aceita.
→ *The Mind Q2 + Q5.*

## P5 — Parser A ≠ Parser B (discrepância de interpretação)
**Mecânica:** dois componentes leem o mesmo dado de formas diferentes (validação vê X, execução vê Y).
**Onde aparece:** e-mail (`a@b.com@evil.com`), URL/SSRF (normalização), unicode/case em rotas
(`/ADMIN`), upload (dupla extensão), host header, divergência entre engines de navegador (tridente).
**Gatilho:** onde há validação seguida de uso, tente uma entrada que os dois lados interpretem diferente.
→ *The Mind Q5 (dado muda de formato entre camadas).*

## P6 — Estado assumido sequencial, mas requisições são paralelas (race)
**Mecânica:** checagem-e-uso não-atômicos; N requisições simultâneas passam pela checagem antes de
qualquer uma escrever.
**Onde aparece:** resgatar cupom/gift card 1×, sacar saldo, aceitar convite, aplicar voto, limites de uso.
**Gatilho:** ação "só pode uma vez" ou com limite → dispare em paralelo. Quantifique o impacto
(`rules/chain-table.md` → race-condition anchors).
→ *The Mind Q4 + Q6.*

## P7 — Superfície esquecida (existe mas não deveria estar exposto)
**Mecânica:** função/host/rota existe e funciona, só não está linkada — falta enforcement, não obscuridade.
**Onde aparece:** `/admin` via wordlist, endpoints em JS, subdomínio órfão (takeover), API antiga sem
authz, `robots.txt`.
**Gatilho:** enumere subdomínios, leia o JS, force-browse rotas de admin, cheque CNAMEs órfãos.
→ *The Mind Q3 (caminho alternativo pro mesmo efeito).*

## P8 — Bypass de controle por variação de request
**Mecânica:** o controle casa com uma forma específica do request e falha nas variantes.
**Onde aparece:** método (`GET` passa onde `POST` barra), headers (`X-Original-URL`, `X-Rewrite-URL`),
`Referer` forjado, path (`/admin/`, `/admin/.`, `%2e`).
**Gatilho:** endpoint barrado → repita trocando método, adicionando headers de override, variando o path.
→ *The Mind Q3 + Q6.*

---
_Adicione um padrão novo só quando ele for transversal (aparece em várias classes). Padrão
específico de uma classe fica no arquivo da classe (`memory/<classe>.md`)._
