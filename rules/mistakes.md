# Mistakes — registro "não repita"

Lições de engajamentos reais. Cada uma nasceu de uma sessão onde se perdeu tempo, inflou
report, ou perdeu bug. **Target-agnóstico.** Leia no início de todo hunt e no `contra-prova`.

## Top 10 (leia primeiro)

1. **Escreva artefatos no disco.** Output no terminal não é evidência. Se não está no disco, não existe.
2. **Nunca alucine paths.** `ls` todo path antes de citar em report/mensagem. Faltando → "pendente", nunca invente.
3. **Rode a triagem ANTES de escrever o report.** As perguntas do `contra-prova` matam achado fraco em 30s; report leva 30 min.
4. **Use browser real pra bug de WAF/JS/CAPTCHA/UI.** 403 de CDN em curl não é "não vulnerável" — é "você nunca chegou no app".
5. **Demonstre impacto com dado real, não linguagem teórica.** "Poderia resultar em..." = isca de N/A. "Eis o dado que acessei" = achado.
6. **Regra do irmão: teste todo endpoint/método/campo/alias adjacente.** 30%+ dos IDOR/BAC pagos são bugs de irmão.
7. **Case a versão de CVSS com a plataforma.** H1 = 3.1. Bugcrowd/Intigriti/Immunefi = 4.0. Mismatch = retrabalho de triagem.
8. **Leia a policy ANTES do 1º probe.** Headers obrigatórios (com seu user real, não `researcher`), rate limit, OOS, técnicas banidas.
9. **"CONFIRMADO" = PoC funcional contra o alvo vivo.** Fingerprint/diff de status/chain inferido = `POTENCIAL` no máximo.
10. **Corrigido uma vez, recalibra.** Mesmo erro sinalizado 2× → pare e audite; não repita.
11. **Piso de gate não é trabalho.** Se satisfazer um gate = escrever um marcador em vez de produzir evidência, o marcador é inválido. Rode o trabalho ou falhe o gate.

---

## COMPORTAMENTO
- **Piso de gate não é trabalho.** Marcador `coverage-<classe>` sem evidência real = rejeitado. Floor de wall-clock que passa via `sleep` = inválido. Inferência entre regiões (§9) = rejeitada.
- **Escreva no disco; não alucine paths.** Todo artefato citado num report é persistido com `Write` num path determinístico; `ls` pra confirmar. Subagente que alega sucesso ecoa o `ls`.
- **Não chame "CONFIRMADO" sem PoC contra o alvo vivo.** Entradas de brain de anomalia de probe usam status `LEAD`, nunca `CONFIRMED`, até um teste de 2 contas ou before/after reproduzir dano real.
- **Leia memória/brain/`.env` antes de perguntar ao Tiago.** Re-pedir credencial/token/estado que você mesmo escreveu na memória desperdiça tempo. Valor stale → atualize, não peça replay.
- **Corrigido → audite as próximas 3 ações contra a correção.** Erro sinalizado 2× no mesmo tema → pare e pergunte. Não diga "vou lembrar" e repita em 5 turnos.
- **Rankeie quando pedirem, não liste.** "Qual o mais forte?" espera lista ordenada (1/2/3) + 1 linha de porquê + 1 ação recomendada.
- **Nunca placeholder quando o valor real está a 1 arquivo.** `researcher`/`YOUR_USERNAME` em campo exigido pela policy = violação. Carregue de `policy`/`scope`/`CLAUDE.md` ou PARE e pergunte.
- **Não troque credencial no meio do teste** — invalida o PoC. A verificação usa a MESMA credencial do exploit, ou um observador independente separado.
- **Não invente faixa de bounty** — cite hacktivity ou a página do programa.
- **Rotacione o token de detecção** (§8): `alert(1)` é tier 1 de 7; negativo nele ≠ "sem XSS".
- **Registre TODO vetor exausto com o blocker específico.** Evidência negativa evita re-probe. Todo KILL dispara `brain.py record`.
- **Não re-ataque superfície EXHAUSTED sem nova capacidade.** Se o brain diz exausto com um pré-requisito, satisfaça-o ou pule.

## MÉTODO
- **Triagem (7 perguntas) ANTES de escrever report.** Se matar o achado, é a ferramenta funcionando. Siga caçando.
- **Rode chain em toda capacidade confirmada** antes do report primário (§12). Chain nulo ainda te força a olhar irmãos.
- **Regra do irmão** (§2): método × rota × mutation adjacente × nomes de param alternativos. 30 min por achado confirmado.
- **Minere o texto de rejeição — ele É a spec da re-submissão.** Cada frase da rejeição vira item de checklist com evidência casada.
- **Impacto com dado real**, nunca frase teórica. Sem impacto concreto → o achado não está pronto.
- **Diferencial de status em ID-placeholder ≠ prova de acesso unauth.** Precisa de ≥2 sinais independentes (dado real p/ ID válido sem cred; semântica de framework; confirmação no source; testes de equivalência).
- **IDOR exige teste cross-user**, não checagem de resposta a ID-placeholder. Matriz: A-como-A, A-como-B, B-como-A, fake-como-A. Crie a 2ª conta no dia 1.
- **CORS wildcard sem caminho de entrega de credencial não é explorável** (Bearer/custom header/SameSite=Strict → browser não anexa cross-origin).
- **Violação de spec sozinha não é vuln.** A seção Impacto descreve dano real, não violação de padrão.
- **Fingerprint da stack ANTES de rodar exploit específico** (`/.well-known/openid-configuration`, cookie, formato de erro).
- **WAF 403 num path = path existe** (intel de SSRF-chain), mas não é submission sozinho. 404=ausente, 403=WAF mas provável presente, 200/401/500=alcançável.
- **Asymmetria de status sozinha não prova mass-assignment.** Precisa do request que seta o campo + leitura-de-volta autenticada que prova persistência. Rotule `UNCONFIRMED` até ler de volta.
- **Exploit probabilístico precisa medir confiabilidade** antes de reivindicar. Rode 5-10× em sessões frescas; <80% = "concern arquitetural em condição controlada", não "exploit reproduzível".
- **Timing como oráculo** classifica SSRF "cego" (baselines: NXDOMAIN, porta fechada, auth-fail, filtrado).
- **Chave "scoped" ignora escopo até provar o contrário.** Crie chave scoped e martele recursos fora de escopo; 200 = bug de lógica.
- **Auth-ordering é erro de CLASSE.** Validação antes de authz (400 pra recurso próprio e fake) → o dev repetiu no grupo de rotas.
- **Não faça IDOR contra conta real desconhecida** — safe harbor só cobre o que você possui. Sem token legítimo → PARE, documente a superfície.
- **Info disclosure: chain ou pule, nunca standalone.** Source map/`.well-known`/erro verboso só sobem se autenticam contra alvo in-scope ("tem segredo" ≠ "segredo funciona").

## TOOLING
- **Browser real (browser-agent/Camoufox/Playwright) pra WAF/JS/CAPTCHA/UI.** Curl não resolve `_abck`/`__cf_bm`/Turnstile nem exercita chat/admin/WYSIWYG/postMessage.
- **Antes de "não vulnerável" em endpoint com WAF, confirme que a camada de app foi alcançada.** `0/31 bypasses` em curl contra challenge CF não significa nada.
- **"WAF bloqueia X" NUNCA é dead-end** sem rodar a escada de 7 níveis ([[rules/waf-bypass]]). Veredito só após registro nível-a-nível — e mesmo assim é "bypass exaurido", não "endpoint não vulnerável".
- **OAuth de IdP grande (Google/Apple) não completa em browser stealth** — planeje passo manual.
- **Tokens Bearer salvos expiram** — assuma stale no início da sessão; re-minte via browser.
- **Cape memória/concorrência de scanner** (`nuclei -c 25 -rl 30 -bs 25`) — senão OOM no host.
- **Perfile rate limit empiricamente (5-10 probes)** antes de hunt longo. Bloqueou → não repita, rotacione ou espere.

## REPORTING
- **Case CVSS com a policy** (H1=3.1; resto=4.0). Ler `scope`/ficha antes de pontuar.
- **Mudou a severidade, mude TODA cópia** (título, box de resumo, vetor CVSS, tabela). Grep o número/vetor antigo pós-edição.
- **Não submeta "HTTP 200" como prova** — complete "como atacante, agora eu consigo ___" com ação concreta.
- **Report de state-change = BEFORE / EXPLOIT / AFTER / CONTROL** (GET baseline → PUT exploit → GET independente → controle negativo).
- **Nunca CWE-200 como primário** — use o filho específico (306, 522, 598, 942, 307, 347, 284).
- **Título H1 ≤80 chars** (asset + weakness + 1 linha de impacto).
- **Escalada não-testada vai em seção "Untested Escalation", não no score.** Nunca pontue em "would be".
- **"Steelman do triager" antes de submeter:** escreva a frase exata que o triager usaria pra fechar como N/A. Se convence, o achado é fraco.
- **Achados chainados vão juntos, não separados** — 2 Medium relacionados viram 1 report melhor. Mas cheque dedup cross-vector (1 fix mata os dois = 1 bounty).
- **Não discuta severidade na triagem** — espere o review do programa; responda com evidência, não argumento.

## ESCOPO / POLICY
- **Leia `policy`/`scope.md` antes do 1º probe ativo** (headers com valor real, rate limit, OOS, técnicas banidas). Re-leia a cada sessão.
- **Injete rate limit + headers + categorias banidas em TODO preâmbulo** de agente/subagente.
- **Triagem econômica antes de caçar** — não persiga Lows num VDP de teto $25-150.
- **Verifique TODO wildcard antes de "recon exausto".** Probar TLD-país não listado = violação.
- **Alvo de redirect não é auto-in-scope** — rode scope-check no destino, não na origem.
- **Ação destrutiva exige instância de teste isolada, nunca produção.** Documente passos de reversão.
- **Header de atribuição = cortesia, não autorização.** Não torna request in-scope; ao cruzar pra serviço de terceiro (pagamento/analytics/chatbot backend), cheque a policy separado.

## TEMPO
- **Precheck de conectividade antes de recon/hunt** (`dig +short`, `curl -o /dev/null -w %{http_code}`). Tudo NXDOMAIN → PARE e pergunte.
- **Declare alvo inalcançável em 3 probes falhos** — não adicione variantes de curl.
- **Respeite `retry-after`** — 429 multi-minuto → mude de host/classe, registre a janela.
- **Time-box duro em chain de primitivo ambíguo** (25-30 min). Estourou → "sem chain", siga.
- **Aceite "sem submissão" como resultado válido.** 0 achados honestos > submeter ruído.
- **Update de brain no fim da sessão é parte do trabalho**, não overhead. `/resume` depende disso.

## LACUNAS DE CONHECIMENTO
- **Postura de takeover de cloud muda** — cheque a API do vendor antes de investir (ver [[rules/vendor-fingerprints]]).
- **Comportamento de browser/CSP muda a cada ~6 meses** — teste no browser atual, não em writeup velho.
- **Lib bundled/tree-shaken não tem a API pública completa** (60-90% removida) — sonde a superfície real antes de citar capacidade num chain.
- **Extração de system-prompt sozinha é Low** — enquadre como bypass de guardrail, não info disclosure. Só sobe se tem credencial/PII ou habilita ataque follow-on.
- **Chave de widget client-side é feita pra ser pública** (Segment/PostHog/Sentry DSN) — só persiga se a chave alcança APIs de management/mutação/dado de outros.
- **Maturidade da plataforma determina EV** — programa maduro: EV está em chains, lógica de negócio, superfícies de tier pago, não em "XSS na página de login".

## SSTI / SANDBOX DE TEMPLATE
- **Distinga bloqueio-de-sandbox de AttributeError** — `"invalid template"` = sandbox rejeitou; `"'X' object has no attribute 'Y'"` = getattr nativo falhou (attr não existe). Teste o blocklist num objeto onde o attr EXISTE.
- **Mapeie o blocklist sistematicamente** (~30 nomes de attr por tipo de objeto) — não jogue dardos. A lista ALLOWED é sua superfície.
- **Sandbox baseada em `is_safe_attribute` (runtime) ≠ filtro regex de source** — obfuscação de source (unicode/concat/join) é tática pra filtro-regex; contra blocklist de runtime é esforço perdido. Ache um dunder fora do blocklist, ou um tipo de objeto com gap.
- **Homoglifos unicode defeat igualdade-de-string, mas getattr do Python é estrito** — são PROBE (dizem que o blocklist usa igualdade), não bypass funcional.
- **CVE-2025-27516 `|attr('format')` só funciona pra attr não-dunder** em sandbox hardened — teste com não-dunder (`.real`, `.bit_length`) primeiro pra ter o primitivo.
- **Teste o endpoint que RENDERIZA, não o que só faz PARSE** (ex.: `/pulls/{n}/simulator` vs `/configuration-simulator`).
- **Leak de endereço de memória / DoS via `|pprint`** raramente é submittable — DoS costuma ser OOS; leak de endereço precisa de primitivo de corrupção pareado.
- **Saiba quando PARAR no SSTI** — sandbox Jinja hardened (nível Mergify) come dias. 90 min sem dunder passando nem gap de tipo → pare, pivô pra outra classe (webhook/auth/race).
