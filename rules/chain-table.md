# Chain Table — capacidade → próximo bug

Referência do §12 (chain-search obrigatório), do `code 6`, do `protocolo armar a arapuca` e
do `descobrir a roda`. Chains profundas pagam o máximo.

## O algoritmo de chain-walk

1. Comece com o bug A confirmado.
2. Mapeie o que A **te dá** (capacidade/primitivo).
3. Procure nesta tabela o que **aceita a saída de A como entrada**.
4. Teste o melhor candidato (B).
5. B confirmado → mapeie capacidades combinadas → cheque impacto terminal → se não terminal,
   B vira o novo A → volta ao passo 3.
6. B falhou → próximo candidato (máx. 3 falhas por profundidade).
7. Reporte o chain quando chegar a impacto terminal ou esgotar candidatos.

## Tabela capacidade → próximo elo

| Você tem (capacidade) | Procure (próximo elo) | Combinado dá |
|---|---|---|
| **Execução de JS no contexto da vítima** | HttpOnly ausente → roubo de cookie | Token de sessão |
| | Token CSRF acessível → forjar requests | Ações autenticadas |
| | Listener postMessage sem checagem → injetar mensagens | Controle do estado do app |
| | Acesso ao DOM → ler dado sensível | PII, tokens, chaves |
| **Injeção de texto arbitrário** | Input avaliado/executado → code exec | Execução de JS |
| | Input renderizado em outro contexto → stored XSS | JS no contexto de outros users |
| | Input mandado à API → injeção de parâmetro | Abuso de API |
| **Controle de URL/redirect** | redirect_uri de OAuth → roubar auth code | Token OAuth |
| | Open redirect → phishing a partir de domínio confiável | Roubo de credencial |
| | Controle de `iframe src` → clickjacking | Manipulação de UI |
| **Controle de cookie (set/read)** | Cookie bomb (estoura headers) → bloqueia callbacks | Força página de erro |
| | Session fixation → seta session ID conhecido | Sequestro de sessão |
| | Cookie tossing → sobrescreve cookie de subdomínio | Confusão de auth |
| **Referência a janela cross-origin** | `window.location` legível → roubo de URL | Tokens na URL |
| | postMessage pra janela → injeta dado | Manipulação de estado |
| | Controle de `window.opener` → tabnabbing | Phishing |
| **SSRF (fazer requests do servidor)** | Metadata cloud → credenciais IAM | Acesso cloud |
| | Serviços internos → painéis admin | Acesso interno |
| | localhost → bypass de allowlist de IP | Bypass de auth |
| **IDOR (ler dado de outro user)** | Ler tokens de auth → impersonar | ATO |
| | Ler PII → data breach | Violação de privacidade |
| | Escrever pra outro user → modificar conta | Manipulação de conta |
| **Escrita/upload de arquivo** | Escrever no web root → web shell | RCE |
| | Escrever SVG → stored XSS | Execução de JS |
| | Escrever config → mudar comportamento do app | Takeover do app |
| **Controle de DNS (subdomínio)** | Subdomínio é redirect_uri de OAuth → roubo de token | ATO |
| | Subdomínio serve conteúdo → phishing confiável | Roubo de credencial |
| | Subdomínio com cert wildcard → MitM | Interceptação de tráfego |

## Impactos terminais (pare de chainar, reporte)

- **ATO** (Account Takeover): sessão roubada, token OAuth, reset de senha.
- **RCE**: exec server-side, web shell.
- **Exfil em massa**: PII/financeiro/credenciais em volume.
- **Admin total**: escalada de privilégio a admin.
- **Comprometimento de infra**: cred cloud → acesso ao ambiente inteiro.

## Chains profundas reais (exemplos)

- **9 elos — Self-XSS → ATO (Renwa 2026):** Self-XSS no editor → drag-drop cross-origin →
  scroll-to-fragment → listener postMessage sem checagem → vítima clica Evaluate → DOM-XSS lê
  CSRF+OAuth → cookie bomb bloqueia callback → leitura same-origin extrai code → troca → ATO.
- **4 elos — S3 → OAuth → ATO:** bucket S3 listável → bundles com `client_secret` → sem PKCE →
  intercepta code via redirect_uri manipulado → ATO.
- **5 elos — Subdomain Takeover → ATO:** CNAME dangling → reivindica subdomínio → é redirect_uri
  OAuth → cookie tossing no pai → session fixation → vítima autentica → ATO.
- **6 elos — Prompt Injection → Admin:** chatbot segue instrução injetada → IDOR via AI → exfil
  por imagem markdown → API keys vazadas → serviço interno → endpoint de promoção → Admin.

## Regras de processo

1. Confirme cada elo com request/response exato. 2. Mapeie capacidades a cada elo. 3. Busque
writeups a cada passo. 4. Time-box 20 min por elo. 5. Máx. 3 candidatos falhos por
profundidade. 6. Cada elo DIFERENTE (endpoint/mecanismo/impacto). 7. Cada elo PROVÁVEL.
8. Reporte o chain INTEIRO como uma submissão — chains pagam mais.

---

## Âncoras-feeder por classe (disciplina de feeder)

Quando um achado cai numa das classes abaixo, ele é **feeder, não report**. Antes de declarar
o achado completo, sonde as âncoras. Alguma âncora deu sinal → candidato a chain (dispare
`armar a arapuca`/`chain-builder`). Todas falharam → informativo, aplica never-submit.

### `open-redirect`
1. Reflexão de redirect_uri OAuth → `?redirect_uri=<seu-domínio>`; code entregue no seu domínio = ATO.
2. `returnTo`/`next`/`continue` pós-auth → `returnTo=javascript:alert(document.cookie)` (se `location.href=returnTo`).
3. SAML RelayState / OIDC `post_logout_redirect_uri` → `<svg onload>` / redirect externo.
4. CSRF no fluxo de login pós-redirect → self-XSS no alvo + login-CSRF = ATO.
5. Redirect pra subdomínio irmão + você controla um subdomínio → cookie tossing.

### `cors`
1. Endpoint autenticado com `Access-Control-Allow-Credentials: true` (sem isso, é informativo).
2. Endpoint de dado sensível (`/api/me`, billing, segredos) alcançável pela origin permissiva.
3. Origin-reflection + `Origin: null` (iframe sandboxed / data: URI).
4. Bypass de regex de wildcard: `target.com.attacker.com`, `nottarget.com`, `target.com\.attacker.com`.
5. Handler postMessage cross-origin sem validação de origin = o sink de roubo de dado.

### `info-disclosure`
1. Bundle/source/config com segredos OAuth → oauth-hunter (client_secret + sem PKCE).
2. Stack trace com IPs/nomes de serviço internos → alvo pro SSRF.
3. Endpoint debug devolvendo headers de request → IDOR/session fixation.
4. `.git`/`.env`/`backup.tar.gz`/`wp-config.php` expostos → creds de DB (privesc) ou chaves de assinatura (JWT alg confusion).
5. Metadata cloud alcançável via contexto XSS (`window.fetch` → 169.254.169.254) → roubo IMDS.
6. API key em bundle com escopo ativo → verifique o escopo; se acessa dado de outro user, IDOR-via-key.

### `csrf`
1. CSRF em troca de senha/e-mail/telefone → ATO (muda o vetor de recovery).
2. CSRF em desabilitar MFA / enrolar 2º fator → bypass de MFA.
3. CSRF em troca de papel/permissão/convite de time → privesc.
4. CSRF em troca de método de pagamento/endereço de saque → impacto financeiro.
5. CSRF em registro de client OAuth / criação de API key → chain de credencial-backdoor.

### `subdomain-takeover`
1. Subdomínio é redirect_uri OAuth / ACS SAML / issuer OIDC → reivindica → ATO.
2. Domínio pai compartilha cookies (`.target.com`) → cookie tossing → session fixation → ATO.
3. Subdomínio com cert wildcard → MitM/confusão de TLS.
4. Subdomínio referenciado do JS de prod (CDN, asset) → phishing de domínio confiável.
5. Subdomínio em `script-src` do CSP → bypass de CSP no pai → escala stored XSS.

### `xxe`
1. SSRF via XXE → metadata cloud (`SYSTEM "http://169.254.169.254/..."`) → creds IAM.
2. Exfil OOB pra DTD do atacante → XXE cego em cookie/config/arquivo privado.
3. SAML XXE (parse de assertion) → bypass de auth via forja de assertion assinada.
4. Upload DOCX/XLSX/SVG XXE → payload sobrevive ao pipeline → dispara no viewer interno (admin).
5. Wrapper PHP / JNDI Java → `php://filter/...` pra fonte; `jar://`/`ldap://` pra RCE via classloader.

### `file-upload`
1. Upload no web root + executável → web shell → RCE.
2. Upload SVG/HTML renderizado inline → stored XSS no contexto do viewer.
3. Path traversal no filename → sobrescreve config/cron/`authorized_keys` → privesc/RCE.
4. Metadata do upload renderiza no admin (filename, EXIF) → stored XSS no admin → ATO.
5. Upload dispara processador server-side (PDF, resize, AV) → SSRF/RCE via CVE do processador.

### `race-condition` (o multiplicador)
1. Ação financeira (transfer/saque/débito de saldo) → quantifique o valor.
2. Cupom/gift-card/referral → quantifique (produto grátis × N).
3. Tokens one-shot (reset de senha, aceite de convite, enroll de MFA) → ATO se resgatado 2×.
4. Checagem de escrita de arquivo → TOCTOU → privesc/RCE.
5. Checagem de rate-limit/quota → bypass → enumeração/scraping em massa → amplifica IDOR.

### `business-logic`
1. Arquivo público / trigger de share-with-admin → o artefato manipulado é mostrado a um user de mais privilégio?
2. Estado carrega pra outro contexto → preço manipulado stored → renderiza no admin como fonte-da-verdade.
3. Skip de workflow → acessa feature não paga → quantifique (feature premium × users).
4. Valores negativos/gigantes → overflow/sign flip → chain financeiro.
5. TOCTOU em saldo → chain de race-condition.

### `privilege-escalation`
1. Mass-assignment de papel/permissão/tenant → conta escalada vê dado de outro tenant? (amplifica IDOR).
2. Manipulação de claim JWT funciona → quais outros claims (sub/aud/iss) são desprotegidos → cross-tenant.
3. Endpoint admin alcançável mas rate-limited → confirme ações admin completas, não só GET.
4. Forced-browsing de URL admin funciona → cheque operações de escrita (DELETE/PATCH) também.
5. HTTP method override → bypass de auth → tente o mesmo truque em todo endpoint admin.
