# Identidades de plataforma — mapa canônico de env-vars

Todo agente/skill/comando que precise de usuário, handle, e-mail, senha, token ou cookie de
uma plataforma de bug bounty **DEVE ler de uma env-var em runtime**.

> **NUNCA** hardcode usuário, e-mail, senha, token ou cookie em código, markdown, scope,
> reports ou PoCs. NUNCA adivinhe/alucine um. NUNCA use placeholder tipo `<seu-handle>` e
> assuma que o Tiago preenche. Se uma env-var necessária está vazia, **falhe alto** nomeando
> a variável faltante — não substitua por default nem caia pra identidade de outra plataforma.
>
> Este arquivo lista **nomes** de variável; os valores vivem no shell do Tiago, nunca no repo.

## HackerOne

| Env var | Guarda | Usar para |
|---|---|---|
| `HACKERONE_USERNAME` | Handle em `hackerone.com` | Campo reporter, @-menção |
| `HACKERONE_TOKEN` | Token de API pareado ao usuário | Auth REST (`Authorization: Basic`) |
| `H1_API_KEY` | Forma combinada `username:token` | Scripts que querem 1 segredo só |
| `HACKERONE_EMAIL_ALIAS` | `<handle>@wearehackerone.com` | Qualquer form/signup de alvo que peça e-mail |

## Bugcrowd

| Env var | Guarda | Usar para |
|---|---|---|
| `BUGCROWD_USERNAME` | Handle em `bugcrowd.com` | Reporter, @-menção |
| `BUGCROWD_EMAIL` | E-mail real de login | **Só o login do Bugcrowd.** Nunca expor a alvo/PoC/form de terceiro. |
| `BUGCROWD_PASSWORD` | Senha da conta | Só fluxo de auth |
| `BUGCROWD_TOTP_SECRET` | Segredo TOTP base32 | Códigos 2FA no auth |
| `BUGCROWD_EMAIL_ALIAS` | `<handle>@bugcrowdninja.com` | Form/signup de alvo que peça e-mail |
| `BUGCROWD_TOKEN` | Token de API | Auth REST (quando aplicável) |

## Intigriti

| Env var | Guarda | Usar para |
|---|---|---|
| `INTIGRITI_USERNAME` | Handle em `intigriti.com` | Reporter, @-menção |
| `INTIGRITI_TOKEN` | Token de API | Auth REST |
| `INTIGRITI_SPA_COOKIE` | Cookie de sessão SPA | Quando a API REST não serve |
| `INTIGRITI_EMAIL_ALIAS` | `<handle>@intigriti.me` | Form/signup de alvo que peça e-mail |

## YesWeHack

| Env var | Guarda | Usar para |
|---|---|---|
| `YESWEHACK_EMAIL` | `<scoped>@yeswehack.ninja` | A **única** identidade YWH (reporter e contato) |
| `YESWEHACK_TOKEN` | Token de API (quando emitido) | Auth REST |

YesWeHack **não tem campo de username separado** — não invente um.

## Regras

1. **Handle ≠ alias.** Três plataformas (H1/Bugcrowd/Intigriti) têm *handle* (`*_USERNAME`) E
   um *e-mail alias* (`*_EMAIL_ALIAS`) separados. Handle = identidade/reporter na plataforma;
   alias = o que você dá pro **programa alvo** quando o form pede e-mail. Nunca troque os dois.
2. **Isolamento entre plataformas.** Um alias da H1 só roteia mail pela H1. Nunca reuse a
   identidade (handle OU alias) de uma plataforma ao interagir com outra.
3. **E-mail pessoal é reservado.** `BUGCROWD_EMAIL` é a única var com o e-mail pessoal real, e
   só o fluxo de auth do Bugcrowd a usa. Nunca expor a programa/PoC/screenshot/report.
4. **Ler em runtime:** Python `os.environ.get("HACKERONE_USERNAME")`; Shell `"$HACKERONE_USERNAME"`;
   em prompt de skill/agente, passe o símbolo, não resolva.
5. **Falhe alto se vazio:** `error: HACKERONE_USERNAME não definido; recuso adivinhar`. Não
   escolha outra var, não use placeholder, não invente.
6. **Reports/PoCs referenciam o símbolo, nunca o valor.** No artefato salvo, escreva o símbolo
   (`${HACKERONE_EMAIL_ALIAS}`). Resolva o valor real só na hora de submeter/rodar, nunca no
   rascunho/commit. Este repo pode conter recon; identidade real nunca entra no git.

## Lookup rápido: "que identidade vai aqui?"

| Preciso | HackerOne | Bugcrowd | Intigriti | YesWeHack |
|---|---|---|---|---|
| Handle reporter / @-menção | `$HACKERONE_USERNAME` | `$BUGCROWD_USERNAME` | `$INTIGRITI_USERNAME` | (n/a) |
| E-mail no signup/PoC do alvo | `$HACKERONE_EMAIL_ALIAS` | `$BUGCROWD_EMAIL_ALIAS` | `$INTIGRITI_EMAIL_ALIAS` | `$YESWEHACK_EMAIL` |
| Auth de API | `$H1_API_KEY` *ou* `$HACKERONE_USERNAME`+`$HACKERONE_TOKEN` | `$BUGCROWD_TOKEN` | `$INTIGRITI_TOKEN` | `$YESWEHACK_TOKEN` |
| Auth web/SPA | (use API) | `$BUGCROWD_EMAIL`+`$BUGCROWD_PASSWORD`+`$BUGCROWD_TOTP_SECRET` | `$INTIGRITI_SPA_COOKIE` | (use API) |
