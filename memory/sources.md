# sources.md — Feeds pra minerar write-ups

Fontes pra alimentar o `memory/` (via `modo dojo`). Ao distilar um write-up, marque a URL em
`memory/_ingested.md` (criado no 1º dojo) pra não reprocessar.

## Write-ups / disclosures
- HackerOne Hacktivity — https://hackerone.com/hacktivity (disclosures públicos por classe)
- PortSwigger Research — https://portswigger.net/research
- Intigriti Bug Bytes / blog — https://blog.intigriti.com
- Pentester Land (agregador) — https://pentester.land/list-of-bug-bounty-writeups.html
- r/bugbounty top — https://reddit.com/r/bugbounty

## Metodologia / técnicas
- HackTricks — https://book.hacktricks.xyz
- OWASP WSTG — https://owasp.org/www-project-web-security-testing-guide/
- OWASP API Security Top 10 — https://owasp.org/API-Security/
- OWASP LLM Top 10 — https://genai.owasp.org

## Referência por classe (aponta pras rules/)
- Payloads crus → [[rules/payloads]]
- Bypass de WAF → [[rules/waf-bypass]]
- Escalada / chains → [[rules/chain-table]]
- Provas com curl → [[rules/techniques]]
- Fingerprints de vendor / patched → [[rules/vendor-fingerprints]]

## Disciplina
- 2–3 write-ups por sessão de dojo (qualidade > volume).
- Distilar a **mecânica reusável**, nunca colar o texto. Espelhar o sinal novo em `signals.md`.
