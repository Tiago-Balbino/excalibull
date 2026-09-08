# Never-Submit — lista de kill + achados condicionalmente válidos

Referência do `protocolo contra-prova`. Resumo sempre-ativo no [[THE-MIND]] §11.

## Lista de kill instantâneo (sem chain, não reporta)

Estes achados são **sempre rejeitados** a menos que acompanhados de um chain funcional:

- Headers ausentes (CSP/HSTS/X-Frame-Options)
- SPF/DKIM/DMARC ausentes
- Introspection de GraphQL sozinha
- Disclosure de banner/versão sem exploit de CVE
- Clickjacking sem PoC de ação sensível
- Self-XSS
- Open redirect sozinho
- SSRF só-DNS (sem exfil de dado nem acesso interno)
- CORS wildcard sem PoC de exfil com credencial
- CSRF de logout
- Rate limit em formulário não-crítico
- Sessão não invalidada no logout
- Sessões concorrentes permitidas
- IP interno em mensagem de erro
- Flags de cookie ausentes sozinhas
- `client_secret` de OAuth em app mobile (esperado)
- `client_id` de OAuth sozinho (público por design)
- Endpoint de discovery OIDC (público por design)
- Config client-side de SPA (URLs de API, chaves de Segment)
- Takeover de `*.azurewebsites.net` (Microsoft reserva hostnames desprovisionados — não
  explorável; não testar, não reportar)

## Condicionalmente válidos (viram achado quando chainados)

| Você tem | Chain necessário | Impacto combinado |
|---|---|---|
| Open redirect | + roubo de code OAuth → troca por token | ATO |
| SSRF só-DNS | + exfil de dado de serviço interno | Data breach |
| CORS wildcard | + PoC de roubo de dado com credencial | Roubo cross-origin |
| Introspection GraphQL | + bypass de auth em mutations | Ações não autorizadas |
| Listagem de S3 | + segredos em bundles → chain OAuth | ATO |
| Prompt injection | + IDOR via chatbot (dado de outro user) | Data breach |
| Subdomain takeover | + redirect_uri de OAuth naquele subdomínio | ATO |

**Regra de ouro (do §0):** rode a checagem never-submit **na ideia**, não depois de 30 min
de rascunho. Primeira pergunta ao confirmar um primitivo: "isto está na lista?" Se sim, só
continua se der pra construir o chain concreto em ≤20 min. Senão, larga e registra no brain.
