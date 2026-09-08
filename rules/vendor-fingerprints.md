# Postura de vendors — bugs corrigidos, fingerprints, cooldowns

Kill-list de classes corrigidas, assinaturas de fingerprint pra detectar framework, e tabelas
de cooldown de takeover. Consulte quando o recon aponta pra superfície de vendor (cloud, IdP,
CDN, DB gerenciado) ou quando um chain depende de comportamento de framework.

Atualize quando um engajamento provar que um vendor fechou uma classe ou uma assinatura mudou.

## Corrigidos — não testar

| Vetor | Corrigido por | Desde |
|---|---|---|
| Takeover de `*.azurewebsites.net` | Microsoft reserva hostnames desprovisionados | 2022-11 |
| "Bucket S3 público por default" em buckets novos | Block Public Access on por default | 2023-04 |
| GCS uniform bucket-level access em buckets novos | Default do Google | 2020 |
| Takeover de `*.github.io` em repo deletado | Reserva 24h + checagem de CNAME | 2018 |

## Cooldowns de subdomain-takeover (cloud)

Janela de disponibilidade após liberação do nome. Teste só se o cooldown é curto E o programa
permite takeover de SaaS de terceiro (ver `scope.md`/`policy` + §1 escopo).

| Serviço | Cooldown | Nota |
|---|---|---|
| `*.azurewebsites.net` (App Service) | Reserva indefinida | Pule — corrigido. |
| `*.trafficmanager.net` | ~2h | Testável; ainda é dangling-CNAME quando achado. |
| `*.cloudapp.net` (VM clássica) | ~7 dias | Testável, superfície limitada. |
| `*.blob.core.windows.net` | Imediato | Requer colisão de nome de storage account. |
| `*.herokuapp.com` | Imediato após deleção | Escopo do programa precisa permitir. |
| `*.fastly.net` | Imediato | Requer colisão de config, não só de nome. |
| `*.github.io` | 24h depois imediato | Só quando o CNAME dangling é confirmado. |
| `s3://<bucket>` | Imediato | Region-scoped; teste com `head-bucket` primeiro. |

## Assinaturas de fingerprint de framework
Colete 5 sinais antes de rodar CVEs específicas. Match parcial é ambíguo — rode um
diferenciador seguro antes de comprometer com uma lista de CVE.

### Keycloak vs Spring Authorization Server
| Sinal | Keycloak | Spring Auth Server |
|---|---|---|
| Path OIDC discovery | `/realms/<realm>/.well-known/openid-configuration` | `/.well-known/openid-configuration` na raiz |
| `issuer` | `https://.../realms/<realm>` | igual à base URL |
| Cookie | `KEYCLOAK_SESSION`/`KEYCLOAK_IDENTITY` | só `JSESSIONID` |
| Admin | `/auth/admin/` | sem UI admin nativa |
Rodar CVE de Keycloak no Spring desperdiça probe e acende WAF.

### Azure App Service vs S3 estático
| Sinal | Azure App Service | S3 estático |
|---|---|---|
| Headers | `x-powered-by: ASP.NET`, `Server: Microsoft-IIS`, `x-aspnet-version` | `Server: AmazonS3`, `x-amz-request-id`, `x-amz-id-2` |
| Body 404 | HTML "The resource ... has been removed" | `<Error><Code>NoSuchKey</Code>` XML |

### Next.js vs Nuxt
| Sinal | Next.js | Nuxt |
|---|---|---|
| Raiz de hidratação | `__NEXT_DATA__` | `__NUXT__` |
| Path de asset | `/_next/static/...` | `/_nuxt/...` |

## Chrome CSP drift (re-verifique a cada ~6 meses)
Antes de citar um bypass de CSP num chain, re-rode o PoC no canal estável atual — não num
writeup velho.
| Feature | Comportamento atual (≥ Chrome 124) |
|---|---|
| `'unsafe-inline'` + `nonce-...` | Nonce vence; unsafe-inline ignorado pra aquela source. |
| `'strict-dynamic'` + `'unsafe-inline'` legado | `strict-dynamic` tem precedência; unsafe-inline ignorado. |
| `script-src-attr 'unsafe-inline'` | Exigido pra handlers inline (`onclick=`, `onerror=`). |
| `trusted-types` imposto | Bloqueia sinks DOM que recebem string pura; precisa policy de trusted-type. |

## Superfície interna de DB gerenciado (catálogos Postgres)
Em Postgres gerenciado (Neon, Supabase, RDS, Crunchy), user autenticado de DB pode ler config
por-tenant via GUCs e catálogos — vaza hostnames internos usáveis como alvo de SSRF.
```sql
SELECT name, setting FROM pg_settings WHERE name NOT IN ('application_name','TimeZone','search_path');
SELECT * FROM pg_shadow; SELECT * FROM pg_user; SELECT * FROM pg_roles;
```
GUCs com prefixo de vendor (`neon.*`, `supabase.*`, `<vendor>.tenant_id`, `<vendor>.console_url`)
são as linhas interessantes — combine com qualquer primitivo SSRF no control plane.
**Não** tente `SET ROLE`/`ALTER ROLE`/`SECURITY DEFINER`/escalada de extensão/FDW outbound —
plataformas gerenciadas bloqueiam e o dead-end queima a sessão.

## Adicionar entradas
Novo hardening de vendor → linha na tabela certa com data de primeira-observação + ponteiro
pro engajamento/doc que provou. Lições narrativas vão em [[rules/mistakes]], não aqui. Mantenha este
arquivo como tabela de lookup greppável pelos hunters de recon/takeover.
