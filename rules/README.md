# rules/ — Regras de referência

Regras sempre-disponíveis que o `modo hunter` carrega por situação (ver roteador no
[[THE-MIND]] PARTE 3). **Nomes em inglês, conteúdo em PT.** Os princípios de caça
resumidos (§0–§12) vivem no [[THE-MIND]] PARTE 2; aqui mora o desdobramento e o material
de consulta.

| Arquivo | O que é | Quando carregar |
|---|---|---|
| `never-submit.md` | Lista de kill instantâneo + "conditionally valid / chain required" | Toda triagem (`protocolo contra-prova`) |
| `chain-table.md` | Capability → próximo bug + impactos terminais + chains reais + **âncoras-feeder por classe** | Todo sinal PASS (§12), `code 6`, `armar a arapuca` |
| `identities.md` | Env-vars de identidade por plataforma + regras de uso (nunca hardcodar) | `protocolo report`, `casa-nova`, qualquer signup em alvo |
| `mistakes.md` | Registro "não repita" por categoria (comportamento/método/tooling/report/escopo/tempo/lacunas/SSTI) | Início de todo hunt + `contra-prova` |
| `techniques.md` | Provas concretas com curl (GraphQL authz, DRF 401/404, OAuth, PKCE, source maps, gRPC, clairvoyance, SAML) | Ao caçar a classe correspondente |
| `waf-bypass.md` | Escada de bypass de WAF (7 níveis) | WAF barrando payload |
| `vendor-fingerprints.md` | Patched (não testar) / cooldowns de takeover / fingerprints de framework / CSP drift / managed-DB | Recon + antes de testar CVE de vendor |
| `payloads.md` | Referência **crua** (não destilada) de payloads XSS/SSRF/SQLi/IDOR/OAuth + escada de rotação de detecção | Execução de payload (§8) |

**Disciplina:** aprendeu técnica/erro/fingerprint novo numa caçada → atualize o arquivo
certo aqui (com a fonte). Cresce a cada engajamento.
