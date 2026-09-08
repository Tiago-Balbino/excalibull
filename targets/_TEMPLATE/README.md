# <Nome do Programa>

> Copie a pasta `_templates/alvo` para `<plataforma>/<slug>/` e preencha tudo.
> Mantenha `target.yml` em dia — ele alimenta o `RANKING.md`.

## 1. Identificação

| Campo            | Valor                              |
|------------------|------------------------------------|
| Plataforma       | hackerone / bugcrowd / intigriti / outros |
| Link do programa | https://…                          |
| Tipo             | bounty pago / VDP / privado        |
| Faixa de bounty  | low $… – critical $…               |
| Escopo wildcard  | sim / não                          |
| Data de início   | AAAA-MM-DD                         |

## 2. Status atual

<1–3 linhas: em que pé está o alvo hoje. Ex.: "Recon inicial feito, ~120
subdomínios vivos. Mapeando a API GraphQL. Nenhum finding ainda.">

## 3. Escopo (resumo)

- **In:** …
- **Out:** …
- Detalhes e histórico de mudanças: [`scope.md`](./scope.md)

## 4. Recon

| Métrica              | Valor | Atualizado em |
|----------------------|:-----:|---------------|
| Subdomínios          |   –   | AAAA-MM-DD    |
| Hosts vivos          |   –   | AAAA-MM-DD    |
| Endpoints coletados  |   –   | AAAA-MM-DD    |

- Stack / tecnologias: ver [`recon/tech.md`](./recon/tech.md)
- Notas de recon: [`recon/notes.md`](./recon/notes.md)

## 5. Superfície mapeada

- **Aplicações / hosts principais:** …
- **APIs:** … (REST / GraphQL / gRPC, versões, docs)
- **Autenticação / sessão:** … (tipo de token, SSO, MFA, roles)
- **Funcionalidades interessantes:** … (upload, webhooks, integrações, billing, admin)

## 6. Vetores a testar

- [ ] …
- [ ] …
- [ ] …

## 7. Findings

| Data       | Título                     | Severidade | Status no programa | Link |
|------------|----------------------------|------------|--------------------|------|
| AAAA-MM-DD | —                          | —          | —                  | [md](./findings/AAAA-MM-DD-titulo.md) |

Status: `rascunho` · `enviado` · `triado` · `aceito` · `duplicado` · `n/a` · `pago`

## 8. Log de sessões

| Data       | O que foi feito                                   |
|------------|--------------------------------------------------|
| AAAA-MM-DD | …                                                |

## 9. Score

Notas em [`target.yml`](./target.yml). Reflita aqui o resultado de
`python3 _scripts/gen_ranking.py`.

| Fator         | Nota (1–5) | Peso | Subtotal |
|---------------|:----------:|:----:|:--------:|
| bounty        |     –      |  5   |    –     |
| escopo        |     –      |  4   |    –     |
| superficie    |     –      |  4   |    –     |
| atividade     |     –      |  3   |    –     |
| familiaridade |     –      |  2   |    –     |
| oportunidade  |     –      |  2   |    –     |
| **Total**     |            |      | **–/100** |

Classe: 🔥 / ⭐ / 🌱 / ❄️

## 10. OpSec / notas

- Rate limit observado: …
- VPN / proxy exigido? …
- Contas de teste: … (credenciais **não** vão no git — ver `.gitignore`)
- Cuidados específicos do programa: …
