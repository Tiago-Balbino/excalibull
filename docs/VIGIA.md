# Vigia — recon completo em segundo plano: o que está vivo e o que morreu

Bot de recon local, irmão do Carrasco: recebe uma **missão** revisada, roda em
segundo plano, classifica cada host e compara com a execução anterior. Mesmo
ciclo de jobs (`submit`/`status`/`wait`/`cancel`/`jobs`), mesmo modelo de gate:
o Mind é consultado **dentro do worker** para o host e para cada URL exata antes
de qualquer tráfego. Gatilho: `protocolo vigia do mastro` em [CODES.md](../CODES.md).

## Pipeline

| Fase | O que faz | Toca o alvo? |
|---|---|---|
| 1. Descoberta passiva | Fontes de terceiros do `passive.py` (crt.sh, OTX, HackerTarget, urlscan, Wayback; VT/SecurityTrails/Shodan/Censys com chave) + `hosts` + baseline (`revisit_known`) | Não |
| 1b. Descoberta ativa | Força bruta por wordlist embutida + permutações dos nomes achados; cada candidato é gateado por host e resolvido via DNS (`active_dns.enabled`) | Só o DNS |
| 2. Gate do host | `hive_get_context` tipo `host`; só segue com `confirmed`, `authorized`, `action_allowed` e a revisão aprovada | Não |
| 3. DNS | DoH (`dns.google`, padrão, expõe a cadeia CNAME) ou resolvedor do sistema | Só o DNS autoritativo |
| 4. Gate da URL | `hive_get_context` `url_prefix` para `https://host/` (e cada porta) | Não |
| 5. Sonda de liveness | Um GET em `/` por porta de `http.probes`, ao **IP já resolvido**, sem redirect, proxy, cookie ou retry; para na primeira que responde (`probe_all: false`) | Sim, 1 GET por porta |
| 5b. Portas estendidas | **Só em host já vivo:** um GET em cada porta de `http.extended_ports` (8443, 8080, 3000...), cada uma gateada por URL | Sim, 1 GET por porta/host vivo |

Por padrão a sonda para na primeira porta que responder (`probe_all: false`),
minimizando tráfego. A janela `limits.seconds` conta a fase de varredura.

### Descoberta ativa de subdomínios (`active_dns`)

Gera candidatos `label.base` a partir da wordlist embutida
(`tools/data/vigia-subdomains.txt`, ~385 rótulos: infra, ambientes, termos de
plataforma financeira/apostas/afiliados) e, com `permutations: true`, de afixos
sobre os rótulos já observados (`api` → `api-dev`, `staging-api`, `apiv2`...).
**Cada candidato passa pelo mesmo gate do Mind por host antes do DNS** — não há
resolução sem escopo confirmado. Configure com `active_dns.enabled`,
`active_dns.wordlist` (`builtin`|`none`), `active_dns.permutations` e
`active_dns.max_candidates` (teto duro).

**Poda de ruído:** um candidato de força bruta que **não resolve** é descartado,
não vira `morto`. Só nomes que já se sabia existir (semente, passivo, baseline)
são classificados como `morto` ao desaparecer. O resumo traz `discovery.known`
(hosts conhecidos), `active_candidates` (gerados) e `active_found` (resolveram).
Com DNS curinga no domínio, a força bruta resolve nomes falsos: rode o preflight
e prefira `wordlist: none` + permutações nesse caso.

### Portas e serviços (`http.extended_ports`)

`http.probes` é o conjunto barato de liveness (tipicamente `https:443`, `http:80`).
`http.extended_ports` (até 16 entradas `scheme:porta`, distintas das de `probes`)
só é sondado em hosts **já classificados como vivos** — assim a varredura de portas
não roda nos milhares de candidatos mortos da força bruta. Cada porta estendida
passa pelo gate de URL próprio (`https://host:8443/`), respeita o rate e o
orçamento, e para junto com o resto se o alvo devolver 429 repetido.

O host vivo ganha `services` (uma entrada por porta que respondeu) e, na nota,
`extra_ports` lista as portas além da principal. O resumo traz `services` (total)
e `multiport_hosts` (hosts com mais de um serviço). Um serviço que não fala HTTP
(SSH, por exemplo) aparece como `protocol_error` com a causa registrada — ainda
conta como porta viva, pois o TCP foi aceito.

## Classificação

| Estado | Significado |
|---|---|
| `vivo` | Algum serviço respondeu: status HTTP qualquer (inclusive 4xx/5xx/429), TLS inválido ou protocolo estranho após TCP aceito |
| `sem_web` | Resolve para IP público, mas nenhuma porta sondada aceitou conexão (recusada/timeout) |
| `morto` | NXDOMAIN ou NOERROR sem endereço |
| `interno` | Só resolve para endereço não público (RFC 1918, loopback, link-local...) — **nunca sondado** |
| `fora_de_escopo` | O Mind confirmou `out_of_scope` para o host — nada é feito |
| `nao_verificado` | Mind sem confirmação, SERVFAIL/erro de DNS, URL negada, orçamento, cancelamento, 429 repetido |

`vivo` conta como vivo; `sem_web` + `morto` contam como mortos no resumo.
**`nao_verificado` nunca é morto** — é ausência de observação, não negativo.

Diff contra o baseline local (`.hive/vigia/baselines/<program>.json`):
`novo`, `morreu` (era vivo, agora morto/sem_web), `reviveu`, `mudou` (vivo nos
dois, mas status/servidor/título/redirect diferentes) e `igual`. Hosts
não verificados não sobrescrevem o estado anterior do baseline. Com
`revisit_known: true` os hosts do baseline são re-checados — é assim que o
Vigia descobre o que morreu desde a última execução.

### Leads `[UNTESTED]`

- `dangling_cname`: host morto com cadeia CNAME — candidato a subdomain
  takeover; verificar manualmente o serviço de destino antes de qualquer alegação.
- `non_public_address_in_dns`: DNS público expõe endereço interno.

Nenhum lead é achado. Seguir com `seguir o rastro` e `contra prova`.

## Preparar e executar

```sh
cp examples/vigia/mission.json .hive/vigia-mission.json   # editar
python3 tools/vigia.py validate .hive/vigia-mission.json  # sem tráfego
python3 tools/vigia.py submit .hive/vigia-mission.json    # retorna job_id
python3 tools/vigia.py wait <job_id> --seconds 30
python3 tools/vigia.py status <job_id>
python3 tools/vigia.py cancel <job_id>                    # para antes do próximo host
python3 tools/vigia.py jobs
```

Campos da missão: `domains` (para fontes passivas), `hosts` (sementes, minúsculas),
`revisit_known`, `passive.enabled`, `active_dns` (`enabled`/`wordlist`/`permutations`/
`max_candidates`), `dns.enabled`/`dns.resolver` (`doh`|`system`), `http.enabled`/
`http.probes` (`https:443`, `http:80`...)/`http.probe_all`/`http.extended_ports`
(portas só em hosts vivos), `policy` (revisão, automação permitida,
`required_headers_env`) e `limits`
(`max_hosts` ≤ 5000, `seconds` ≤ 4 h, `timeout` ≤ 30 s, `rate` 0,1–10 req/s HTTP,
`dns_rate`, `response_bytes`). Use o **menor** rate entre a missão e o programa.

`VIGIA_REQUIRED_HEADERS` (JSON) contém só os headers de identificação exigidos
pelo programa. `Authorization`/`Cookie` são rejeitados: o Vigia é anônimo.
Exige `HIVE_HANDLE`, `HIVE_TEAM_TAG` e `hive login` como o Carrasco.

## Ponte para o recon de conteúdo (`targets`)

O Vigia faz liveness; crawl, JS, endpoints e CORS são do `saquear o navio`. Em vez
de duplicar isso, o Vigia entrega os hosts vivos prontos para o saquear:

```sh
python3 tools/vigia.py targets .hive/vigia/jobs/<job_id>/result.json --level full --rate 1
```

Saída JSON com `alive_hosts`, `hosts` (porta padrão → `--hosts` do saquear),
`urls` (serviços em porta não padrão → `--url`) e `suggested_command` já montado.
**Isto não autoriza tráfego:** é uma lista de candidatos; o saquear re-gateia cada
URL via `hive_get_context` antes de qualquer requisição. Saída 0 com hosts vivos,
1 se o recon não achou nenhum host vivo, 2 se o resultado não terminou.

## Estado, journal e publicação

`.hive/vigia/jobs/<job_id>/`: `plan.json` (snapshot), `result.json` (journal
salvo a cada ~2 s e no fim), `events.jsonl` (cada tentativa HTTP gravada com
fsync **antes** do envio), `history.json` (busca no Mind, dado não confiável),
`worker.log`. Nada disso é versionado.

Ao terminar o worker prepara na outbox: um **resumo** (contagens, mudanças,
leads, cobertura e fontes falhas) e o **inventário em blocos** `vivos-N`,
`mortos-N`, `outros-N`, cada um abaixo de 12 KB para caber no limite remoto de
16 KiB, com `asset_refs` por host. Publicar e confirmar pelo fluxo oficial:

```sh
python3 tools/hive_outbox.py publish <program_id>
python3 tools/seal_gate.py <program_id>
```

Se a preparação falhar: `vigia.py stage <missão> .hive/vigia/jobs/<job_id>/result.json`
(sem tráfego; confere o hash da missão).

| Estado do job | Interpretação |
|---|---|
| `completed` | Todos os hosts classificados, nenhuma fonte passiva falhou |
| `partial` | Há `nao_verificado`, truncamento por `max_hosts`, fonte falha, 429 repetido, orçamento ou cancelamento (`reason`) |
| `blocked` | Mind indisponível ou **revisão de escopo mudou** durante a missão: tudo para |
| `failed` | Pré-condição local ou armazenamento |

Saídas: `run` 0 = completed, 1 = partial/blocked/failed com notas preparadas,
2 = erro/publicação pendente. `status`/`wait`: 0 terminal, 1 pendente, 2 erro ou
worker morto (`stale`).

## Limites conhecidos

- Cada consulta ao Mind que não confirma escopo aciona a invalidação do cache
  local de recibos do `HiveClient` (comportamento fail-closed existente). Rodar o
  Vigia em hosts fora de escopo enquanto você caça à mão pode exigir regravar
  recibos.
- DoH envia os nomes dos hosts ao `dns.google`. Use `resolver: system` se o
  programa ou você preferir não expor a lista a terceiros (perde a cadeia CNAME
  completa e, com ela, parte da detecção de `dangling_cname`).
- Liveness é sobre as portas sondadas: `sem_web` não prova ausência de outros
  serviços. Um WAF que responde por um host morto aparece como `vivo`.
- O baseline de diff é local ao operador; o histórico canônico são as notas no Hive.
- Testado offline (fakes + servidor loopback, inclusive TLS autoassinado). Nenhuma
  execução contra programa real foi feita para validar esta entrega.
