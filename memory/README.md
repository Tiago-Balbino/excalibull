# memory/ — Banco de conhecimento distilado

Corpus de write-ups **distilados** (não copiados) para identificar padrões recorrentes de
vulnerabilidade. Conhecimento **transversal a alvos**. Conteúdo específico de programa vive
canonicamente no Hive; `brain/` é apenas WAL local. Consulte no início de toda caçada e
alimente ao aprender uma técnica realmente generalizável.

## Organização
- `patterns.md` — **o coração**: os 8 padrões meta (P1–P8), ligados às 6 perguntas do [[THE-MIND]].
- `arsenal.md` — **o *como testar*** por classe (sinais · confirmação · escalada · bypasses · FP · fontes).
- `signals.md` — **o *quando dispara***: índice de gatilhos (sinal → pattern → hipótese → probe 🟢/🔴 → FP)
  usado pelo motor de hipóteses para relacionar mecanismos ao contexto coletado.
- `<classe>.md` — write-ups distilados por classe (crie conforme caçar; ex.: `broken-access-control.md`).
- `sources.md` — feeds/repositórios pra continuar minerando.
- `hive-first-source-of-truth.md` — decisão arquitetural e invariantes.
- `hive-ingest-flow.md` — runbook de consulta, publicação e verificação.
- `dojo-log.md` — log do `modo dojo` (write-ups distilados + fila de revisão espaçada). Criado no 1º dojo.

## Relação com o resto
- `memory/` = conhecimento genérico (padrões, técnicas). Cresce devagar, curado.
- `rules/` = regras de referência sempre-ativas (never-submit, chain-table, payloads…). O `memory/`
  aponta pra elas; não duplique.
- Hive Mind = estado canônico por alvo.
- `brain/` = WAL da sessão, reconciliado no Hive antes do fechamento.

## Esquema de cada entrada (mantenha consistente pra padrões emergirem)
```
### <título curto>
- **Alvo · Classe · Bounty · Data** — [link]
- **Padrão:** a mecânica em 1–2 frases (a suposição do dev que deixou de ser verdade).
- **Como acharam:** o passo concreto que revelou o bug.
- **Gatilho:** o sinal que, num alvo novo, deve fazer você suspeitar do mesmo.
```

## Como alimentar
1. Write-up bom? Distile no arquivo da classe usando o esquema acima. **Nunca cole o texto
   original** — resuma + linke (força o aprendizado, respeita direito autoral).
2. Mecânica transversal e nova → também em `patterns.md`.
3. Técnica acionável nova → `arsenal.md` (com fonte) **e** um `S-*`/`C-*` em `signals.md` (a
   disciplina de sincronia do banco de sinais).

## Dojo com a estrutura atual

Usar o alvo e o contexto escolhidos no modo dojo conforme CODES.md. Hunter fica suspenso durante o estudo; o dojo não executa testes diretos no alvo.

Acrescentar à destilação os campos **pré-condições, relação causal, contraexemplos, confirmação e fonte**. Enriquecer entradas existentes quando o mecanismo já estiver representado. Manter propostas incompletas como candidatas no arquivo da classe; elas não entram automaticamente em signals.md.

Para promover um sinal, conferir sua condição observável e a interpretação da fonte, incluindo um exemplo positivo, um negativo semelhante e um incompleto. Preservar o formato atual consumido por hypotheses.py. Esse helper reconhece regex e IDs de sinais, mas não verifica todas as condições em prosa; seus resultados são candidatos a revisar, e não prova de aplicabilidade ou vulnerabilidade.

Registrar os exercícios e seus limites em dojo-log.md e as fontes em _ingested.md, criados quando uma sessão real precisar deles. Somente conhecimento transversal entra neste banco; fatos, evidências e hipóteses específicos do programa são publicados no Hive.

O projeto futuro de fichas estruturadas, avaliações e recuperação seletiva está em [PLANO-DOJO.md](../../HIVE/hive_atlas/PLANO-DOJO.md). Ele ainda não foi implementado.

> Curadoria > volume. Uma entrada bem distilada vale mais que dez links soltos.
