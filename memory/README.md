# memory/ — Banco de conhecimento distilado

Corpus de write-ups **distilados** (não copiados) para identificar padrões recorrentes de
vulnerabilidade. Conhecimento **transversal a alvos**. Conteúdo específico de programa vive
canonicamente no Hive; `brain/` é apenas WAL local. Consulte no início de toda caçada e
alimente ao aprender uma técnica realmente generalizável.

## Organização
- `patterns.md` — **o coração**: os 8 padrões meta (P1–P8), ligados às 6 perguntas do [[THE-MIND]].
- `arsenal.md` — **o *como testar*** por classe (sinais · confirmação · escalada · bypasses · FP · fontes).
- `signals.md` — **o *quando dispara***: índice de gatilhos (sinal → pattern → hipótese → probe 🟢/🔴 → FP)
  que o `code 6` varre contra o recon.
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
   disciplina de sincronia que mantém o `code 6` completo).

> Curadoria > volume. Uma entrada bem distilada vale mais que dez links soltos.
