# memory/ — Banco de conhecimento distilado

Corpus de write-ups **distilados** (não copiados) para identificar padrões recorrentes de
vulnerabilidade. Conhecimento **transversal a alvos** (o estado por alvo vive no `brain/`; a
ficha canônica no board `knowledge-targets`). Consulte no início de toda caçada; alimente ao
aprender algo novo (`modo hunter`/`modo dojo`).

## Organização
- `patterns.md` — **o coração**: os 8 padrões meta (P1–P8), ligados às 6 perguntas do [[THE-MIND]].
- `arsenal.md` — **o *como testar*** por classe (sinais · confirmação · escalada · bypasses · FP · fontes).
- `signals.md` — **o *quando dispara***: índice de gatilhos (sinal → pattern → hipótese → probe 🟢/🔴 → FP)
  que o `code 6` varre contra o recon.
- `<classe>.md` — write-ups distilados por classe (crie conforme caçar; ex.: `broken-access-control.md`).
- `sources.md` — feeds/repositórios pra continuar minerando.
- `dojo-log.md` — log do `modo dojo` (write-ups distilados + fila de revisão espaçada). Criado no 1º dojo.

## Relação com o resto
- `memory/` = conhecimento genérico (padrões, técnicas). Cresce devagar, curado.
- `rules/` = regras de referência sempre-ativas (never-submit, chain-table, payloads…). O `memory/`
  aponta pra elas; não duplique.
- `brain/` = estado por alvo (o que testei/exauri). Gerido por `tools/brain.py`.

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
