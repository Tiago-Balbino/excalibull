# Monitor de métricas

Registra números reais da sessão no WAL e prepara uma nota Hive. Começar quando
o operador ligar o protocolo; não retroagir dados desconhecidos.

```sh
python3 tools/session_monitor.py start meu-programa --mode hunter --posture lanca
python3 tools/session_monitor.py where --protocol saquear-o-navio
python3 tools/session_monitor.py event hive hive_search --duration-ms 125 --event-id chamada-1
```

O exemplo de duração deve ser substituído pelo tempo realmente medido pelo
executor. Quando não houver duração, omitir a opção. Falhas usam `--failed`.
Registrar uma chamada para cada operação Hive observada, sem conteúdo da query
ou da resposta. `where` marca modo, postura e protocolo onde houve uso.

Saquear e pérola negra medem seus subprocessos automaticamente se houver monitor
ativo para o mesmo programa. Isso não inclui todas as operações da sessão:
MCP/usage do modelo precisam ser registrados pelo agente/executor.

Um arquivo de usage traz somente números reais da plataforma:

```json
{"input_tokens": 200, "output_tokens": 40, "cached_input_tokens": 100, "source": "executor"}
```

```sh
python3 tools/session_monitor.py usage /tmp/usage-numerico.json --event-id intervalo-1
python3 tools/session_monitor.py finding achado-1 --confirmed
python3 tools/session_monitor.py status
python3 tools/session_monitor.py report
python3 tools/session_monitor.py stop
```

O JSON acima ilustra o formato; não o registrar como consumo real. Cada ID
identifica um intervalo sem sobreposição; repetir o mesmo ID não duplica os
tokens. Contagens cumulativas devem ser convertidas em deltas antes de registrar.
Input inclui cache: `total_tokens = input_tokens + output_tokens`. Sem usage,
tokens ficam indisponíveis. Um intervalo registrado não prova cobertura da sessão
inteira. O monitor nunca estima tokens a partir do tamanho do texto.
Se algum intervalo omitir cache, `cached_input_tokens` fica indisponível;
`cached_input_tokens_reported` e `cached_input_samples` conservam apenas a
contagem e a quantidade de amostras efetivamente informadas.

`finding --confirmed` só depois da confirmação de contra prova. Sem essa opção
é candidato, não achado. O marco armazena tempo de parede desde início da medição,
contexto e contagens disponíveis naquele instante. Não confundir tempo decorrido,
que inclui esperas, com tempo efetivo de processamento. IDs de achado são aliases
sem PII, detalhes de requisições ou valores sensíveis.

Uma escalada posterior mantém o ID do achado. Registrar seu marco como evento
de protocolo, por exemplo `event protocol escalada-achado-1 --event-id degrau-2`,
com contexto atualizado por `where --protocol escada-de-jaco`. Não repetir
`finding --confirmed` para contar o mesmo bug novamente.

Estado em `brain/metrics/`. O resumo contém sessão/programa, modos/posturas/
protocolos, operações Hive, sucesso/falha, duração de chamadas observadas, tokens
registrados e marcos de achados. Eventos não registrados permanecem lacunas,
sem virar zero uso. Há uma sessão ativa por WAL; outro programa exige outra
sessão. Cada evento fica associado ao contexto ativo no momento.

`report` prepara snapshot enquanto o monitor continua ativo; `stop` prepara a
nota final e encerra a medição. Em reader, preparar/entregar ao writer antes de
encerrar a publicação. A ferramenta bloqueia escrita direta em instância reader.
Nota: `programs/<program>/notes/excalibull-monitor-<session-id>.md` na instância
selecionada, com publicação pendente. O agente ingere, espera idle e confirma
read-back; desligar a medição não comprova publicação.
