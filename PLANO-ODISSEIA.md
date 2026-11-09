# Plano Odisseia

Lacunas que continuam fora da cobertura atual dos protocolos de recon.
Proposta para implementação posterior, sem coletores ou testes ativos
disparados por este documento. Fontes: inspeção de `passive.py`, `saquear.py`,
`jsrecon.py`, `apkrecon.py`, `endpoints.py` e `perola_negra.py`.

As três melhorias aprovadas pertencem ao **protocolo pérola negra**: tráfego
autenticado observado, estrutura de requisições e revisita de ativos conhecidos.
Uso e limites em [docs/RECON-AMPLIADO.md](docs/RECON-AMPLIADO.md).

## Superfícies ainda não integradas

| Lacuna | Situação atual | Proposta e critério de conclusão |
|---|---|---|
| Aplicativos móveis | `apkrecon.py` analisa APK/XAPK/APKS localmente, mas não integra os protocolos | Módulo opcional de APK com hosts, endpoints, deeplinks e configs. Artefato rastreável e sanitizado no Hive, distinguindo extração estática de comportamento real; sem autorização automática de hosts |
| OpenAPI, Postman e schema GraphQL | JS/capturas extraem rotas/nomes de operações, sem contratos completos | Importar documentos disponíveis, separar declarado/observado e manter métodos, tipos e relações; fixtures de versões e operações não observadas; introspecção remota depende de autorização |
| Dev/staging/QA | **Implementado.** `passive.py --json` emite `inventory` (prod E não-prod) com `environment`, `sources`, `in_scope`, `new` e `probe_authorization: pending-per-asset`; `saquear.py` preserva esse inventário no relatório de cobertura. Sondar continua exigindo `hive_get_context` por ativo ao vivo; nada aqui autoriza tráfego | Concluído: ambos os ambientes no inventário com ambiente/fonte/escopo e autorização por ativo pendente |
| WebSockets/eventos | Captura atual conserva estrutura HTTP, sem interpretar mensagens WebSocket, SSE ou protocolos binários | Módulo por transporte com direção, tipo/schema e sequência sanitizados; limites explícitos e sem conteúdo sensível persistido |

## Profundidade e qualidade da cobertura

| Lacuna | Situação atual | Melhoria proposta |
|---|---|---|
| Rotas/chunks não alcançados | BFS JS tem limite; conteúdo condicional pode faltar | Retomada incremental com fila persistente e indicação de caminhos pendentes, sob escopo/rate |
| Source maps completos | Valida referências limitadas, sem reconstrução integral do código original | Importação offline dos mapas coletados e extração com proveniência por arquivo, sem publicar segredos |
| Sessão/estado | Pérola negra observa os fluxos percorridos; papel é alias informado | Matriz de fluxos × papéis × estados × browsers, com pendências e exemplos; uma captura não significa cobertura total |
| Revisita autenticada comparável | Revisita automática é estática; capturas são agregadas sem diff completo entre sessões equivalentes | Comparar capturas sanitizadas por fluxo/papel/estado e distinguir diferenças de conta, versão e dados de teste |
| Baselines fora do writer | Snapshot/corpus disponíveis podem estar incompletos em relação ao Hive | Recuperar estado via Hive antes da seleção e reconciliar versões/horários |
| Progresso entre execuções | Limites podem repetir os primeiros hosts/bundles | Fila rotativa de revisitas, prioridade por mudança e retomada de adiados, sem agendamento automático nesta fase |
| Armazenamento do cliente | Rede não inventaria IndexedDB, cache, service workers e estado local | Inventariar nomes/tipos e relações com requests sob autorização, sem exportar valores pessoais |

## Investigação que o recon alimenta

Encontrar URL, método ou operação fornece superfície e sinais. Falhas de
autorização e lógica de negócio exigem hipóteses, ações permitidas e evidência:
comparar contas/papéis, verificar dono de objetos, ordem das etapas, mudanças de
estado e leitura de volta. O recon não deve rotular bugs pela presença de um
endpoint, diferença visual ou status HTTP.

Usar os protocolos auxiliares revisados: `seguir o rastro` ramifica sinais
concretos; matriz de exaustão sustenta decisões de parar;
`inventar/descobrir a roda` propõe novos caminhos quando os rastros terminam;
`contra prova` verifica duplicação, escopo, impacto e reprodução. Definições dos
demais protocolos seguem na revisão em andamento.

## Ordem sugerida para implementação futura

1. ~~Preservar ambientes não produtivos no inventário passivo.~~ **Feito**
   (`inventory` em `passive.py`/`saquear.py`; sondagem segue por autorização por ativo).
2. Importar documentação de APIs com proveniência e separado declarado/observado.
3. Integrar aplicativos móveis quando houver essa superfície no programa.
4. Acrescentar transportes de eventos e matriz de fluxos/estados.
5. Retomar coletas limitadas e comparar sessões autenticadas equivalentes.

Cada módulo informa o que observou, o que faltou e por quê. Aplicar escopo/regras
antes de tráfego, revisar PII/segredos antes de publicar e fechar com ingestão,
`idle` e read-back. Ausência de observação continua lacuna, sem virar conclusão
de segurança.
