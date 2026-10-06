# Plano de correção do Excalibull para o Hive Mind atual

Data da análise: 2026-10-06. Este documento registra o diagnóstico inicial e a execução incremental da refatoração.

A recomendação é tornar o Excalibull um consumidor do cliente oficial `hive`, com consulta remota, estado local de sessão e uma fila explícita de contribuições. O Hive continua sendo a fonte canônica por programa. A prioridade inicial é corrigir a autorização local, que hoje pode divergir do veredito do servidor.

## Direção atual — pasta temporária como canal de ingestão remota

O operador definiu que a publicação deve usar um ingestor remoto do Hive. Uma pasta
local ignorada pelo Git serve exclusivamente para depositar os arquivos a enviar;
após confirmação da ingestão e read-back, os arquivos enviados podem ser apagados.
Essa pasta não é memória canônica, corpus ou baseline. Falhas mantêm somente os
itens pendentes para retry; limpeza local não pode significar exclusão no Hive.
Essa direção substitui a proposta de manter os documentos publicados em outbox
durável e depender de um workspace de writer acessível ao Excalibull.

Verificação de 2026-10-06:

- `main` remoto do Mind e release/instalação atual: v1.4.0, commit `678572a`.
  `hive mind` anuncia quatro ferramentas de leitura; não anuncia ingestão/upload.
- Existe `POST /api/v1/ingest`, mas o handler ingere o workspace já existente no
  servidor e não lê documentos do corpo da requisição. `RemoteClient.IsWriter()`
  retorna `false`. Isso não implementa envio dos arquivos do computador do membro.
- A API do Center também foi conferida na revisão remota `master` `d9da3a4`, em
  cópia temporária: não há rota de upload/contribuição de documentos ao Mind.
- O serviço remoto respondeu saudável como v1.4.0. O token desta máquina está
  expirado e foi rejeitado; não foi possível homologar operações autenticadas.
  Nenhuma chamada mutável de ingestão foi usada como teste.
- A pasta observada pelo writer atual também não serve como canal descartável:
  remoções são detectadas pelo watcher e podem virar `pending_delete`, seguido
  de exclusão por poda. O canal temporário precisa ser separado da persistência
  do documento no serviço.

**Dependência para implementar esse fluxo:** contrato remoto que receba os arquivos,
persista documentos/revisões no serviço e devolva confirmação por contribuição.
Depois disso, substituir o transporte local do Excalibull pelo cliente oficial,
usar a pasta temporária apenas para envio e limpar exclusivamente arquivos cujo
conteúdo enviado tenha sido confirmado. O adaptador local entregue nas etapas
anteriores não representa o fluxo solicitado agora.

## Execução — primeira etapa implementada

- Cache schema 2, validade padrão de 15 minutos (máximo uma hora), programa/sessão/configuração do cliente e descarte de permissões de revisão anterior. Matching de URL preserva origem/porta/caminho; permissões exigem ativo exato. Aprovação por arquivo local removida.
- MCP pelo launcher oficial `hive mind`, descoberta de capacidades, contexto/busca/catálogo e diagnóstico `unknown` conservador. Configuração do projeto e hook de início atualizados.
- Coletores e análise usam staging local (`EXCALIBULL_OUTBOX_DIR`, padrão `.hive/outbox/`) sem configuração de servidor. Fichas registram projeto; notas aceitam o par plataforma/nome. Exportação gera pacote com manifesto de hashes e preserva `pending-writer`.
- Recibos antigos não são reutilizados. O Selo continua sendo verificação de preparação local: publicação requer entrega a writer, ingestão e read-back explícitos.
- Validação desta etapa: 146 testes passaram; handshake e capacidades também foram conferidos com o Mind instalado. A homologação das consultas autenticadas depende de login válido.
- Próximas etapas: gerador compartilhado para todos os documentos, manifestos duráveis por sessão/retry, confirmação automática de publicação, recuperação de baselines remotos e homologação autenticada. Exportação de pacote não implementa essas etapas.

## Execução — documentos, outbox e Selo por sessão

- Gerador compartilhado em `hive_documents.py`: autoria configurada, classificação,
  resultado de evidência, fonte, coleta RFC 3339, registro de projeto em par e ativos
  concretos canônicos. Notas, fichas, endpoints, snapshots, cobertura e monitor usam
  esse contrato. Nenhum metadado concede escopo.
- `hive_outbox.py` mantém manifestos versionados por sessão, conjunto esperado,
  IDs estáveis, revisões imutáveis, hashes e tentativas. Retry do mesmo conteúdo
  preserva a revisão; mudança reabre a publicação. Locks e escritas atômicas
  preservam concorrência e retomada. Não remove WAL ou migra arquivos anteriores.
- Endpoints e snapshots têm projeções locais separadas da exportação e contribuições
  por host/sessão/autor. Métricas compartilham a sessão da outbox. Defaults pessoais
  foram retirados; os coletores exigem `HIVE_HANDLE`/`HIVE_TEAM_TAG`.
- Adaptador de writer explícito: `deliver` verifica hashes e não sobrescreve arquivos
  divergentes; `ingest` usa `hive mind --config ... --data-dir ... --role writer`,
  confirma a capacidade anunciada e interpreta relatório schema 1, sem poda.
  Falhas depois de publicação exigem reconciliação, sem presumir rollback.
- `verify` exige fila confirmada e read-back de cada path/ID/revisão/trecho. Registra
  prova `retrieved-fragment` com validade de 15 minutos; o contrato atual continua
  sem comprovar hash integral remoto. Falha parcial ou autenticação inválida não sela.
- `seal_gate.py` exige todo o conjunto esperado e handoff vinculado aos hashes do
  scratch/WAL. `--handoff-only` permite execução local encerrada com publicação
  pendente explícita. Arquivos de hoje ou pacotes exportados não satisfazem publicação.
- Limites: entrega automatizada exige workspace de writer acessível; transporte para
  um writer remoto continua operacional. Não houve publicação real, alteração de
  escopo nem login. Baselines remotos, hipóteses com proveniência e homologação
  autenticada são os próximos incrementos. A API de contribuição direta ainda
  depende de contrato no Hive/Center.
- Validação desta etapa: suíte completa com **206 testes**; ciclo sintético com o
  gateway stdio real cobriu preparação → entrega → ingestão → fila → read-back →
  Selo. A execução sintética não equivale a homologação do serviço operacional.

## 1. Base verificada e limites

- Excalibull: `master`, commit `1fd08178a155d279f80f2301180785a7bcc40b0b`, incluindo as alterações locais existentes em `CODES.md`, `THE-MIND.md` e `memory/README.md`, além da exclusão local de `PLANO-DOJO.md`.
- Hive Mind: checkout de engenharia em `../HIVE/hive_mind`, `main`, commit `678572af36b600343b7b7dd011c1f874da0e117f`, sem alterações locais.
- Instalação: launcher `hive` v1.0.0; produto Mind v1.4.0, com o mesmo `source_revision` do checkout analisado.
- Codex: MCP já registrado pelo launcher com argumentos `mind` e configuração de URL remota. A configuração global não foi alterada.
- Diagnóstico inicial da configuração: o MCP do projeto apontava para um launcher removido e o hook do Claude tentava abrir um túnel obsoleto. Corrigidos nesta etapa: `.mcp.json` usa `hive mind` e o hook foi retirado.
- Diagnóstico com rede: `/mind/healthz` respondeu com v1.4.0. O token local está expirado e o acesso autenticado foi rejeitado. É necessário executar `hive login` para homologar consultas autenticadas; não foi realizado login nem alteração do acervo.
- `get_sync_status` retornou `unknown`. Pelo código, o cliente remoto devolve esse estado quando a consulta HTTP falha; os zeros exibidos junto dele não comprovam uma fila vazia.
- Verificação do Excalibull: **57 testes passaram** em `test_hive_integration.py`, `test_revision.py`, `test_guards.py` e `test_perola_negra.py`. Eles ainda usam fixtures da arquitetura antiga. Quatro divergências foram reproduzidas separadamente, sem tráfego para alvos.

Esta análise distingue código implementado, instalação observada e propostas de evolução. Não comprova o aceite operacional das specs 06–08, que continuam `pending` em `docs/spec/status.json`. O código e alguns guias divergem; os comportamentos citados abaixo foram conferidos na implementação.

## 2. O que mudou no Hive e onde o Excalibull ficou para trás

| Mudança implementada no Hive | Situação do Excalibull | Correção necessária |
| --- | --- | --- |
| Launcher oficial, instalação/atualização verificadas, login no Center e `hive setup`/`doctor` | Documentação, resolução de workspace e hook de início ainda dependem de configuração local antiga e túnel Qdrant | Adotar `hive mind` como entrada do MCP; retirar caminhos pessoais e túnel do fluxo padrão |
| MCP `stdio` encaminha consultas via HTTPS/JWT para `/mind`; configuração local completa deixa de ser necessária | Ferramentas exigem `config/hive.toml` e `HIVE_DATA_DIR`, inclusive para coleta/análise | Separar consulta, coleta local e publicação; manter writer local somente como configuração explícita |
| `hive_list_targets` descobre projetos entre programas, com ranking e paginação | `code 7` privilegia listagem de diretórios locais | Usar catálogo remoto, consumir `next_offset`, preservar avisos e cobertura parcial |
| Registro de projeto usa `program_id`, `platform`, `target_name` e, quando aplicável, `observed_targets` | Geradores não emitem a identidade estruturada do projeto | Gerar os metadados juntos e validar o contrato antes de preparar publicação |
| Backend remoto declara `IsWriter() == false`; `ingest_workspace` não é anunciado ao cliente remoto | Protocolos pressupõem escrita local seguida de ingestão em toda sessão | Detectar capacidades reais e manter contribuições pendentes para entrega a writer |
| Ingestão de writer possui relatório JSON por arquivo e outcomes definidos | Wrapper de CLI observa principalmente exit code; Selo verifica presença de arquivo | Interpretar relatório e confirmar a contribuição específica por read-back |
| Conversor oferece envelope versionado, hash de origem e localizadores para formatos estruturados | Cada ferramenta produz Markdown/JSON e decide seu próprio destino/metadados | Compartilhar exportação e validação; aproveitar conversor onde ele está disponível |

Histórico relevante: catálogo registrado em `69378b8`, descoberta global em `5639d65`, paginação em `1fc30dd`, HTTP/JWT em `820df0c`, cliente remoto em `e5e0543`, substituição documental da instância em `cb51626`, launcher em `206e53b` e cliente sem configuração local em `29ab448`.

### Limitação decisiva: ingestão remota não é upload

`server/http.go` expõe busca, contexto, catálogo, status e `POST /api/v1/ingest`. O último apenas solicita ingestão do workspace **do servidor**; não recebe os arquivos do computador do caçador. Além disso, não é exposto como ferramenta MCP pelo cliente remoto atual.

Portanto, trocar a ingestão do cliente antigo por uma chamada HTTP não resolve a publicação. O primeiro incremento do Excalibull deve preparar um pacote compatível e deixá-lo pendente para um writer por um canal operacional definido. Publicação direta pelo membro depende de um contrato adicional de contribuição no ecossistema Hive. Não inventar esse endpoint nem declarar dados publicados após apenas exportá-los.

## 3. P0 — corrigir autorização e diagnóstico

Arquivos: `tools/hive_scope_cache.py`, `tools/scope_hook.py`, `tools/browser_recon.py`, `tools/recon.py`, `tools/cors_headers_scan.py` e seus testes.

### Problemas confirmados

1. **Problema inicial, agora removido:** a materialização por arquivo local aceitava qualquer revisão com formato de SHA-256. Um mismatch gerava aviso, mas regras `include` ainda viravam `confirmed=true` e `action_allowed=true`. Isso contradiz `.codex/mcp-instructions.md`.
2. **Wildcard mais amplo que no Hive:** `_asset_matches()` inclui o domínio raiz para `*.example.com`; `server/scope.go` exclui o domínio raiz.
3. **Prefixo de caminho incorreto:** comparação textual com `startswith()` aceita `/apiary` sob `/api`. O Hive exige caminho exato ou descendente separado por `/`, na mesma origem normalizada.
4. **Exclusões por URL perdidas:** `scope_hook.py` consulta somente hosts. Com permissão de host e negação de `/admin`, o lookup do host permite, enquanto o lookup da URL completa nega.
5. **Isolamento incompleto no cache:** `authorization_for()` não recebe programa. O browser faz uma comparação adicional de `program_id`, mas hook e preflight não vinculam sua consulta ao programa ativo. O mesmo host pode pertencer a programas diferentes.
6. **Frescura limitada:** TTL padrão de oito horas não verifica mudança de revisão de escopo ou perda de acesso. Reduzir TTL sozinho não produz revogação imediata.

### Entrega

- Desativar `record-scope` como fonte de permissão; permitir apenas vereditos de `hive_get_context` obtidos pelo fluxo autorizado.
- Versionar o cache e invalidar recibos legados potencialmente derivados de arquivo local. Preservar o WAL e as contribuições.
- Vincular recibos ao programa, ativo exato, instância/serviço e sessão; exigir a tríade `confirmed`, `authorized`, `action_allowed`.
- Preservar URL/origem/caminho quando essa precisão for necessária. Validar destino inicial, cada redirect e ativos filhos antes de acessá-los.
- Usar fixtures comuns com a semântica de `server/scope.go` para wildcard, URL, porta, IP/CIDR e normalização. O veredito do servidor permanece a autoridade; o matcher local não amplia a permissão.
- Revalidar no início/retomada de protocolo e após falha de autenticação, mudança de programa ou revisão. Definir o limite de frescura explicitamente; operações sensíveis consultam o Hive ao vivo.
- Tratar `unknown` como estado indeterminado. Separar autenticação expirada, serviço inacessível e fila com trabalho pendente.

**Aceite:** as quatro reproduções acima passam a bloquear; um recibo de programa A nunca libera programa B; ausência, expiração, erro e exclusão bloqueiam. A suíte não aceita mais hashes arbitrários como prova de aprovação.

## 4. P1 — desacoplar infraestrutura e adotar o catálogo remoto

Arquivos: `tools/hive_paths.py`, `tools/hive_workspace.py`, `.mcp.json`, `.claude/settings.json`, `setup.sh`, `README.md`, `CODES.md` e instruções dos agentes.

### Entrega

- Criar uma camada pequena de integração, por exemplo `tools/hive_gateway.py`, para contratos de consulta, diagnóstico e capacidades. Ela usa o MCP oficial iniciado por `hive mind`; autenticação e transporte continuam no cliente Hive.
- Scripts de análise também podem consumir respostas estruturadas fornecidas pelo agente, com origem e data explícitas. Isso evita obrigá-los a conhecer tokens, Qdrant ou credenciais de servidor.
- Ler `structuredContent` em busca/contexto/catálogo. O bloco textual dessas ferramentas é apenas um resumo.
- Determinar disponibilidade de escrita por ferramentas/capacidades anunciadas; não inferir de uma pasta existente, variável de ambiente ou papel autodeclarado.
- Substituir dependência implícita de configuração local antiga por configurações explícitas: cliente remoto padrão e adaptador de writer local opcional. Não redirecionar silenciosamente uma operação de produção para arquivos arquivados.
- Remover o hook que abre SSH para a porta do túnel antigo e o caminho absoluto antigo. Diagnóstico de início deve ser curto e informar indisponibilidade sem tentar reparar infraestrutura automaticamente.
- Reconciliar o registro antigo de `.mcp.json` com o registro de usuário criado por `hive setup`. Preferir o registro oficial por usuário; se houver configuração de projeto necessária, usar o launcher estável, sem path pessoal ou binário de versão fixa.
- `code 7`: catálogo remoto e diagnóstico. `code 7 find`: contexto/busca do programa escolhido. `code 8`: contexto remoto + WAL. `code 9`: saúde, publicação pendente e estado local como informações distintas.
- Escolher projetos por `(program_id, platform, target_name)`, preservando os ativos tipados associados. `hive_search` continua restrito a um programa; descoberta entre programas pertence a `hive_list_targets`.
- Consumir `offset`/`next_offset`, ordens `balanced`, `most_documented` e `needs_recon`, além de `warnings`, `truncated` e `unregistered_files`. Paginação não elimina os limites internos de varredura.

**Aceite:** em máquina com o cliente instalado, consultar catálogo/contexto sem configuração local antiga, túnel, Ollama ou Qdrant no computador. Projeto listado, ranking ou metadado observado nunca autoriza tráfego.

## 5. P1 — padronizar documentos e criar fila de contribuições

Arquivos: `tools/hive_workspace.py`, `tools/endpoints.py`, `tools/recon_snapshot.py`, `tools/session_monitor.py`, `tools/saquear.py` e `tools/perola_negra.py`.

### Entrega

- Extrair um gerador/validador compartilhado, por exemplo `tools/hive_documents.py`, com programa, projeto, classificação, origem, coleta RFC 3339, equipe, handle e ativos.
- Emitir `platform` e `target_name` juntos. Emitir `observed_targets` somente como ativos concretos canônicos (`host:`, `ip:`, `url_prefix:`), conforme o contrato; wildcard e CIDR continuam regras de escopo.
- Retirar defaults pessoais de autoria. Equipe/handle devem ser fornecidos por configuração válida; metadados de métricas e cobertura seguem a mesma convenção.
- Dividir contribuições por assunto/projeto/ativo, com limite de tamanho verificado. Eliminar o corte silencioso de `asset_refs` nos primeiros 60 hosts do corpus de endpoints.
- Preferir contribuições por sessão/autor com nomes estáveis para retry. O corpus por programa pode ser uma projeção agregada; não exigir que diversos writers substituam um único arquivo compartilhado.
- Usar os sanitizadores existentes e validar antes de enfileirar. HAR bruto, valores de cookies, tokens e PII não acompanham a contribuição. Preservar observação, hipótese, confirmado, descartado e inconclusivo como estados distintos.
- Criar `tools/hive_outbox.py` com manifestos versionados em uma pasta local ignorada pelo Git, separada do cache de consulta e do WAL de raciocínio.

Fluxo proposto:

```text
preparado → pendente de writer → entrega confirmada → indexado → verificado por read-back
```

Cada contribuição registra ID estável, sessão, programa/projeto, paths relativos, hash do arquivo preparado, ativos e tentativas/erros. Repetir uma tentativa conserva sua identidade; corrigir conteúdo gera uma nova revisão preparada. Exportar um pacote não confirma entrega.

O adaptador de writer local opcional valida o workspace explicitamente escolhido e usa o binário oficial com configuração de writer. O cliente remoto prepara/exporta para o writer; a futura API de contribuição pode substituir essa etapa sem mudar os coletores.

**Aceite:** recon e análise funcionam em cliente remoto sem acesso de escrita ao servidor; contribuições sobrevivem a falha e reinício; nenhum arquivo preparado aparece como publicado antes da confirmação.

## 6. P1 — tornar o Selo verificável por contribuição

Arquivos: `tools/seal_gate.py`, novo gerenciador de publicação, runbook de ingestão e instruções dos agentes.

### Entrega

- Presença de um arquivo com data de hoje deixa de satisfazer a publicação da sessão. O Selo compara o conjunto esperado de contribuições com o manifesto da sessão.
- No writer, interpretar o relatório JSON `schema_version=1`, inclusive `ok`, `exit_code`, `scan_complete`, resultados por arquivo, `published` e `reason_code`.
- Distinguir `created`, `updated`, `unchanged`, `skipped`, `missing`, `failed` e `cancelled`. Um arquivo ignorado por `foreign_writer` ou ausente não comprova publicação da contribuição esperada.
- `published=true` com falha posterior exige reconciliação; falha de commit não permite presumir rollback. `unchanged` somente serve quando a identidade/conteúdo esperado já estão confirmados.
- Esperar status válido da fila e recuperar cada contribuição esperada por path e identificador estável presente na nota, verificando o conteúdo relevante. `idle` sozinho não prova que aquela nota foi indexada.
- A busca/contexto atuais não devolvem documento integral ou hash/revisão completos. Registrar o alcance da verificação; prova integral por hash/revisão depende de extensão de recuperação de documento no Hive.
- Permitir encerrar a execução com handoff local pendente e mensagem explícita. **Selo de publicação concluída** só ocorre após confirmação; não apagar WAL/outbox em situação pendente.

**Aceite:** handoff antigo, contribuição ausente, token expirado, `unknown`, lote parcialmente falho ou read-back divergente impedem declarar persistência concluída. Uma sessão retomada continua do último estado confirmado.

## 7. P2 — adaptar recon, baselines e hipóteses

| Componente | Refatoração |
| --- | --- |
| `passive.py` | Receber inventário remoto ou snapshot identificado; remover leitura obrigatória de todo o diretório Hive para calcular diff. Preservar hosts prod e não-prod |
| `saquear.py` | Coletar para scratch/outbox; eliminar exigência de writer antes de iniciar; manter autorização por destino e cobertura parcial |
| `perola_negra.py` | Importar HAR offline sem exigir writer; consultar baseline antes de revisitar; preparar endpoints, snapshot e cobertura como contribuições |
| `endpoints.py` | Corpus de sessão independente do transporte; exportar contribuições por projeto/ativo; reconstruir projeções sem sobrescrever trabalho de outros autores |
| `recon_snapshot.py` | Associar baseline a programa/projeto/URL, fonte, coleta e confirmação de publicação; não promover coleta parcial a baseline completo |
| `hypotheses.py` | Consumir contexto remoto limitado com proveniência e negativos, além do WAL; ausência de resultado não significa ausência de teste prévio |
| `target_model.py` e `brain.py` | Preservar raciocínio local; exportar resultados relevantes e reconstruir estado a partir de evidências acessíveis. Aprendizado local de pesos não vira fato do programa |
| `session_monitor.py` | Exportar pela fila; registrar latência/resultado real das operações e contexto da sessão. Tokens indisponíveis continuam indisponíveis |

**Limite do contrato atual:** busca semântica é limitada e não equivale à exportação integral do corpus. A API atual também não oferece recuperação completa por path. Diferenças e baselines devem declarar cobertura `partial`/`unknown` quando só há contexto limitado; não classificar automaticamente como “novo” todo host que faltou nesse contexto. Agregação completa entre sessões pode exigir um contrato de recuperação no Hive ou pacote completo fornecido pelo writer.

**Aceite:** mesmos dados sintéticos geram as mesmas observações em cliente remoto e writer local; resultados negativos são preservados; coleta parcial e contexto incompleto não viram cobertura completa.

## 8. P2 — documentação, testes de contrato e implantação

- Atualizar em conjunto `AGENTS.md`, `.codex/mcp-instructions.md`, `.claude/skills/hive-mind/SKILL.md`, `CLAUDE.md`, `THE-MIND.md`, `CODES.md`, `README.md`, `memory/hive-*`, `docs/RECON-AMPLIADO.md`, `docs/MONITOR.md` e instruções de `setup.sh`.
- Usar os templates mantidos de `server/skills/` como referência de contrato, preservando modos e protocolos do Excalibull. Instalar templates do Hive não deve sobrescrever cegamente as instruções específicas deste projeto.
- Reescrever `code 3`/`casa nova`: preparar ficha registrada na outbox em cliente remoto; gravar no workspace somente com adaptador writer escolhido. Nova ficha não aprova escopo.
- Revisar propostas `backstage`/`backstorage` do `TODO.md` diante da arquitetura remota. Recuperação offline e publicação posterior podem usar WAL/outbox; um backend local não ganha autoridade de escopo por essa mudança.
- Manter a integração Dojo/Atlas em etapa própria. `memory/` e regras transversais não devem virar um programa fictício no Mind; evidência restrita não se torna conhecimento geral automaticamente.
- Versionar fixtures sintéticas das respostas MCP, catálogo paginado, relatórios de ingestão e metadados de documentos. Aceitar campos adicionais e falhar conservadoramente em estados desconhecidos.
- Testar reader remoto, writer local explícito, capacidades ausentes, timeout, token expirado, isolamento de programa, exclusões por URL, retry idempotente, concorrência de contribuição e read-back divergente.
- Homologar uma sessão sintética completa com o binário de release, fora do checkout de engenharia: catálogo → contexto → resultado positivo/negativo → preparação → writer → ingestão → read-back → Selo.
- Migrar estados locais por cópia/inventário de hashes, sem ingestão automática de arquivos arquivados, alteração de escopo ou remoção de WAL. Manter compatibilidade legada explicitamente selecionada até a homologação.

## 9. Ordem recomendada de implementação

| Incremento | Prioridade | Resultado revisável | Dependência |
| --- | --- | --- | --- |
| 1. Autorização e cache | P0 | Remover autorização de arquivo local, corrigir matching, programa e URLs; invalidar cache legado; regressões verificadas | Nenhuma |
| 2. Cliente oficial e catálogo | P1 | Integração por capacidades, diagnóstico e catálogo paginado; retirar túnel do fluxo padrão | 1 |
| 3. Documentos e outbox | P1 | Metadados de projeto, exportação única, autoria e contribuições retomáveis | 2 |
| 4. Publicação e Selo | P1 | Adaptador writer explícito, relatório por arquivo e confirmação da sessão | 3 + canal operacional de entrega ao writer |
| 5. Protocolos e corpus | P2 | Saquear, pérola negra, endpoints, baselines e hipóteses sem dependência de pasta do servidor | 3–4 |
| 6. Instruções e homologação | P2 | Fluxos/documentação finais coerentes e sessão sintética completa | 1–5; atualizar docs mínimas em cada incremento |
| 7. Contribuição remota direta | Evolução conjunta | Publicação por membro sem acesso ao workspace de servidor | Contrato novo no Hive/Center, autenticação, autorização e recibos |

**Primeira ação operacional:** renovar o login desta máquina e repetir `hive doctor`. Isso habilita homologação autenticada, mas não resolve o acoplamento dos scripts nem concede capacidade de publicação.

**Primeira entrega de código:** incremento 1. **Primeiro marco funcional:** cliente remoto consulta contexto, executa um protocolo autorizado e prepara contribuições sem configuração local antiga; publicação pendente é rastreável. **Conclusão da migração:** writer confirma os documentos da sessão e o Selo verifica essa confirmação.

## 10. Fontes de implementação

Hive Mind:

- [README e fluxo do produto](../HIVE/hive_mind/README.md)
- [Histórico e propostas de evolução](../HIVE/hive_mind/PLANO_MELHORIA_E_LIMPEZA.md)
- [MCP e ferramentas por papel](../HIVE/hive_mind/server/mcp.go)
- [Backend remoto e estado unknown](../HIVE/hive_mind/server/remote.go)
- [Rotas HTTP e ingestão do workspace do servidor](../HIVE/hive_mind/server/http.go)
- [Semântica de escopo](../HIVE/hive_mind/server/scope.go)
- [Metadados e registro de projeto](../HIVE/hive_mind/server/metadata.go)
- [Catálogo paginado e limites](../HIVE/hive_mind/server/target_catalog.go)
- [Relatório de ingestão](../HIVE/hive_mind/docs/spec/contracts/ingestion-report.md)
- [Envelope do conversor](../HIVE/hive_mind/docs/spec/contracts/ingestion-document.schema.json)
- [Template Codex mantido](../HIVE/hive_mind/server/skills/codex.md)
- [Launcher, atualização e rollback](../HIVE/hive_cli/README.md)

Excalibull:

- [Invariantes MCP](.codex/mcp-instructions.md)
- [Resolução da outbox local](tools/hive_paths.py)
- [Writer e gerador de notas atuais](tools/hive_workspace.py)
- [Cache de vereditos de escopo](tools/hive_scope_cache.py)
- [Hook de autorização](tools/scope_hook.py)
- [Selo atual](tools/seal_gate.py)
- [Corpus de endpoints](tools/endpoints.py)
- [Protocolos e comandos](CODES.md)
