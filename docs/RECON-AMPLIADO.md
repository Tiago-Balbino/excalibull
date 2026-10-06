# Recon: saquear o navio e pérola negra

## Saquear o navio

Recon ativo médio/completo com crawl limitado, JavaScript/endpoints e auditoria
CORS/headers opcional. Antes de executar, consultar contexto/regras no Hive,
escolher postura de lança e registrar recibos dos ativos exatos. Escudo usa
artefatos disponíveis e orientações. Não executar estes exemplos contra um
programa sem cumprir o gate de autorização.

```sh
python3 tools/saquear.py meu-programa --hosts app.exemplo.com \
  --level medium --rate 1 --scratch /tmp/saquear
python3 tools/saquear.py meu-programa --url https://app.exemplo.com/ \
  --level full --max-pages 60 --max-js 40 --cors --rate 1 \
  --scratch /tmp/saquear
```

`--domains` acrescenta descoberta em terceiros, sem autorizar hosts encontrados.
`--skip-crawl` e `--skip-js` permitem selecionar etapas. Médio/completo ajusta
limites do crawl; scanners externos não são ligados automaticamente. Cada URL,
bundle e redirect acessado exige recibo vigente do mesmo programa. Respeitar
também constraints/headers e limites específicos informados pelo Hive.

Sem `--data-dir`, usa `.hive/outbox/` ou `EXCALIBULL_OUTBOX_DIR`.
Os arquivos permanecem pendentes de entrega a writer; consultar o contexto
do Hive não publica arquivos. Informe `HIVE_HANDLE`/`HIVE_TEAM_TAG` e selecione a
sessão com `hive_outbox.py start/status`. Os coletores usam o gerador compartilhado,
IDs por sessão/autor/assunto e revisões imutáveis. O corpus de endpoints e o snapshot
de comparação são projeções em `outbox/projections/<program>/`; contribuições por
host ficam em `outbox/programs/<program>/notes/`. Projeções não entram na exportação.

Para publicar o conjunto esperado, use `hive_outbox.py deliver/ingest/verify` com
workspace/configuração de writer explícitos. O Selo padrão exige a sessão confirmada;
`--handoff-only` preserva publicação pendente. Consultar o contexto
remoto pelo MCP oficial antes de emitir tráfego.

## Pérola negra

Três capacidades complementares ao `achar o x` e ao `saquear o navio`:
observar requisições de sessões reais, preservar sua estrutura e revisitar
ativos conhecidos comparando a superfície observada. Ferramenta:
`tools/perola_negra.py`. Essas capacidades pertencem ao **pérola negra**.

## Preparação

O agente consulta o Hive pelo `program_id`, recon anterior, descartes e regras.
`--data-dir`/`EXCALIBULL_OUTBOX_DIR` seleciona o staging local de contribuições,
com padrão `.hive/outbox/`. A preparação funciona sem papel writer, configuração
de servidor, Qdrant, Ollama ou túnel no computador. Esses arquivos são pendentes
e não substituem a consulta ao Hive remoto pelo cliente oficial `hive mind`.
Metadados: `python3 tools/hive_workspace.py workspace`.

Antes da coleta estática: `hive_get_context` no ativo exato (URL concreta com `url_prefix` para requests) e registrar a resposta
com `tools/hive_scope_cache.py record resposta.json`. O programa do recibo deve
coincidir com o selecionado. O coletor verifica cada URL, inclusive bundles,
mapas e redirects. Hosts descobertos não recebem autorização automática.

Aplicar também constraints do Hive (manual-only, rate, headers obrigatórios,
ações permitidas). `--rate` controla a coleta estática. Manual-only exige escolher
observação de navegação manual, sem revisita automatizada. Em postura escudo,
usar artefatos já coletados e instruções; a revisita ativa depende da postura
que permite testes diretos.

## HAR: importar tráfego já coletado

No navegador, usar contas próprias de teste, percorrer o fluxo autorizado e
exportar o HAR da aba Network. Manter o HAR bruto em área privada fora do
repo/Hive: ele pode conter credenciais e dados pessoais. A importação é offline;
não reproduz requests nem copia o HAR para o writer.

```sh
python3 tools/perola_negra.py meu-programa \
  --har /tmp/privado/fluxo.har --role member --flow checkout \
  --data-dir /caminho/excalibull-outbox --scratch /tmp/perola-negra
```

Executar novamente com outro HAR/papel para comparar contextos. Usar aliases
(`member`, `admin`, `checkout`), sem nomes/e-mails das contas. O papel é informado
pelo operador; presença de credencial não comprova autenticação bem-sucedida.
`browser_recon.py <program> --har ... --output ...` também funciona isoladamente.
HAR e coleta estática usam somente a biblioteca padrão Python.

## CDP: observar a sessão ao vivo

Alternativa: observar um Chromium já aberto pelo operador com CDP em loopback,
em perfil de teste separado. O operador faz login e conduz os fluxos. Não
compartilhar a porta de depuração: ela controla a sessão. A ferramenta não abre
o navegador nem cria/salva perfis.

Instalação opcional em ambiente próprio:

```sh
python3 -m venv /tmp/excalibull-browser-venv
/tmp/excalibull-browser-venv/bin/python -m pip install playwright
```

Não é necessário instalar os browsers do Playwright para conectar ao Chromium
já aberto.

```sh
/tmp/excalibull-browser-venv/bin/python tools/perola_negra.py meu-programa \
  --cdp http://127.0.0.1:9222 --seconds 120 --role member --flow checkout \
  --data-dir /caminho/excalibull-outbox --scratch /tmp/perola-negra
```

O observador registra requests e status HTTP durante a janela escolhida. Não
navega, clica, testa permissões, reproduz requests ou salva cookies. Registra
somente URLs com recibo Hive vigente e compatível; as demais contam como filtradas.
**O filtro de observação não bloqueia tráfego do navegador**: o operador conduz
somente fluxos autorizados. Requisições iniciadas antes e contextos criados depois
da conexão podem faltar. Falhas e requests pendentes ficam na cobertura.

Referências: [eventos de rede](https://playwright.dev/python/docs/network) e
[conexão CDP](https://playwright.dev/python/docs/api/class-browsertype#browser-type-connect-over-cdp).

## Revisitar ativos conhecidos

```sh
python3 tools/perola_negra.py meu-programa \
  --hosts app.exemplo.com --revisit-known --max-hosts 10 --max-js 40 --rate 1 \
  --data-dir /caminho/excalibull-outbox --scratch /tmp/perola-negra
```

`--hosts` seleciona raízes explícitas. `--url` é repetível e permite páginas de
entrada específicas. `--revisit-known` acrescenta páginas do snapshot anterior
e raízes de hosts do corpus de endpoints no staging local. Consultar o Hive ao vivo
antes: o staging pode estar incompleto/desatualizado. Passar `--url` explicitamente
se a query for importante; seus valores não ficam no baseline. Rotas sanitizadas
com `{redacted}` não são reproduzidas.

O coletor relê HTML/bundles e compara endpoints, operações GraphQL, stacks e
hashes. Não reproduz POST/DELETE nem visita todos os endpoints encontrados.
Coleta parcial não substitui o baseline completo. Resultados:
`first-observation`, `changed`, `unchanged`, `failed`, `blocked-without-receipt`.
`unchanged` significa superfície observada igual, sem concluir ausência de bugs.
Endpoint não observado desta vez não está comprovadamente removido. Limites de
hosts/bundles, falhas e bloqueios são explícitos.

Saídas: `0` coleta observada concluída; `1` parcial; `2` erro de execução,
formato ou dependência. Isso não indica publicação confirmada.

## Estrutura, destino e fechamento

O contrato mantém host/porta, método, path sanitizado, nomes dos parâmetros
query, schema dos tipos do corpo, content-type, nomes de operações GraphQL,
papel/fluxo informado, presença de credencial e status HTTP. Não mantém valores
de query/body, conteúdo de respostas, headers livres ou credenciais. Métodos
de rotas estáticas permanecem `?` quando não foram observados.

IDs/e-mails/tokens comuns nos paths viram marcadores. Sanitização é conservadora
e exige revisão antes de publicar: slugs de pessoas podem parecer rotas comuns.
Nomes dos campos permanecem, sem valores. Não há importador completo de
OpenAPI/Postman/schema GraphQL nesta entrega.

`endpoints.py merge` aceita texto legado ou `{"program_id": "...", "records": [...]}`.
Métodos diferentes ficam separados; observações preservam parâmetros, portas,
papéis e fluxos. Repetir merge não duplica a mesma observação nem apaga status.
Método desconhecido permanece para preservar contexto. Corpus corrompido ou
programa incompatível falham sem sobrescrever o estado anterior.

Scratch: `perola-negra-records.json` e `perola-negra-coverage.json`.
Outbox local `programs/<program_id>/notes/`:

- Corpus de endpoints (`document_type: endpoint`).
- `excalibull-perola-negra-snapshot.md`: baseline completo.
- `excalibull-perola-negra-coverage.md`: cobertura da última execução.

O agente revisa conteúdo/PII, publica positivos e negativos, ingere, aguarda
`idle` e confirma read-back. O utilitário retorna
`publication: pending-ingest-idle-readback`; escrita no staging local não encerra o
protocolo. Falhas/parciais não são negativos de segurança.

CDP requer Playwright. Sua integração foi verificada com eventos simulados;
navegador real e recon contra alvo não foram executados nesta implementação.
