# Plano de implementação do Carrasco

Carrasco é o executor local de hipóteses da Excalibull, versionado neste mesmo
repositório GitHub. Recebe um experimento delimitado, verifica o escopo via Mind,
executa, preserva o journal e prepara uma contribuição. O protocolo **execução
pública** entrega a tarefa em segundo plano e aguarda sua resposta. O nome não
altera a classificação interna/restrita dos dados.

## Fronteiras dos produtos

| Produto | Integração e responsabilidade |
|---|---|
| Center/launcher | `hive login`, permissões por produto e clientes oficiais; Carrasco não lê tokens Hive nem acessa Qdrant |
| Mind | `hive_search` antes de testes; `hive_get_context` para cada URL antes de cada requisição; contribuições pela outbox, ingestão e read-back |
| Atlas | Mecanismos e recomendações `[UNTESTED]`; futuro adaptador `atlas_observe`/busca/feedback; não executa nem autoriza |
| Scout | Atualiza manifestos; aprovação continua no fluxo próprio. Mudança da revisão aprovada bloqueia o experimento |
| Burp | Futuro fornecedor de observações sanitizadas e aliases de contexto. README atual informa daemon/captura produtiva pendentes; não é dependência do MVP |
| Excalibull/Carrasco | Plano, orçamento, credenciais locais, execução, controles, decisão e contra prova; humano decide elegibilidade e submissão |

Fonte desta divisão: READMEs dos checkouts irmãos `../HIVE/hive_cli`,
`hive_mind`, `hive_atlas`, `hive_scout` e `hive_burp`, inspecionados durante a
implementação. Não equivale a homologação de versões instaladas ou serviços remotos.

## Etapa 1 — executável delimitado (implementada)

- `tools/carrasco.py`: Python stdlib, perfil `cross-account-read` v1; não chama LLM.
- Contrato estrito validado em código; exemplo sintético versionado em `examples/carrasco/`.
- Duas contas próprias e dois objetos privados, confirmados pelo operador; URLs
  HTTPS no mesmo origin, sem query/fragmento/credenciais; somente GET de leitura.
- Headers/credenciais por ambiente; marcadores sintéticos distintos por objeto.
- Seis passos: controle A, controle B, acesso anônimo B, A→B, repetição A→B e
  leitura de volta B. Controles falhos interrompem antes do próximo estágio.
- Correspondência exata de campo JSON por JSON Pointer; status 200 sozinho é insuficiente.
- Bloqueio na falha do Mind, revisão de escopo divergente, 429/5xx ou orçamento.
- Transporte sem redirect, retry, proxy herdado ou cookie jar; leitura limitada em bytes.
- Journal privado e incremental, com tentativa gravada antes de emitir a requisição.
- Jobs locais: `submit`, `status`, `wait`; snapshot do plano e evidências referenciadas;
  um worker por job. Preparação na outbox ao terminar; `stage` permite recuperar entrega.
- Testes offline com clientes injetados e servidor em loopback; nenhuma caçada real
  foi executada para validar esta etapa.

Aceite: distinguir confirmação mecânica de leitura cruzada, refutação do caso,
inconclusivo e bloqueio; jamais confirmar pelo HTTP isolado, perder a separação de
sessões ou declarar publicação pela mera criação de uma nota.

## Etapa 2 — piloto integrado (próxima)

1. Homologar um programa/ambiente controlado via login real do launcher e Mind.
2. Preparar dois objetos privados com marcadores aleatórios e duas contas próprias.
3. Revisar permissões, automação, headers e limites; preencher a revisão aprovada.
4. Executar um cenário vulnerável e um protegido; confirmar journal, ingestão,
   fila idle e read-back. Registrar custos/tempo reais e lacunas de medição.
5. Revisar manualmente falsos positivos, compartilhamento legítimo e propriedade.

Aceite: tráfego e evidências auditáveis, testes reproduzíveis, publicação confirmada
e nenhuma credencial/conteúdo de resposta nos artefatos compartilhados.

## Etapa 3 — investigador e Atlas

- Adaptador versionado para referências de evidência do Mind e observações do
  Atlas; usar descoberta de capacidades em vez de assumir ferramentas disponíveis.
- Modelo recebe apenas evidência pertinente e gera **proposta** no contrato de
  plano; o executor valida os argumentos independentemente do modelo.
- Recuperar evidências citadas e preservar proveniência/versão; atualmente os
  `evidence_refs` são aliases declarados, não resolvidos nem verificados pelo worker.
- Pré-condições faltantes retornam pendência; respostas HTTP, memória e recomendações
  são dados não confiáveis e não alteram ferramentas, escopo ou política.
- Orçamentos de tokens, dinheiro e chamadas por hipótese; contabilizar uso real.
- Feedback revisado ao Atlas separado dos fatos do programa no Mind; não promover
  automaticamente um resultado a conhecimento transversal.

Aceite: hipótese escrita em linguagem natural + evidência suficiente produz um
plano revisável; plano incompleto não dispara tráfego; comparação com baseline
mede precisão, custo por candidato validado e testes repetidos evitados.

## Etapa 4 — novas capacidades

**Em andamento.** O executor agora tem um **registro de perfis**: cada perfil declara
schema, oráculos (passos/controles) e vereditos próprios, e `limits.requests` deve
bater com a contagem fixa do perfil. Perfis somente leitura (GET) implementados e
testados offline:

- `cross-account-read` (IDOR de leitura entre duas contas; 6 passos).
- `unauthenticated-read` (objeto privado próprio legível sem credencial; 4 passos:
  controle do dono → dois acessos anônimos → leitura de volta do dono).

Pendente nesta etapa:

- Novos perfis para papéis e fluxos com várias etapas, cada um com oráculos e
  testes próprios. Escrita exige política de efeitos, leitura de volta e limpeza
  (o transporte atual é GET-only; nenhum perfil de escrita existe ainda).
- Integração Burp após homologação dos contratos de captura/contexto; nenhuma
  expectativa de replay produtivo a partir da prova sintética atual.
- Fila com prioridades, leases, cancelamento e retomada; concorrência somente
  com limite global por programa e isolamento de contas/objetos.
- Política estruturada de automação, rate e headers no contrato Mind. Hoje o
  contexto tipado fornece escopo/revisão, mas não todos esses controles; o operador
  os revisa no plano. O executor não interpreta automaticamente regras em prosa.

## Limites atuais e operação

O worker testa um plano escrito/revisado, não raciocina autonomamente nem cria
contas/objetos. `confirmed` confirma o experimento, mantém revisão humana de
impacto/legitimidade, duplicidade e submissão pendente. A busca no Mind é limitada;
nenhum resultado de busca significa apenas ausência no pacote retornado.

O limite de tempo é verificado entre etapas e blocos de leitura. Operações
bloqueantes de DNS, MCP ou socket podem exceder o prazo até retornarem/expirarem;
não é um supervisor com prazo rígido. Processo encerrado pode deixar `queued` ou
`running`; `wait` tem timeout e não reenvia testes. Reinício de teste é uma nova
execução deliberada. Não há serviço permanente, scheduler ou cancelamento nesta versão.

Estado em `.hive/carrasco/` é scratch privado; fatos do programa continuam no Mind.
Arquivos versionados contêm somente código, testes e exemplos sintéticos. Execução
local não exige servidor Carrasco; publicação no GitHub exige commit/push deste repo.
