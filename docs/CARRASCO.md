# Carrasco e protocolo execução pública

Executor local no mesmo repositório da Excalibull. O protocolo entrega uma hipótese
e evidências para um worker em segundo plano e aguarda sua conclusão. Código e
exemplos são versionados; planos reais, credenciais e journals ficam fora do Git.

## Perfis disponíveis

Cada perfil é um oráculo próprio: define o schema do plano, a sequência de passos
(controles, teste e leitura de volta) e os vereditos. `cross-account-read` e
`unauthenticated-read` são **somente leitura (GET)**; `cross-account-write` escreve
(PATCH/PUT) sob regras adicionais.

| Perfil | Hipótese testada | Objetos/contas | Requests | Exemplo |
|---|---|---|---|---|
| `cross-account-read` | A sessão A lê o objeto privado da conta B (IDOR de leitura) | 2 contas próprias, 2 objetos | 6 | `examples/carrasco/cross-account-read.json` |
| `unauthenticated-read` | Objeto privado legível sem credencial alguma (autenticação ausente) | 1 conta própria, 1 objeto | 4 | `examples/carrasco/unauthenticated-read.json` |
| `cross-account-write` | A sessão A altera o objeto privado da conta B (IDOR de escrita) | 2 contas próprias, 1 objeto | 5 | `examples/carrasco/cross-account-write.json` |

O campo `profile` do plano escolhe o oráculo; `limits.requests` deve bater com a
contagem fixa do perfil.

### Perfil de escrita (`cross-account-write`)

A escrita cruza uma fronteira de risco, então exige três coisas, todas verificadas:

- **Política de efeitos** (`policy.effects`): declaração revisada de que a escrita é
  reversível, idempotente, só em objetos próprios e sem dados de terceiros. Sem ela,
  o plano não valida.
- **Corpos autorados** (`write.body`, `cleanup.body`): JSON sintético **que você
  escreve e revisa**. O worker valida que cada corpo posiciona exatamente o marcador
  esperado no JSON Pointer e envia **apenas isso** — nunca inventa o corpo. Método
  restrito a `PATCH`/`PUT`.
- **Limpeza obrigatória**: depois do teste, o **dono** reescreve o objeto de volta ao
  marcador original e o worker **verifica** a restauração. A limpeza roda mesmo se o
  ataque for bloqueado no meio (429/5xx/escopo) e está fora do orçamento de ataque.
  Se a restauração não puder ser confirmada, o resultado é `failed` com
  `manual_restoration_required: true` — **você precisa restaurar o objeto à mão**.

Sequência (5 passos): controle do dono → escrita do atacante → leitura de volta do
dono → **limpeza do dono** → **verificação**. Limitação conhecida: o contexto do Mind
autoriza escopo **por URL**, não por método; permissão de escrita no ativo é coberta
pela sua política de efeitos e pela revisão das regras do programa, não inferida pelo
worker.

## Preparar o experimento

1. Ative hunter com postura de lança conforme CODES; escolha o programa no Mind,
   consulte histórico/regras e obtenha a revisão aprovada para os ativos exatos.
2. Crie os objetos privados em contas próprias (dois objetos/duas contas para
   `cross-account-read`; um objeto/uma conta para `unauthenticated-read`), sem
   compartilhamento. Coloque em cada objeto um marcador diferente, `carrasco-` +
   pelo menos 16 caracteres aleatórios. Confirme propriedade e privacidade; o bot
   não cria os objetos.
3. Copie o exemplo do perfil escolhido para `.hive/carrasco-plan.json`.
   Preencha programa, hipótese, referências/aliases de evidências, URL(s) do(s)
   objeto(s), revisão aprovada, limites e JSON Pointer do campo com o marcador.
   O exemplo usa `/content`, isto é, o campo `content` do JSON.
4. Revise `policy`: as flags são declaração do operador sobre contas, privacidade
   e regras de automação. Não são autorização de escopo; esta vem do Mind ao vivo.
   Se manual-only ou automação proibida, não execute este perfil. Respeite o menor
   limite do programa, mesmo que o validador permita rate maior.
5. Configure `HIVE_HANDLE`, `HIVE_TEAM_TAG` e faça `hive login`/`hive doctor`.
   Configure as credenciais como objetos JSON de headers no ambiente privado, por
   exemplo `Authorization` ou `Cookie`, com valores de sessões distintas. Por perfil:
   `cross-account-read` usa `CARRASCO_ACCOUNT_A` e `CARRASCO_ACCOUNT_B`;
   `unauthenticated-read` usa só a do dono (`CARRASCO_ACCOUNT_A`) e os passos anônimos
   não recebem credencial; `cross-account-write` usa a do atacante (`CARRASCO_ACCOUNT_A`)
   e a do dono (`CARRASCO_ACCOUNT_B`, que faz controle, leitura de volta e limpeza).
   `CARRASCO_REQUIRED_HEADERS` contém apenas headers comuns de
   identificação exigidos pelo programa, sem credenciais. Não os coloque no plano,
   no chat, no Git ou em comandos que os imprimam. O worker herda o ambiente.

As referências de evidência são aliases, por exemplo `owner-b-control`, ligados
a notas/capturas conhecidas pelo operador; o MVP não busca os documentos por alias.
O plano contém as URLs e as asserções necessárias para executar os controles ao vivo.
Não declarar uma evidência ausente como pré-condição verificada.

## Entregar em segundo plano e esperar

```sh
python3 tools/carrasco.py validate .hive/carrasco-plan.json
python3 tools/carrasco.py submit .hive/carrasco-plan.json
```

`validate` verifica o formato sem Hive/tráfego. `submit` verifica a configuração
local e retorna um `job_id`; a autorização remota será checada pelo worker.
Use o ID retornado (substitua `<job_id>`):

```sh
python3 tools/carrasco.py status <job_id>
python3 tools/carrasco.py wait <job_id> --seconds 30
```

O agente chama `wait` em intervalos de até 30 segundos, comunica progresso e
continua aguardando o mesmo ID. `wait`/`status` nunca emitem requisições ao alvo.
Timeout significa execução pendente, não conclusão nem licença para repetir.
`finished` sinaliza resultado terminal e tentativa de staging encerrada; não
comprova ingestão. `progress` mostra tentativas, respostas recebidas, limite e
último passo; `cleanup`/`manual_restoration_required` mostram restauração pendente,
inclusive enquanto o processo executa. O `run_id` permanece o mesmo do envio ao
resultado. Se o processo morrer com `running`, `status`/`wait` mostram
`worker: "dead"` e `stale: true` (saída 2) e `wait` retorna imediatamente em vez
de esgotar o timeout. Preservar journal e inspecionar `worker.log`; não reiniciar
o experimento automaticamente. `worker` também pode ser `alive`, `exited` ou
`unknown` (sem `job.json`).

```sh
python3 tools/carrasco.py cancel <job_id>
python3 tools/carrasco.py jobs
```

`cancel` é cooperativo: grava um sinal que o worker consulta antes de cada passo de
ataque e o resultado vira `blocked` com `reason: cancelled_by_operator`. No
`cross-account-write`, se a escrita já foi tentada, **a limpeza obrigatória e a
verificação ainda rodam** (`attack_status: interrupted`). `cancel` não mata o
processo nem apaga o journal. `jobs` lista os jobs locais do mais recente ao mais
antigo, sem URLs, marcadores ou credenciais.

Para execução em primeiro plano:

```sh
python3 tools/carrasco.py run .hive/carrasco-plan.json
```

## Resultado e publicação

| Estado | Interpretação |
|---|---|
| `confirmed` | Leitura: marcador privado lido duas vezes pelo ator não autorizado (A ou anônimo), com controles válidos. Escrita: GET 200 do dono comprova o marcador alterado, mesmo se a resposta de escrita alegar negação. Sempre exige revisão humana |
| `refuted` | Leitura cruzada: 403/404; leitura anônima: 401/403/404. Escrita: 403/404 e GET 200 do dono com o marcador original comprovado. Não esgota a classe nem outros fluxos |
| `inconclusive` | Controle, conteúdo, transporte ou repetição insuficientes |
| `blocked` | Mind/escopo/revisão/limite/429/5xx impediram continuar |
| `failed` | Pré-condição local, worker ou armazenamento falhou — **ou a limpeza do `cross-account-write` não foi confirmada** (`manual_restoration_required: true`: restaure o objeto à mão) |

`result.json` conserva aliases, status, hash/tamanho da resposta, correspondência
do marcador e revisão de escopo. Não conserva corpo, cookies ou headers. O plano
privado preserva a receita; o hash do plano vincula o journal a ela. A propriedade
real das contas e a ausência de compartilhamento são pré-condições revisadas pelo
operador, não inferidas somente das respostas.
401 nas tentativas cruzadas é inconclusivo, pois pode indicar expiração da sessão.
Mesmo um 403/404 vale somente nas condições observadas; o piloto não verifica
novamente a sessão A no final e não comprova que toda a classe está protegida.

Na escrita, ausência do marcador alterado não comprova integridade: campo ausente,
conteúdo inesperado ou leitura de volta sem 200 são inconclusivos. A obrigação de
restaurar fica registrada antes do envio, pois um timeout pode ocorrer depois do
efeito no servidor. Bloqueio antes de tentar enviar a escrita não dispara limpeza.
Redirect da limpeza é rejeitado; restauração continua sujeita ao Mind vigente.
A verificação confirma o campo do marcador, não a equivalência integral do objeto.
O journal parcial e os alertas de restauração sobrevivem a erros do worker.

O worker prepara positivos e negativos na outbox existente. `publication=staged`
significa preparação local. Revise o candidato com `contra prova`, publique e
confirme pelo fluxo oficial:

```sh
python3 tools/hive_outbox.py publish <program_id>
python3 tools/seal_gate.py <program_id>
```

`publish` depende das permissões de ingestão do membro, espera a fila e verifica
read-back conforme o contrato existente. O journal do Carrasco não muda sozinho
de staged para published: a confirmação oficial permanece na outbox/Selo.
Se preparar a nota falhar, o resultado continua em disco com publicação pendente:

```sh
python3 tools/carrasco.py stage .hive/carrasco-plan.json .hive/carrasco/jobs/<job_id>/result.json
```

Use o snapshot `plan.json` do job se o plano original mudou. `stage` confere seu
hash e não repete tráfego; a outbox reutiliza conteúdo idêntico. HTTP 200, exemplo
validado ou teste offline não comprovam um achado em um programa real.

## Códigos de saída

`validate`/`submit`/`stage`/`jobs`: 0 em sucesso, 2 em erro. `run`: 0 para confirmed/refuted,
1 para blocked/inconclusive/failed com nota preparada, 2 para erro ou publicação
pendente. `wait`/`status`/`cancel`: 0 para terminal, 1 para pendente, 2 para erro ou
worker morto. Falha ao gravar o journal durante a limpeza vira `failed` com
`cleanup_journal_failed` (a limpeza não é enviada sem registro prévio). Sempre
interprete também o JSON: saída 0 não implica achado ou publicação remota.

Plano de evolução: [PLANO-CARRASCO.md](PLANO-CARRASCO.md).
