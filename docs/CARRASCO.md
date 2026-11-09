# Carrasco e protocolo execução pública

Executor local no mesmo repositório da Excalibull. O protocolo entrega uma hipótese
e evidências para um worker em segundo plano e aguarda sua conclusão. Código e
exemplos são versionados; planos reais, credenciais e journals ficam fora do Git.

## Preparar o experimento

1. Ative hunter com postura de lança conforme CODES; escolha o programa no Mind,
   consulte histórico/regras e obtenha a revisão aprovada para os ativos exatos.
2. Crie dois objetos privados em contas próprias, sem compartilhamento entre elas.
   Coloque em cada objeto um marcador diferente, `carrasco-` + pelo menos 16 caracteres
   aleatórios. Confirme propriedade e privacidade; o bot não cria os objetos.
3. Copie `examples/carrasco/cross-account-read.json` para `.hive/carrasco-plan.json`.
   Preencha programa, hipótese, referências/aliases de evidências, URLs dos dois
   objetos, revisão aprovada, limites e JSON Pointer do campo com o marcador.
   O exemplo usa `/content`, isto é, o campo `content` do JSON.
4. Revise `policy`: as flags são declaração do operador sobre contas, privacidade
   e regras de automação. Não são autorização de escopo; esta vem do Mind ao vivo.
   Se manual-only ou automação proibida, não execute este perfil. Respeite o menor
   limite do programa, mesmo que o validador permita rate maior.
5. Configure `HIVE_HANDLE`, `HIVE_TEAM_TAG` e faça `hive login`/`hive doctor`.
   Configure `CARRASCO_ACCOUNT_A` e `CARRASCO_ACCOUNT_B` como objetos JSON de headers
   no ambiente privado, por exemplo `Authorization` ou `Cookie`, com valores das
   sessões distintas. `CARRASCO_REQUIRED_HEADERS` contém apenas headers comuns de
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
comprova ingestão. Se o processo morrer com `running`, preservar journal e
inspecionar `worker.log`; não reiniciar o experimento automaticamente.

Para execução em primeiro plano:

```sh
python3 tools/carrasco.py run .hive/carrasco-plan.json
```

## Resultado e publicação

| Estado | Interpretação |
|---|---|
| `confirmed` | Marcador privado de B lido duas vezes por A, com controles e leitura de volta válidos; candidato exige revisão humana |
| `refuted` | Duas tentativas cruzadas negadas com 403/404; não esgota a classe nem outros fluxos |
| `inconclusive` | Controle, conteúdo, transporte ou repetição insuficientes |
| `blocked` | Mind/escopo/revisão/limite/429/5xx impediram continuar |
| `failed` | Pré-condição local, worker ou armazenamento falhou |

`result.json` conserva aliases, status, hash/tamanho da resposta, correspondência
do marcador e revisão de escopo. Não conserva corpo, cookies ou headers. O plano
privado preserva a receita; o hash do plano vincula o journal a ela. A propriedade
real das contas e a ausência de compartilhamento são pré-condições revisadas pelo
operador, não inferidas somente das respostas.
401 nas tentativas cruzadas é inconclusivo, pois pode indicar expiração da sessão.
Mesmo um 403/404 vale somente nas condições observadas; o piloto não verifica
novamente a sessão A no final e não comprova que toda a classe está protegida.

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

`validate`/`submit`/`stage`: 0 em sucesso, 2 em erro. `run`: 0 para confirmed/refuted,
1 para blocked/inconclusive/failed com nota preparada, 2 para erro ou publicação
pendente. `wait`/`status`: 0 para terminal, 1 para pendente, 2 para erro. Sempre
interprete também o JSON: saída 0 não implica achado ou publicação remota.

Plano de evolução: [PLANO-CARRASCO.md](PLANO-CARRASCO.md).
