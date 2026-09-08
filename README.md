# Excalibull ⚔️🐂

Framework pessoal de bug bounty — a fusão do **Sword** (método de caçada + modos +
memória distilada, em português) com o **brain persistente + regras com enforcement** do
framework pentest-agents. Os alvos vivem num board canônico separado, o
**knowledge-targets**, e são sincronizados para cá sob demanda.

> ⚠️ **Escopo:** use apenas em alvos que você está **autorizado** a testar (programa de bug
> bounty / pentest com escopo definido). Na dúvida, pergunte antes de disparar.

---

## Índice

1. [O que é](#o-que-é)
2. [Instalação](#instalação)
3. [Fluxo de caçada](#fluxo-de-caçada)
4. [Comandos](#comandos)
   - [Códigos (`code N`)](#códigos-code-n)
   - [Protocolos (`protocolo <nome>`)](#protocolos-protocolo-nome)
   - [Modos (`modo <nome>`)](#modos-modo-nome)
5. [knowledge-targets — o board de alvos](#knowledge-targets--o-board-de-alvos)
6. [O brain persistente](#o-brain-persistente)
7. [Mapa de arquivos](#mapa-de-arquivos)
8. [Ambiente](#ambiente)

---

## O que é

Três camadas que trabalham juntas:

1. **O cérebro (`THE-MIND.md`)** — o método (6 perguntas universais), os princípios
   sempre-ativos (impacto-primeiro, regra do irmão, A→B, exaustão, never-submit, chain-walk),
   o roteador de comandos, e a descrição do brain persistente. **Leia primeiro.**
2. **Os comandos (`CODES.md`)** — `code N` (ações rápidas), `protocolo <nome>` (fluxos),
   `modo <nome>` (posturas ligadas: hunter, escudo, dojo, lança, tridente…).
3. **O enforcement (`.claude/settings.json` + `tools/`)** — hooks Python que garantem
   escopo, never-submit, versão CVSS, arquivos citados, e o Selo de saída.

E dois bancos de dados:
- **`memory/`** — conhecimento distilado, transversal a alvos (patterns P1–P8, arsenal,
  signals, sources).
- **`brain/`** — estado persistente por alvo (o que já foi testado/exaurido, capacidades,
  endpoints, sessões), gerido por `tools/brain.py`.

---

## Instalação

```bash
cd ~/projetos/pessoal/excalibull
bash setup.sh                      # detecta o SO e instala Go + toolchain de recon
python3 tools/brain.py init        # inicializa o brain persistente
python3 tools/brain.py status
```

`setup.sh` é **multi-OS**: detecta macOS (Homebrew) ou Linux (apt/dnf/pacman/zypper/apk),
instala Go e, via `go install`, o toolchain: `subfinder httpx katana nuclei dnsx gau
waybackurls amass gospider gf ffuf`. Também instala as deps Python (`requests`, `pyyaml`,
`curl_cffi` opcional) e os gf-patterns em `~/.gf`.

Requisitos mínimos sem o toolchain: `python3` + `pip install requests` (as ferramentas de
recon em Python puro caem para fallback quando um binário falta).

---

## Fluxo de caçada

```
portfolio.md            escolher o programa (alimentado pelo "modo sábado à tarde")
    │
    ▼
code 7 find <alvo>      puxa a ficha do alvo do knowledge-targets → targets/<alvo>/
    │
    ▼
modo hunter on          carrega THE-MIND + rules/ + memory/ + brain brief (code 8)
    │
    ▼
6 perguntas do The Mind  por feature/endpoint  →  triagem cética (5 perguntas)
    │
    ▼
protocolo contra-prova   mata falso positivo (cruza com rules/never-submit.md)
    │
    ▼
protocolo escada de jacó escala o achado real até o teto
    │
    ▼
protocolo report         rascunho (hooks validam CVSS/arquivos/never-submit); humano submete
    │
    ▼
modo hunter off          Selo de saída (seal_gate.py precisa passar) + brain grava tudo
    │
    ▼
code 7 send <alvo>       devolve o estado atualizado pro knowledge-targets
```

---

## Comandos

Definição completa em **`CODES.md`**. Resumo:

### Códigos (`code N`)

| Código | Nome | Resumo |
|--------|------|--------|
| `code 0 <alvo>` | Recon completo | recon + probe + crawl + gf + scan CORS/headers → ficha |
| `code 1 <alvo>` | Recon passivo | só enumeração passiva, sem tocar no alvo |
| `code 2 <url>` | Scan alvo único | audita CORS/headers de uma URL |
| `code 3 <alvo>` | Nova ficha | cria `targets/<alvo>/` no formato do knowledge-targets |
| `code 4 "<decisão>"` | Registrar decisão | adiciona bloco no `THE-MIND.md` |
| `code 5 <vuln> [alvo]` | Dupcheck | checa se a vuln já foi reportada (local + hacktivity) |
| `code 6 <alvo>` | Gerar hipóteses | casa o recon contra `memory/signals.md` + `rules/chain-table.md` → leads `[UNTESTED]` |
| **`code 7 send <alvo>`** | **Sync → board** | envia `targets/<alvo>/` → `knowledge-targets/<plataforma>/<slug>/` |
| **`code 7 find <alvo>`** | **Sync ← board** | busca `knowledge-targets/<plataforma>/<slug>/` → `targets/<alvo>/` |
| **`code 7`** | **Diff board** | lista/diffa o que existe no board vs em `targets/` |
| `code 8 <alvo>` | Brain brief | pre-flight do brain: o que já foi testado/exaurido |
| `code 9` | Brain status | visão geral do brain (alvos, exaustos, findings) |
| `code 10 <report> <status>` | Learn | registra o desfecho de uma submissão no brain (EV futuro) |
| `code 11 <draft>` | Quality | pontua um rascunho de report antes de submeter |

### Protocolos (`protocolo <nome>`)

| Protocolo | Objetivo |
|-----------|----------|
| `casa-nova` | Pacote do coletor web → ficha de alvo |
| `contra-prova` | Dupla verificação pessimista — matar falso positivo (5 perguntas + never-submit) |
| `report` | Rascunhar report de achado confirmado + checklist de submissão |
| `ladrão de bancos` | Escolher alvo → recon em 3 níveis (passivo→médio→completo) → sintetizar |
| `One Piece` | Caçada com **uma conta só** (self-state, tampering, race, escopo, step-skip) |
| `armar a arapuca` | Inventário vivo de achados fracos + passo de combinação → chain |
| `monitor` | Vigília ligável de um alvo: baseline + checagens de mudança (feature nova = alvo fresco) |
| `descobrir a roda` | Reconstruir o sistema a partir das peças → mapa do não-testado → cadeias |
| `escada de jacó` | Subir um `[ACHADO]` confirmado degrau a degrau até o pior caso (antes do report) |

### Modos (`modo <nome>`)

| Modo | Postura |
|------|---------|
| `modo hunter` | Caçador sênior: 6 perguntas → triagem → escala → tenacidade → Selo de saída |
| `postura escudo` | Stealth: só o silencioso (não dispara flag); vitrine `[REQUER AUTORIZAÇÃO]` |
| `formação de lança` | Execução ativa assistida (dentro do hunter; incompatível com o escudo) |
| `formação tridente` | Teste diferencial em 3 engines (Blink/Gecko/WebKit) — compatível com o escudo |
| `seguir o rastro` | Tenacidade dirigida: ramificar em profundidade a partir de um sinal |
| `modo dojo` | Treino: write-up → conhecimento retido (recall + aplicação + espaçamento) |
| `modo sábado à tarde` | Curadoria do `portfolio.md` (garimpa e rankeia programas) |
| `modo bicicleta` | O cérebro como copiloto explícito (sugere o próximo comando) |

---

## knowledge-targets — o board de alvos

Os alvos **não** moram no excalibull — vivem no board canônico
`~/projetos/pessoal/knowledge-targets/` (repositório separado, versionado, organizado por
plataforma: `hackerone/<slug>/`, `bugcrowd/`, `intigriti/`, `outros/`). Cada alvo tem
`README.md` (ficha), `target.yml` (metadados + score), `scope.md`, `recon/`, `findings/`,
`assets/`. O board gera um `RANKING.md` por score composto.

`excalibull/targets/` é uma **cópia de trabalho**: vazia por padrão. Você traz um alvo pra
cá pra caçar e devolve quando termina:

```bash
python3 tools/kb_sync.py find coinspot   #  code 7 find — puxa do board pra targets/
# ... caça ...
python3 tools/kb_sync.py send coinspot   #  code 7 send — devolve pro board + regenera ranking
python3 tools/kb_sync.py                 #  code 7 (sem arg) — diffa board vs targets/
```

O caminho do board é resolvido por `KNOWLEDGE_TARGETS_DIR` (default `../knowledge-targets`).
A estrutura de `targets/<alvo>/` espelha a do board, então o sync é uma cópia direta em
ambos os sentidos.

---

## O brain persistente

`tools/brain.py` mantém o estado da caçada em `brain/` (local; gitignored exceto o índice
`MEMORY.md`). Ele evita re-testar o que já foi exaurido e lembra as capacidades obtidas.

```bash
python3 tools/brain.py init                 # inicializa
python3 tools/brain.py brief <alvo>         # pre-flight (code 8): o que já rolou
python3 tools/brain.py status               # visão geral (code 9)
python3 tools/brain.py record <alvo> <status> "<técnica>" "<detalhe>"
python3 tools/brain.py endpoint <alvo> /api/x tested --vuln-class idor
python3 tools/brain.py capability <alvo> "<capacidade>" --from-capability "<origem>"
python3 tools/brain.py exhausted <alvo>     # vetores mortos
```

O `modo hunter` grava no brain automaticamente durante o loop; o **Selo de saída**
(`modo hunter off`) só fecha quando `tools/seal_gate.py` confirma que ficha + log + brain
estão atualizados.

---

## Mapa de arquivos

| Arquivo/pasta | Papel |
|---|---|
| `THE-MIND.md` | O cérebro — ler primeiro. Método + princípios + roteador + brain + log. |
| `CODES.md` | Todos os comandos (`code`/`protocolo`/`modo`). |
| `CLAUDE.md` | Regras operacionais do projeto (para o agente). |
| `portfolio.md` | Funil de programas rankeados. |
| `rules/` | Regras de referência: never-submit, chain-table, identities, mistakes, techniques, waf-bypass, vendor-fingerprints, payloads. |
| `memory/` | Conhecimento distilado (patterns P1–P8, arsenal, signals, sources). |
| `brain/` | Estado persistente por alvo (`brain.py`; local, gitignored exceto `MEMORY.md`). |
| `targets/<alvo>/` | Cópia de trabalho de um alvo (sincronizada com o board via `code 7`). |
| `tools/` | brain, kb_sync (code 7), guards de enforcement, recon, cors/headers scan, resolve DoH. |
| `.claude/settings.json` | Hooks de enforcement (escopo, never-submit, CVSS, arquivos, Selo). |

---

## Ambiente

Linux ou macOS nativo (rede + git ok). `python3` (não `uv`). `pip install requests pyyaml`.
Toolchain de recon via `bash setup.sh`. O board `knowledge-targets` é um repo git separado,
sibling do excalibull em `~/projetos/pessoal/`.
