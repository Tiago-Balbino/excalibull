# Excalibull — operação de caçada (bug bounty)

Projeto de caçada real: encontrar, provar e reportar vulnerabilidades em programas
autorizados. Nasceu da fusão do **Sword** (método + modos + memória em prosa) com o
**brain persistente + regras com enforcement** do framework pentest-agents.

## Regra do cérebro
`THE-MIND.md` é o **cérebro** do projeto: método (6 perguntas) + princípios sempre-ativos
+ roteamento (qual comando, quando) + o brain persistente + log de decisões.
**Antes de qualquer caçada, leia-o** — tudo passa por ele.

## Arquivos-chave (leia sempre)
- `THE-MIND.md` — o cérebro (ler primeiro ao caçar).
- `CODES.md` — comandos, em 3 tipos: `code N` (ação rápida), `protocolo <nome>` (fluxo) e
  `modo <nome>` (postura ligada). Execute o que está definido lá.
- `rules/` — **regras de referência sempre-disponíveis** (nomes em inglês, conteúdo em PT):
  `never-submit.md`, `chain-table.md`, `identities.md`, `mistakes.md`, `techniques.md`,
  `waf-bypass.md`, `vendor-fingerprints.md`, `payloads.md`. O `modo hunter` carrega as
  relevantes. Índice em `rules/README.md`.
- `memory/` — banco de conhecimento distilado: `patterns.md` (P1–P8), `arsenal.md`
  (como testar por classe), `signals.md` (índice de gatilhos). Carregue no início de toda
  caçada; alimente ao aprender algo novo.
- `brain/` — o **brain persistente** gerido por `tools/brain.py`: o que já foi testado,
  exaurido, quais capacidades foram obtidas, endpoints, sessões. Estado local (gitignored,
  exceto `MEMORY.md`). Consulte com `code 7`/`code 8`; ele grava sozinho durante o hunter.
- `portfolio.md` — programas candidatos rankeados (escopo × reward). Porta de entrada do
  `modo hunter`.
- `targets/<dominio>/` — ficha do alvo + saídas de recon + escopo.
- `README.md` — visão geral e quick start.

## Prioridades
1. Broken Access Control / IDOR (máxima)
2. Lógica de negócio (máxima)
3. Recon & low-hanging fruit (headers/CORS, takeover, secrets)
4. Injeção · auth/sessão · SSRF/XXE/upload — conforme a superfície.

## Regra de escopo (inegociável)
Só recon/scan/PoC em alvos **autorizados** por programa com escopo definido. Na dúvida,
pergunte antes de disparar. O hook `tools/scope_hook.py` bloqueia comandos contra hosts
fora do escopo (`targets/<alvo>/scope.txt` / `scope.yaml` / `.scope.txt`).

## Enforcement (hooks em `.claude/settings.json`)
As regras não são só texto — hooks Python as garantem:
- **PreToolUse Bash** → bloqueio de escopo.
- **PreToolUse Write/Edit** → guarda de arquivo inexistente em report, guarda de versão
  CVSS por plataforma, guarda de never-submit em drafts.
- **Selo de saída** do `modo hunter` respaldado por `tools/seal_gate.py`.

## Segurança / higiene
- Nunca hardcodar usuário, e-mail, senha, token, cookie ou TOTP de plataforma. Use os
  símbolos de env-var de `rules/identities.md` (ex.: `$HACKERONE_EMAIL_ALIAS`).
- Não commitar recon cru, PoCs, screenshots, relatórios ou dado real de alvo.
- Operações destrutivas de filesystem/git só quando o Tiago pedir explicitamente.

## Ambiente
Linux nativo (rede + git ok). `python3` (não `uv`). `pip install requests` para as
ferramentas de recon. `bash setup.sh` instala o toolchain de recon (subfinder/httpx/etc.).
