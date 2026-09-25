#!/usr/bin/env python3
"""saquear — orquestrador do `protocolo saquear navios` (mineração encadeada).

Um comando encadeia o pipeline de mineração e consolida tudo no Hive:
  1. passive.py  → agrega hosts de fontes 3rd-party + DIFF vs Hive (delta novo)
  2. jsrecon.py  → em cada SPA host autorizado: endpoints + STACK FINGERPRINT→playbook
  3. endpoints.py → mescla os endpoints achados no corpus canônico (dedupe + diff)
  4. imprime o "saque": hosts novos, endpoints novos, stacks/playbooks

Passos que ficam com o AGENTE (não automatizáveis aqui): hive_get_context/record-scope
(recibo), semear hipóteses no WAL, e captura de XHR autenticado via browser.

Requer recibo vigente p/ os hosts ativos (o scope_hook gateia na invocação Bash).
Uso:
  python3 tools/saquear.py toolsforhumanity \
     --domains worldcoin.org,world.org \
     --spa-hosts developer.world.org,coreapp.worldcoin.org \
     --data-dir /.../hive_instance/data --scratch /tmp/saque
"""
import argparse, json, os, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd, timeout=300):
    try:
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", cmd[0]), *cmd[1:]],
                           capture_output=True, text=True, timeout=timeout, cwd=ROOT)
        return r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return "", f"__timeout__ {cmd[0]}"
    except Exception as e:
        return "", f"__err__ {type(e).__name__}: {e}"

def parse_json(out):
    """Parseia o stdout --json de um sub-tool; devolve dict ou None (contrato robusto).

    Substitui o scraping frágil de headers de stdout: os sub-tools agora emitem
    JSON estruturado (passive/jsrecon --json).
    """
    try:
        return json.loads(out)
    except (json.JSONDecodeError, TypeError):
        return None


# --- extração do contrato JSON dos sub-tools (helpers puros, testáveis) ---
def new_hosts_from_passive(data):
    """delta_prod do passive --json (hosts PROD novos vs Hive)."""
    return list((data or {}).get("delta_prod") or [])


def endpoints_from_jsrecon(host, data):
    """linhas '<host> <path>' dos api_endpoints do jsrecon --json."""
    eps = [p for p in (data or {}).get("api_endpoints", []) if isinstance(p, str) and p.startswith("/")]
    return [f"{host} {p}" for p in eps]


def stacks_from_jsrecon(data):
    """lista de {name, playbook} dos fingerprints do jsrecon --json."""
    return [fp for fp in (data or {}).get("fingerprints", []) if isinstance(fp, dict) and fp.get("name")]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("program")
    ap.add_argument("--domains", default="", help="csv p/ passive (ex.: worldcoin.org,world.org)")
    ap.add_argument("--spa-hosts", default="", help="csv de SPA hosts p/ jsrecon ativo")
    ap.add_argument("--data-dir", default=os.environ.get("HIVE_DATA_DIR", ""))
    ap.add_argument("--scratch", default="",
                    help="dir de scratch (default: cria um tmp saque_*). Não é criado no --help.")
    ap.add_argument("--max-js", type=int, default=40)
    ap.add_argument("--rate", type=float, default=0.0,
                    help="máx req/s repassado ao jsrecon (alvos manual-only, ex.: NBA 3)")
    a = ap.parse_args()
    if not a.data_dir:
        ap.error("passe --data-dir ou defina HIVE_DATA_DIR")
    # cria o scratch só na execução real (antes era default de argparse → rodava
    # até no --help, deixando dirs tmp órfãos a cada invocação)
    a.scratch = a.scratch or tempfile.mkdtemp(prefix="saque_")
    os.makedirs(a.scratch, exist_ok=True)
    print(f"⛴️  SAQUEAR NAVIOS — {a.program}  (scratch: {a.scratch})\n")

    # 1) PASSIVE + diff vs Hive  (consome JSON estruturado)
    new_hosts = []
    if a.domains:
        doms = a.domains.split(",")
        out, err = run(["passive.py", *doms, "--diff-program", a.program,
                        "--data-dir", a.data_dir, "--json"], 300)
        data = parse_json(out)
        new_hosts = new_hosts_from_passive(data)
        deltafile = os.path.join(a.scratch, "_new_hosts.txt")
        open(deltafile, "w").write("\n".join(new_hosts) + "\n")
        print(f"═══ 1) PASSIVE ═══  {len(new_hosts)} host(s) PROD novo(s) vs Hive  (lista completa: {deltafile})")
        for h in new_hosts:
            print(f"   🆕 {h}")
        if data is None and err.strip():
            print(f"   (passive não retornou JSON — nota: {err.strip().splitlines()[-1][:80]})")

    # 2) JSRECON por SPA host  (endpoints + fingerprint via JSON)
    ep_lines = []
    if a.spa_hosts:
        print(f"\n═══ 2) JSRECON (SPA) ═══")
        for host in a.spa_hosts.split(","):
            host = host.strip()
            out, err = run(["jsrecon.py", f"https://{host}", "--max-js", str(a.max_js),
                            *(["--rate", str(a.rate)] if a.rate and a.rate > 0 else []),
                            "--json", "--save", os.path.join(a.scratch, host)], 240)
            data = parse_json(out)
            if data is None:
                print(f"   ● {host}: (jsrecon não retornou JSON) {err.strip().splitlines()[-1][:60] if err.strip() else ''}")
                continue
            host_eps = endpoints_from_jsrecon(host, data)
            fps = stacks_from_jsrecon(data)
            ep_lines.extend(host_eps)
            print(f"   ● {host}: {len(host_eps)} endpoints · stacks: "
                  + (", ".join(fp["name"] for fp in fps) or "—"))
            for fp in fps:
                print(f"       ● {fp['name']}\n       → {fp.get('playbook','')}")

    # 3) MERGE no corpus de endpoints (dedupe + diff)
    if ep_lines:
        epf = os.path.join(a.scratch, "_endpoints.txt")
        open(epf, "w").write("\n".join(sorted(set(ep_lines))) + "\n")
        out, err = run(["endpoints.py", "merge", a.program, "--input", epf,
                        "--source", "saquear", "--data-dir", a.data_dir], 60)
        print(f"\n═══ 3) CORPUS DE ENDPOINTS ═══\n   {err.strip() or out.strip()}")

    print(f"\n⚓ Saque pronto. Próximo (AGENTE): record-scope p/ hosts novos → hipóteses (code 6) "
          f"→ ingest_workspace + read-back. Bundles salvos em {a.scratch}")

if __name__ == "__main__":
    sys.exit(main())
