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
import argparse, os, re, subprocess, sys, tempfile

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

def section(text, header, stop=("=====", "[*]")):
    """extrai as linhas de uma seção '===== HEADER ...' até o próximo marcador."""
    out, on = [], False
    for line in text.splitlines():
        if on and any(line.strip().startswith(s) for s in stop):
            break
        if on and line.strip():
            out.append(line.strip())
        if header in line:
            on = True
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("program")
    ap.add_argument("--domains", default="", help="csv p/ passive (ex.: worldcoin.org,world.org)")
    ap.add_argument("--spa-hosts", default="", help="csv de SPA hosts p/ jsrecon ativo")
    ap.add_argument("--data-dir", default=os.environ.get("HIVE_DATA_DIR", ""))
    ap.add_argument("--scratch", default=tempfile.mkdtemp(prefix="saque_"))
    ap.add_argument("--max-js", type=int, default=40)
    a = ap.parse_args()
    if not a.data_dir:
        ap.error("passe --data-dir ou defina HIVE_DATA_DIR")
    os.makedirs(a.scratch, exist_ok=True)
    print(f"⛴️  SAQUEAR NAVIOS — {a.program}  (scratch: {a.scratch})\n")

    # 1) PASSIVE + diff vs Hive
    new_hosts = []
    if a.domains:
        doms = a.domains.split(",")
        out, err = run(["passive.py", *doms, "--diff-program", a.program, "--data-dir", a.data_dir], 300)
        new_hosts = [h for h in section(out, "PROD novo no Hive") if re.match(r'^[a-z0-9.\-]+$', h)]
        print(f"═══ 1) PASSIVE ═══  {len(new_hosts)} host(s) PROD novo(s) vs Hive")
        for h in new_hosts[:40]:
            print(f"   🆕 {h}")
        if err.strip():
            print(f"   (notas: {err.strip().splitlines()[-1][:80]})")

    # 2) JSRECON por SPA host  (endpoints + fingerprint)
    ep_lines = []
    if a.spa_hosts:
        print(f"\n═══ 2) JSRECON (SPA) ═══")
        for host in a.spa_hosts.split(","):
            host = host.strip()
            out, err = run(["jsrecon.py", f"https://{host}", "--max-js", str(a.max_js),
                            "--save", os.path.join(a.scratch, host)], 240)
            eps = section(out, "API ENDPOINTS")
            fps = section(out, "STACK FINGERPRINT")
            for p in eps:
                if p.startswith("/"):
                    ep_lines.append(f"{host} {p}")
            print(f"   ● {host}: {len(eps)} endpoints · stacks: "
                  + (", ".join(f.lstrip('● ').split(' ')[0] for f in fps if f.startswith('●')) or "—"))
            for f in fps:
                if f.startswith("●") or f.startswith("→"):
                    print(f"       {f}")

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
