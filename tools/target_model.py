#!/usr/bin/env python3
"""target_model.py — Modelo de Alvo do Excalibull (operacionaliza `descobrir a roda`).

Reconstrói a ESTRUTURA do alvo a partir das peças de recon (auto-import do --json de
jsrecon/passive + fatos curados pelo agente) e a usa p/ ENUMERAR ataques contra o alvo
REAL — hipóteses rankeadas que alimentam hypotheses.py e semeiam matrizes de exaustão.
Simula MECANISMOS (jwt/oauth/hmac/state via mechanisms.py) e APRENDE sozinho dos
vereditos (pesos por classe/tech). NÃO faz tráfego: é análise/estado; o disparo é do
agente/humano sob o gate de recibo.

Estado: brain/model/<slug>.json (WAL, atômico+locked). Rebuildável.

Uso (resumo):
  target_model.py init <program>
  target_model.py import-jsrecon <program> <json|->      # endpoints/hosts/fingerprints
  target_model.py import-passive <program> <json|->      # hosts
  target_model.py add-object <program> --name pedido --owned-by user --id-format seq --endpoint /api/orders
  target_model.py add-auth   <program> --kind oauth --spec flow=code,redirect_uri_validation=prefix
  target_model.py add-boundary <program> --to /admin --control authz
  target_model.py enumerate  <program> [--class idor] [--seed-matrix] [--json]
  target_model.py untested   <program>
  target_model.py simulate   <program> <jwt|oauth|hmac|state>
  target_model.py record-verdict <program> <lead> <achado|fp|padrao|inconclusivo>
  target_model.py show       <program> [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from brain import get_brain_dir, slugify, load_capability_graph  # noqa: E402
from file_safety import atomic_write_text, load_json_or_quarantine, locked_file  # noqa: E402
import mechanisms  # noqa: E402

SCHEMA_VERSION = 1

# Prioridade base por classe (§10: BAC/IDOR/lógica primeiro; redirect/headers por último).
_CLS_PRIO = {"idor": 1, "bac": 1, "logic": 1, "auth": 1, "jwt": 1, "oauth": 1,
             "graphql": 2, "hmac": 2, "state": 2, "ssrf": 2, "redirect": 3, "xss": 3,
             "headers": 5}
_VALUE_PARAMS = re.compile(r"(price|amount|qty|quantity|discount|coupon|balance|role|isadmin|plan|tier|refund)", re.I)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _state_path(program: str) -> Path:
    return get_brain_dir() / "model" / f"{slugify(program)}.json"


def _empty(program: str) -> dict:
    return {"schema_version": SCHEMA_VERSION, "program": program, "components": {},
            "auth_flows": [], "roles": [], "objects": [], "boundaries": [],
            "fingerprints": [], "verdicts": [], "weights": {}}


def load(program: str) -> dict:
    st = load_json_or_quarantine(_state_path(program), lambda: _empty(program))
    for k, v in _empty(program).items():
        st.setdefault(k, v)
    return st


def save(program: str, state: dict) -> None:
    atomic_write_text(_state_path(program), json.dumps(state, ensure_ascii=False, indent=2))


def _read_json_arg(arg: str) -> dict:
    if arg == "-":
        return json.loads(sys.stdin.read())
    return json.loads(Path(arg).read_text(encoding="utf-8"))


# ------------------------------------------------------------------ imports
def import_jsrecon(program: str, data: dict) -> dict:
    with locked_file(_state_path(program)):
        st = load(program)
        for path in data.get("api_endpoints", []):
            cid = f"ep:{path}"
            st["components"].setdefault(cid, {"kind": "endpoint", "value": path,
                                              "methods": [], "params": [], "tech": [], "source": "jsrecon"})
        for op in data.get("graphql_ops", []):
            cid = f"gql:{op}"
            st["components"].setdefault(cid, {"kind": "endpoint", "value": f"graphql:{op}",
                                              "methods": ["POST"], "params": [], "tech": ["graphql"], "source": "jsrecon"})
        for host in data.get("hosts", []):
            st["components"].setdefault(f"host:{host}", {"kind": "host", "value": host,
                                                         "methods": [], "params": [], "tech": [], "source": "jsrecon"})
        names = {f["name"] for f in st["fingerprints"]}
        for fp in data.get("fingerprints", []):
            if isinstance(fp, dict) and fp.get("name") not in names:
                st["fingerprints"].append({"name": fp["name"], "playbook": fp.get("playbook", "")})
                names.add(fp["name"])
        save(program, st)
        return st


def import_passive(program: str, data: dict) -> dict:
    hosts = list(data.get("prod") or []) + list(data.get("delta_prod") or [])
    with locked_file(_state_path(program)):
        st = load(program)
        for host in hosts:
            st["components"].setdefault(f"host:{host}", {"kind": "host", "value": host,
                                                        "methods": [], "params": [], "tech": [], "source": "passive"})
        save(program, st)
        return st


def _parse_spec(kv: str) -> dict:
    """'flow=code,redirect_uri_validation=prefix' → dict (valores bool/int inferidos)."""
    spec = {}
    for part in (kv or "").split(","):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k, v = k.strip(), v.strip()
        if v.lower() in ("true", "false"):
            spec[k] = v.lower() == "true"
        elif v.isdigit():
            spec[k] = int(v)
        elif ";" in v:
            spec[k] = [x.strip() for x in v.split(";") if x.strip()]
        else:
            spec[k] = v
    return spec


# ------------------------------------------------------------- Attack catalog
class AttackCatalog:
    """Interface plugável. Backend local agora; futuro: ferramenta de padrões no MCP do Hive."""
    def primitives(self, unit_kind: str, ctx: dict) -> list[dict]:
        raise NotImplementedError


class LocalAttackCatalog(AttackCatalog):
    """Mapeia (unit, contexto) → primitivas, do conhecimento de signals/arsenal/chain-table."""

    def primitives(self, unit_kind: str, ctx: dict) -> list[dict]:
        out: list[dict] = []
        if unit_kind == "object":
            fmt = ctx.get("id_format", "opaque")
            out.append({"cls": "idor", "signal": "S-IDOR-01",
                        "title": f"IDOR/BOLA em '{ctx['name']}' (id {fmt}, dono={ctx.get('owned_by')})",
                        "lead": "authz confia no id do request → objeto de outra conta lido/escrito",
                        "probe": "matriz idor: 2 contas (A/B) + leitura-de-volta (§4); id em path/query/body/header; verbos"})
            out.append({"cls": "idor", "signal": "S-IDOR-02",
                        "title": f"mass-assignment de dono em '{ctx['name']}'",
                        "lead": "injetar ownerId/createdBy no body → escrita cross-account",
                        "probe": "enviar com id de teste + ler de volta (§4)"})
        elif unit_kind == "endpoint":
            tech = [t.lower() for t in ctx.get("tech", [])]
            if ctx.get("behind_authz"):
                out.append({"cls": "bac", "signal": "S-BAC-01",
                            "title": f"BAC por variação em {ctx['value']}",
                            "lead": "controle casa só uma forma do request; variante passa",
                            "probe": "OPTIONS/HEAD (🟢); trocar verbo; X-Original-URL; %2e; /ADMIN"})
            if "graphql" in tech or ctx.get("value", "").startswith("graphql:"):
                out.append({"cls": "graphql",
                            "title": f"GraphQL authz em {ctx['value']}",
                            "lead": "introspection + BAC row-level por tipo query/mutation (2 contas)",
                            "probe": "introspection unauth · role override · alias batching"})
            if any(_VALUE_PARAMS.search(p) for p in ctx.get("params", [])):
                out.append({"cls": "logic", "signal": "S-LOGIC-01",
                            "title": f"lógica de negócio em {ctx['value']}",
                            "lead": "servidor confia no valor do cliente (preço/papel/qty)",
                            "probe": "valor negativo/zero/gigante + leitura-de-volta"})
        elif unit_kind == "fingerprint":
            out.append({"cls": "auth" if "idp" in ctx["name"].lower() or "oauth" in ctx["name"].lower() else "graphql",
                        "title": f"fingerprint: {ctx['name']}",
                        "lead": ctx.get("playbook", ""), "probe": ctx.get("playbook", "")})
        return out


# ------------------------------------------------------------------ enumerate
def _lead_id(cls: str, ref: str) -> str:
    return slugify(f"{cls}-{ref}")[:48]


def _weight(state: dict, cls: str, tech: str = "") -> float:
    w = state.get("weights", {})
    return w.get(f"{cls}|{tech}", w.get(cls, 1.0)) if tech else w.get(cls, 1.0)


def enumerate_leads(program: str, only_class: str = "", catalog: AttackCatalog | None = None) -> list[dict]:
    st = load(program)
    catalog = catalog or LocalAttackCatalog()
    cap = load_capability_graph(get_brain_dir())
    enablers = set(cap.get("nodes", {}).keys())
    leads: list[dict] = []

    def emit(prim: dict, ref: str, endpoint: str = ""):
        cls = prim["cls"]
        if only_class and cls != only_class:
            return
        base = _CLS_PRIO.get(cls, 4)
        w = _weight(st, cls)
        chain = bool(enablers) and cls in ("idor", "bac", "redirect", "ssrf", "graphql")
        score = base - (w - 1.0) - (0.5 if chain else 0.0)
        leads.append({
            "id": _lead_id(cls, ref), "kind": "model", "cls": cls,
            "title": prim["title"], "lead": prim.get("lead", ""), "probe": prim.get("probe", ""),
            "signal": prim.get("signal", ""), "endpoint": endpoint,
            "weight": round(w, 2), "chain": chain, "_score": score,
        })

    # objetos → IDOR/BOLA
    for obj in st["objects"]:
        for prim in catalog.primitives("object", obj):
            emit(prim, obj["name"], obj.get("endpoint", ""))
    # endpoints → BAC/graphql/logic
    authz_targets = {b.get("to") for b in st["boundaries"] if b.get("control") == "authz"}
    for cid, comp in st["components"].items():
        if comp["kind"] != "endpoint":
            continue
        ctx = {**comp, "behind_authz": comp["value"] in authz_targets}
        for prim in catalog.primitives("endpoint", ctx):
            emit(prim, comp["value"], comp["value"])
    # fingerprints
    for fp in st["fingerprints"]:
        for prim in catalog.primitives("fingerprint", fp):
            emit(prim, fp["name"])
    # auth_flows → simuladores de mecanismo
    for flow in st["auth_flows"]:
        for atk in mechanisms.simulate(flow["kind"], flow.get("spec", {})):
            cls = flow["kind"] if flow["kind"] in _CLS_PRIO else "auth"
            if only_class and cls != only_class:
                continue
            base = _CLS_PRIO.get(cls, 2)
            w = _weight(st, cls)
            score = base - (w - 1.0) - (0.5 if atk.get("chain") else 0.0)
            leads.append({
                "id": _lead_id(cls, atk["attack"]), "kind": "model", "cls": cls,
                "title": f"{flow['kind']}: {atk['attack']}", "lead": atk["why"],
                "probe": atk["why"], "signal": "", "endpoint": flow.get("endpoint", ""),
                "weight": round(w, 2), "chain": bool(atk.get("chain")), "_score": score,
            })

    leads.sort(key=lambda x: (x["_score"], x["id"]))
    return leads


# ------------------------------------------------------------------ untested
def untested_surface(program: str) -> list[dict]:
    st = load(program)
    tested_refs = {v["lead"] for v in st["verdicts"]}
    rows = []
    for cid, comp in st["components"].items():
        if comp["kind"] != "endpoint":
            continue
        ref = _lead_id("bac", comp["value"])  # heurística de referência
        if ref in tested_refs:
            continue
        frag = 1 if any(_VALUE_PARAMS.search(p) for p in comp.get("params", [])) else 2
        rows.append({"endpoint": comp["value"], "tech": comp.get("tech", []),
                     "methods": comp.get("methods", []), "fragility": frag})
    rows.sort(key=lambda r: (r["fragility"], r["endpoint"]))
    return rows


# ------------------------------------------------- aprendizado autônomo (pesos)
def record_verdict(program: str, lead: str, verdict: str) -> dict:
    verdict = verdict.strip().lower()
    with locked_file(_state_path(program)):
        st = load(program)
        # descobre a classe do lead (prefixo antes do 1º '-')
        cls = lead.split("-", 1)[0]
        st["verdicts"].append({"lead": lead, "cls": cls, "verdict": verdict, "ts": _now()})
        w = st.setdefault("weights", {})
        cur = w.get(cls, 1.0)
        if verdict in ("fp", "padrao", "padrão", "publico", "público"):
            w[cls] = max(0.2, cur - 0.4)  # rebaixa a classe naquele alvo
        elif verdict in ("achado", "confirmed", "confirmado"):
            w[cls] = min(3.0, cur + 0.6)  # sobe a classe
            # promove IRMÃOS: bug numa classe = dev errou a classe (§3 A→B)
            for other in _CLS_PRIO:
                if other != cls:
                    w[other] = min(3.0, w.get(other, 1.0) + 0.1)
        save(program, st)
        return st


# ------------------------------------------------------------------ CLI helpers
def _print_leads(leads: list[dict]) -> None:
    if not leads:
        print("(nenhum lead — povoe o modelo com import-*/add-* primeiro)")
        return
    print(f"== ENUMERADOR — {len(leads)} lead(s), mais promissores primeiro ==")
    for x in leads:
        tag = f"{x['cls']}·w{x['weight']}" + ("·chain" if x["chain"] else "")
        print(f"[UNTESTED] {x['id']} ({tag}) — {x['title']}")
        if x["lead"]:
            print(f"    hipótese: {x['lead']}")
        if x["probe"]:
            print(f"    probe: {x['probe']}")
        print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Modelo de alvo (descobrir a roda)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init").add_argument("program")
    for name in ("import-jsrecon", "import-passive"):
        p = sub.add_parser(name); p.add_argument("program"); p.add_argument("json")
    ao = sub.add_parser("add-object"); ao.add_argument("program"); ao.add_argument("--name", required=True)
    ao.add_argument("--owned-by", default=""); ao.add_argument("--id-format", default="opaque")
    ao.add_argument("--endpoint", default="")
    aa = sub.add_parser("add-auth"); aa.add_argument("program"); aa.add_argument("--kind", required=True)
    aa.add_argument("--spec", default=""); aa.add_argument("--endpoint", default="")
    ab = sub.add_parser("add-boundary"); ab.add_argument("program"); ab.add_argument("--to", required=True)
    ab.add_argument("--control", default="authz"); ab.add_argument("--from", dest="frm", default="")
    ac = sub.add_parser("add-component"); ac.add_argument("program"); ac.add_argument("--value", required=True)
    ac.add_argument("--kind", default="endpoint"); ac.add_argument("--methods", default=""); ac.add_argument("--params", default="")
    en = sub.add_parser("enumerate"); en.add_argument("program"); en.add_argument("--class", dest="cls", default="")
    en.add_argument("--seed-matrix", action="store_true"); en.add_argument("--json", action="store_true")
    sub.add_parser("untested").add_argument("program")
    si = sub.add_parser("simulate"); si.add_argument("program"); si.add_argument("mechanism")
    rv = sub.add_parser("record-verdict"); rv.add_argument("program"); rv.add_argument("lead"); rv.add_argument("verdict")
    sh = sub.add_parser("show"); sh.add_argument("program"); sh.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.cmd == "init":
        save(a.program, load(a.program)); print(f"[+] modelo inicializado: {_state_path(a.program)}"); return 0
    if a.cmd == "import-jsrecon":
        st = import_jsrecon(a.program, _read_json_arg(a.json))
        print(f"[+] jsrecon importado: {len([c for c in st['components'].values() if c['kind']=='endpoint'])} endpoints, "
              f"{len(st['fingerprints'])} fingerprints"); return 0
    if a.cmd == "import-passive":
        st = import_passive(a.program, _read_json_arg(a.json))
        print(f"[+] passive importado: {len([c for c in st['components'].values() if c['kind']=='host'])} hosts"); return 0
    if a.cmd == "add-object":
        with locked_file(_state_path(a.program)):
            st = load(a.program)
            st["objects"].append({"name": a.name, "owned_by": a.owned_by,
                                  "id_format": a.id_format, "endpoint": a.endpoint})
            save(a.program, st)
        print(f"[+] objeto '{a.name}' adicionado"); return 0
    if a.cmd == "add-auth":
        with locked_file(_state_path(a.program)):
            st = load(a.program)
            st["auth_flows"].append({"id": slugify(a.kind + "-" + (a.endpoint or str(len(st["auth_flows"])))),
                                     "kind": a.kind, "spec": _parse_spec(a.spec), "endpoint": a.endpoint})
            save(a.program, st)
        print(f"[+] auth_flow '{a.kind}' adicionado"); return 0
    if a.cmd == "add-boundary":
        with locked_file(_state_path(a.program)):
            st = load(a.program)
            st["boundaries"].append({"from": a.frm, "to": a.to, "control": a.control, "trusts": []})
            save(a.program, st)
        print(f"[+] fronteira {a.frm or '?'}→{a.to} ({a.control})"); return 0
    if a.cmd == "add-component":
        with locked_file(_state_path(a.program)):
            st = load(a.program)
            st["components"][f"{a.kind[:3]}:{a.value}"] = {
                "kind": a.kind, "value": a.value,
                "methods": [m.strip() for m in a.methods.split(",") if m.strip()],
                "params": [p.strip() for p in a.params.split(",") if p.strip()],
                "tech": [], "source": "curated"}
            save(a.program, st)
        print(f"[+] componente '{a.value}' adicionado"); return 0
    if a.cmd == "enumerate":
        leads = enumerate_leads(a.program, a.cls)
        if a.json:
            print(json.dumps([{k: v for k, v in x.items() if not k.startswith("_")} for x in leads],
                             ensure_ascii=False, indent=2))
        else:
            _print_leads(leads)
        if a.seed_matrix:
            import exhaustion
            seeded = 0
            for x in leads:
                if x.get("endpoint"):
                    exhaustion.op_open(a.program, x["id"], x["cls"], x["endpoint"], "", exhaustion.DEFAULT_THRESHOLD)
                    seeded += 1
            print(f"\n[+] {seeded} matriz(es) de exaustão semeada(s) (exhaustion.py).", file=sys.stderr)
        return 0
    if a.cmd == "untested":
        rows = untested_surface(a.program)
        print(f"== NÃO-TESTADO — {len(rows)} superfície(s), mais frágil primeiro ==")
        for r in rows:
            print(f"   [{'frágil' if r['fragility']==1 else 'médio'}] {r['endpoint']}  "
                  f"tech={r['tech']} métodos={r['methods']}")
        return 0
    if a.cmd == "simulate":
        st = load(a.program)
        flows = [f for f in st["auth_flows"] if f["kind"] == a.mechanism]
        if not flows:
            print(f"(sem auth_flow '{a.mechanism}' no modelo — use add-auth --kind {a.mechanism} --spec ...)",
                  file=sys.stderr); return 1
        for f in flows:
            print(f"== SIMULAÇÃO {a.mechanism} ({f.get('endpoint') or f['id']}) ==")
            for atk in mechanisms.simulate(a.mechanism, f.get("spec", {})):
                ch = f"  [chain: {atk['chain']}]" if atk.get("chain") else ""
                print(f"   ({atk['priority']}) {atk['attack']}{ch}\n       → {atk['why']}")
        return 0
    if a.cmd == "record-verdict":
        record_verdict(a.program, a.lead, a.verdict)
        print(f"[+] veredito '{a.verdict}' registrado p/ {a.lead}; pesos re-ajustados (aprendizado autônomo)."); return 0
    if a.cmd == "show":
        st = load(a.program)
        if a.json:
            print(json.dumps(st, ensure_ascii=False, indent=2)); return 0
        eps = [c for c in st["components"].values() if c["kind"] == "endpoint"]
        hosts = [c for c in st["components"].values() if c["kind"] == "host"]
        print(f"# Modelo do sistema — {a.program}\n")
        print(f"- Hosts: {len(hosts)} · Endpoints: {len(eps)} · Objetos: {len(st['objects'])} · "
              f"Auth flows: {len(st['auth_flows'])} · Fronteiras: {len(st['boundaries'])}")
        print(f"- Fingerprints: {', '.join(f['name'] for f in st['fingerprints']) or '—'}")
        print(f"- Pesos aprendidos: {st['weights'] or '(neutros)'}")
        print(f"- Vereditos: {len(st['verdicts'])}")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
