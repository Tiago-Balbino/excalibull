#!/usr/bin/env python3
"""mechanisms.py — simuladores de mecanismo do Excalibull (dry-run, funções puras).

Dado um SPEC pequeno de um mecanismo bem-definido (JWT, OAuth/OIDC, HMAC, máquina
de estados), devolve a lista RANKEADA de ataques que "valem disparar" e o porquê.
NÃO faz tráfego — é raciocínio local sobre o spec (o que o `arsenal.md` chama de
"simular o mecanismo pra decidir o ataque"). O disparo real é do agente/humano sob
o gate de recibo.

Cada ataque: {"attack","why","priority"(menor=mais alto)[,"chain"]}.
Consumido por tools/target_model.py (enumerador).
"""

from __future__ import annotations


def _rank(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda x: (x.get("priority", 5), x["attack"]))


def simulate_jwt(spec: dict) -> list[dict]:
    """spec: {alg, has_kid, kid, claims:[...], jku, x5u, exp_present}."""
    alg = str(spec.get("alg", "")).lower()
    claims = [str(c).lower() for c in spec.get("claims", [])]
    out: list[dict] = []
    if alg.startswith(("rs", "es", "ps")):
        out.append({"attack": "alg-confusion-rs-to-hs", "priority": 1,
                    "why": "alg assimétrico → assinar com HS256 usando a chave PÚBLICA como segredo HMAC",
                    "chain": "forja de token → ATO"})
    out.append({"attack": "alg-none", "priority": 2,
                "why": "alg=none/None/nOnE + remover assinatura (aceita sem verificar?)"})
    if spec.get("has_kid"):
        out.append({"attack": "kid-injection", "priority": 2,
                    "why": "kid como path/SQL: kid=../../dev/null (chave vazia) · kid=arquivo previsível · SQLi no kid"})
    if spec.get("jku") or spec.get("x5u"):
        out.append({"attack": "jku-x5u-ssrf", "priority": 1,
                    "why": "jku/x5u apontando p/ JWKS do atacante → assina token arbitrário",
                    "chain": "SSRF+forja → ATO"})
    if alg.startswith("hs"):
        out.append({"attack": "weak-hmac-secret", "priority": 3,
                    "why": "HS* com segredo fraco → brute (jwt_tool/hashcat + wordlist)"})
    if any(k in claims for k in ("role", "isadmin", "admin", "tenant", "scope", "plan")):
        out.append({"attack": "claim-tamper", "priority": 2,
                    "why": "claim de privilégio (role/tenant/scope) → elevar após quebrar a assinatura"})
    if spec.get("exp_present"):
        out.append({"attack": "exp-nbf-skip", "priority": 4,
                    "why": "remover/estender exp/nbf → replay de token expirado"})
    return _rank(out)


def simulate_oauth(spec: dict) -> list[dict]:
    """spec: {flow: code|implicit|pkce, redirect_uri_validation: exact|prefix|substring|open,
             state: bool, nonce: bool, pkce: bool, oidc: bool}."""
    flow = str(spec.get("flow", "code")).lower()
    val = str(spec.get("redirect_uri_validation", "unknown")).lower()
    out: list[dict] = []
    if val in ("prefix", "substring", "open", "unknown"):
        why = {"prefix": "validação por prefixo → append (/cb.attacker.com, /cb/../)",
               "substring": "validação por substring → embutir domínio confiável",
               "open": "sem validação → redirect_uri arbitrário",
               "unknown": "validação desconhecida → testar prefix/substring/@/#/\\"}[val]
        out.append({"attack": "redirect_uri-bypass", "priority": 1, "why": why,
                    "chain": "redirect_uri → vaza ?code= → troca por token → ATO"})
    if flow == "implicit":
        out.append({"attack": "implicit-token-leak", "priority": 1,
                    "why": "implicit devolve token no #fragment → leak via redirect/referrer",
                    "chain": "token no fragment → ATO"})
    if flow in ("code", "pkce") and not spec.get("pkce"):
        out.append({"attack": "pkce-downgrade", "priority": 2,
                    "why": "sem PKCE → interceptação/substituição de code (app público)"})
    if not spec.get("state"):
        out.append({"attack": "state-csrf-fixation", "priority": 3,
                    "why": "sem state → login-CSRF / fixação no callback"})
    if spec.get("oidc") and not spec.get("nonce"):
        out.append({"attack": "id_token-replay", "priority": 3,
                    "why": "OIDC sem nonce → replay de id_token"})
    out.append({"attack": "code-reuse-substitution", "priority": 2,
                "why": "reusar code / trocar code entre contas (o code é 1x? amarrado ao cliente?)"})
    return _rank(out)


def simulate_hmac(spec: dict) -> list[dict]:
    """spec: {signs: raw|canonical|unknown, nonce: none|per-request|global|unknown, body_format}."""
    signs = str(spec.get("signs", "unknown")).lower()
    nonce = str(spec.get("nonce", "unknown")).lower()
    out: list[dict] = []
    if signs in ("raw", "unknown"):
        out.append({"attack": "dup-key-smuggling", "priority": 1,
                    "why": "assina bytes crus? → chave duplicada/espaço/\\uXXXX: parser da assinatura ≠ parser da lógica (P5)"})
        out.append({"attack": "sign-A-send-B", "priority": 1,
                    "why": "assino payload A, envio B num /status benigno → servidor re-parseia antes do HMAC?"})
    if nonce in ("global", "unknown"):
        out.append({"attack": "nonce-replay-cross-endpoint", "priority": 2,
                    "why": "contador de nonce é global? → replay cross-endpoint"})
    if nonce in ("per-request", "unknown"):
        out.append({"attack": "nonce-race-burst", "priority": 2,
                    "why": "burst paralelo com nonce idêntico (race no check do nonce, P6)"})
    if signs == "canonical":
        out.append({"attack": "numeric-divergence-only", "priority": 4,
                    "why": "canonicaliza antes do HMAC → smuggle morto; sobra divergência numérica + race do nonce"})
    return _rank(out)


def simulate_state(spec: dict) -> list[dict]:
    """spec: {steps: [nome,...]}. Ataca a suposição de ordem (§ P2/P6)."""
    steps = [str(s) for s in spec.get("steps", [])]
    out: list[dict] = []
    money = any(any(w in s.lower() for w in ("pay", "checkout", "purchase", "refund", "withdraw", "transfer"))
                for s in steps)
    if len(steps) >= 2:
        out.append({"attack": "step-skip", "priority": 2,
                    "why": f"pular pré-requisito: chegar em '{steps[-1]}' sem '{steps[0]}' (passo N confia em N-1?)"})
        out.append({"attack": "step-reorder", "priority": 3,
                    "why": "reordenar etapas (a ordem é garantida ou assumida?)"})
    out.append({"attack": "step-repeat", "priority": 1 if money else 3,
                "why": "repetir/reenviar um passo" + (" (double-spend em fluxo de $)" if money else "")})
    out.append({"attack": "step-race", "priority": 2,
                "why": "burst paralelo no passo que muda estado (race/TOCTOU, P6)"})
    return _rank(out)


_DISPATCH = {"jwt": simulate_jwt, "oauth": simulate_oauth, "oidc": simulate_oauth,
             "hmac": simulate_hmac, "state": simulate_state}


def simulate(mechanism: str, spec: dict) -> list[dict]:
    """Roteia p/ o simulador. Mecanismo desconhecido → lista vazia."""
    fn = _DISPATCH.get((mechanism or "").strip().lower())
    return fn(spec or {}) if fn else []


SUPPORTED = sorted(set(_DISPATCH))
