"""Contratos de recon: estrutura de requisições sem valores, cookies ou corpos crus."""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, unquote, urlsplit

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "QUERY", "MUTATION", "SUBSCRIPTION", "?"}
NAME = re.compile(r"^[A-Za-z_$][A-Za-z0-9_.$\[\]-]{0,63}$")


def name(value):
    value = str(value)
    return value if NAME.fullmatch(value) else "[redacted]"


def safe_path(path):
    """Substitui IDs, e-mails, segmentos codificados e tokens por marcadores.

    Sanitização conservadora; não constitui prova de ausência de PII. Revisar
    a nota antes de publicar, principalmente rotas com slugs de pessoas.
    """
    parts = []
    sensitive_next = False
    for segment in path.split("/"):
        decoded = unquote(segment)
        sensitive = (sensitive_next or "@" in decoded or decoded != segment
                     or (bool(re.search(r"\d", decoded)) and not re.fullmatch(r"v\d{1,3}", decoded)) or len(decoded) > 32
                     or bool(re.search(r"[^A-Za-z0-9_.{}:$-]", decoded)))
        parts.append("{redacted}" if sensitive and segment else segment)
        sensitive_next = decoded.lower() in {"token", "secret", "password", "email", "session", "code"}
    return "/".join(parts) or "/"


def schema(value, depth=0):
    if depth >= 5:
        return "truncated"
    if isinstance(value, dict):
        return {name(k): schema(v, depth + 1) for k, v in list(value.items())[:100]}
    if isinstance(value, list):
        variants = {json.dumps(schema(v, depth + 1), sort_keys=True) for v in value[:20]}
        return {"array": [json.loads(v) for v in sorted(variants)]}
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "string"


def request_record(url, method="?", headers=None, post_data=None, mime_type="",
                   role="unknown", flow="unknown", source="recon", status=None,
                   query_names=(), form_names=()):
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL HTTP(S) necessária")
    if method.upper() not in METHODS:
        raise ValueError("método inválido")
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    content_type = (mime_type or headers.get("content-type", "")).split(";", 1)[0].lower()
    # Nunca persistir headers livres ou valores de parâmetros.
    if not re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", content_type):
        content_type = ""
    query = sorted({name(k) for k, _ in parse_qsl(parsed.query, keep_blank_values=True)}
                   | {name(k) for k in query_names})
    body, operations = {}, []
    if post_data and len(post_data) <= 1_000_000:
        if content_type.endswith("json") or content_type.endswith("+json"):
            try:
                data = json.loads(post_data)
                body = schema(data)
                batches = data if isinstance(data, list) else [data]
                for item in batches[:100]:
                    if isinstance(item, dict):
                        op = item.get("operationName")
                        if op and NAME.fullmatch(str(op)):
                            operations.append(op)
                        # Mantém apenas o nome da operação, nunca query/variáveis literais.
                        operations.extend(re.findall(r"\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]{0,63})\b", str(item.get("query", ""))))
            except (ValueError, TypeError):
                body = "unparsed-json"
        elif content_type == "application/x-www-form-urlencoded":
            body = {name(k): "string" for k, _ in parse_qsl(post_data, keep_blank_values=True)}
        else:
            body = "opaque"
    if form_names:
        body = {name(k): "string" for k in form_names}
    for k, v in parse_qsl(parsed.query):
        if k == "operationName" and NAME.fullmatch(v):
            operations.append(v)
    if content_type == "application/graphql" and post_data:
        operations.extend(re.findall(r"\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]{0,63})\b", post_data))
    return {
        "host": parsed.hostname.lower().rstrip("."), "method": method.upper(),
        "path": safe_path(parsed.path), "port": parsed.port,
        "query_params": query, "body_schema": body, "content_type": content_type,
        "graphql_operations": sorted(set(operations)),
        "access_context": {"role": name(role), "flow": name(flow),
                           "credential_present": any(k in headers for k in ("authorization", "cookie"))},
        "source": name(source), "response_status": status if isinstance(status, int) else None,
    }


def normalize_record(row):
    """Reaplica a sanitização; não aceita campos arbitrários de um JSON externo."""
    host = str(row["host"]).lower().rstrip(".")
    # Impede injeção de credenciais/URL/YAML pelo campo host.
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
        raise ValueError("host inválido")
    port = row.get("port")
    if port is not None and (not isinstance(port, int) or not 1 <= port <= 65535):
        raise ValueError("porta inválida")
    path = str(row["path"])
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("path inválido")
    context = row.get("access_context") or {}
    result = request_record(f"https://{host}{':' + str(port) if port else ''}{path}",
                            str(row.get("method", "?")), role=context.get("role", "unknown"),
                            flow=context.get("flow", "unknown"), source=row.get("source", "recon"),
                            status=row.get("response_status"), query_names=row.get("query_params", []),
                            mime_type=row.get("content_type", ""))
    result["access_context"]["credential_present"] = context.get("credential_present") is True
    # Valida schema recursivamente: folhas devem ser tipos, nunca valores.
    def clean_shape(value, depth=0):
        if depth >= 6:
            return "truncated"
        if isinstance(value, dict):
            return {name(k): clean_shape(v, depth + 1) for k, v in list(value.items())[:100]}
        if isinstance(value, list):
            return [clean_shape(v, depth + 1) for v in value[:20]]
        return value if value in ("string", "number", "boolean", "null", "opaque", "truncated", "unparsed-json") else "redacted"
    result["body_schema"] = clean_shape(row.get("body_schema", {}))
    result["graphql_operations"] = sorted({name(v) for v in row.get("graphql_operations", [])})
    return result
