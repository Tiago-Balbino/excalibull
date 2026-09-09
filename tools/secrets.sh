#!/usr/bin/env bash
# secrets.sh — sela/abre o cofre .secrets/ pra transporte entre máquinas.
#
# O cofre .secrets/ é gitignored (nunca versionado). Este helper empacota tudo
# num único arquivo criptografado (gpg simétrico, AES-256) que você pode levar
# por scp/USB/gerenciador de senhas pra outra máquina — o ciphertext é inútil
# sem a senha. A SENHA você digita interativamente; o script nunca a recebe por
# argumento (não vaza em histórico/ps).
#
#   bash tools/secrets.sh seal     # .secrets/  -> excalibull-secrets.tar.gz.gpg
#   bash tools/secrets.sh unseal   # excalibull-secrets.tar.gz.gpg -> .secrets/
#
# Fluxo entre máquinas:
#   PC1:  bash tools/secrets.sh seal
#         scp excalibull-secrets.tar.gz.gpg  voce@PC2:~/projetos/pessoal/excalibull/
#         (ou copie por USB / cole num gerenciador de senhas)
#   PC2:  git clone/pull  (traz o repo, SEM .secrets/)
#         bash tools/secrets.sh unseal
#         rm excalibull-secrets.tar.gz.gpg   # opcional, some com o blob
set -euo pipefail

cd "$(dirname "$0")/.."
BLOB="excalibull-secrets.tar.gz.gpg"

case "${1:-}" in
  seal)
    [ -d .secrets ] || { echo "erro: .secrets/ não existe aqui." >&2; exit 1; }
    tar czf - .secrets \
      | gpg --symmetric --cipher-algo AES256 --no-symkey-cache -o "$BLOB"
    chmod 600 "$BLOB"
    echo "✅ selado em $BLOB — leve este arquivo. NÃO commite (a menos que aceite o risco B)."
    echo "   sha256: $(sha256sum "$BLOB" | cut -d' ' -f1)"
    ;;
  unseal)
    [ -f "$BLOB" ] || { echo "erro: $BLOB não encontrado aqui." >&2; exit 1; }
    gpg --decrypt --no-symkey-cache "$BLOB" | tar xzf -
    chmod 700 .secrets; chmod 600 .secrets/* 2>/dev/null || true
    echo "✅ aberto em .secrets/ ($(ls .secrets | tr '\n' ' '))"
    ;;
  *)
    echo "uso: bash tools/secrets.sh {seal|unseal}" >&2; exit 2 ;;
esac
