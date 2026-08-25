#!/usr/bin/env sh
set -eu
! rg -n --hidden \
  --glob '!.git/**' \
  --glob '!scripts/check-no-secrets.sh' \
  '(?i)(AWS_SECRET_ACCESS_KEY[[:space:]]*=|-----BEGIN (RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,})' .
