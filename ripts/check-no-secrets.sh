#!/usr/bin/env sh
set -eu
! rg -n --hidden --glob '!.git/**' '(?i)(aws_secret_access_key|private_key-----)' .
