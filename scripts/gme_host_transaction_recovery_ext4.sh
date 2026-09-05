#!/usr/bin/env bash
set -euo pipefail
cd /home/majorforge/forge-virt
exec cargo test -p forge-guest-mutation --lib gme_host_transaction_recovery_ext4 -- --ignored --nocapture
