#!/usr/bin/env bash
set -euo pipefail
cd /home/majorforge/forge-virt
exec cargo test -p forge-guest-mutation --lib gme_host_acceptance_b_multifile_ext4 -- --ignored --nocapture
