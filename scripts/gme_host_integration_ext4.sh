#!/usr/bin/env bash
set -euo pipefail

# Host-native integration proof only. The Rust ignored test performs all
# guest mutation through DirectLibguestfsAdapter; this script only selects the
# test and forwards output. It never names or opens the real Fedora staging.
cd /home/majorforge/forge-virt
exec cargo test -p forge-guest-mutation --lib disposable_qcow2_reaches_direct_guestfish_boundary -- --ignored --nocapture
