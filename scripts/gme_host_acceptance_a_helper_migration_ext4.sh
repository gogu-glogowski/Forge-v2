#!/usr/bin/env bash
set -euo pipefail
cd /home/majorforge/forge-virt
old_root=$(mktemp -d /tmp/forge-gme-b3-XXXXXX)
trap 'git worktree remove --force "$old_root" >/dev/null 2>&1 || true' EXIT
git worktree add --detach "$old_root" 77ca7dca126c70178e90fd814817673148daa275 >/dev/null
cargo build --release -p forge-preparation-control --manifest-path "$old_root/Cargo.toml" >/dev/null
old="$old_root/target/release/forge-preparation-control"
new="$(pwd)/target/release/forge-preparation-control"
cargo build --release -p forge-preparation-control >/dev/null
GME_OLD_HELPER="$old" GME_NEW_HELPER="$new" cargo test -p forge-guest-mutation --lib gme_host_acceptance_a_helper_migration_ext4 -- --ignored --nocapture
