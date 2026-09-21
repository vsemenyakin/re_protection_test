#!/usr/bin/env bash
# Hardened `ship` build (Linux/ELF target). Run on the target-arch host (the Pi).
#
# Layers applied here:
#   0.1  [profile.ship] + --no-default-features --features anti-tamper
#   2.3  --remap-path-prefix for CARGO_HOME / RUSTUP_HOME / rust-src / project root
#   2.4  build-std with panic_immediate_abort + -Zlocation-detail=none
#        (drops /rustc/ paths, std panic strings, and every panic-site file:line)
#   2.5  strip = "symbols" (in the profile)
#   3.3  fresh random CRYPT_K per build (constants' ciphertext differs every build)
#   5.6  seal the binary to its own .text LAST (after strip), same CRYPT_K as the
#        build, or the runtime decode key would diverge and constants decode to garbage
#   2.6  verify_ship.py gates leaks -- REFUSE (non-zero exit) if any forbidden
#        string or cleartext secret float returns, so an unhardened binary never
#        ships silently
#
# Usage: scripts/build-ship.sh [--page-size N]   (default page size 16384)
set -euo pipefail

TOOLCHAIN="nightly-2025-06-15"
TARGET="aarch64-unknown-linux-gnu"
PAGE_SIZE=16384
while [ $# -gt 0 ]; do
  case "$1" in
    --page-size) PAGE_SIZE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")/.."
ROOT="$PWD"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"

# Layer 3.3: fresh random 64-bit encryption key, shared by the build and the seal
# step (exported for both, so crypt::K matches in the binary and in the sealer).
export CRYPT_K="0x$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"

# Layer 4: OLLVM-style obfuscation. Build the plugin if needed, load it only for
# workspace crates via RUSTC_WORKSPACE_WRAPPER (std/deps/build-std stay clean),
# and drive crown/rest from policy.json. REFUSE if the plugin or policy is
# missing -- never ship unobfuscated silently.
PLUGIN="$ROOT/obfusc/build/Obfusc.so"
POLICY="$ROOT/obfusc/policy.json"
[ -f "$PLUGIN" ] || bash "$ROOT/scripts/build-obfusc.sh"
[ -f "$PLUGIN" ] || { echo "REFUSE: obfuscation plugin missing: $PLUGIN" >&2; exit 1; }
[ -f "$POLICY" ] || { echo "REFUSE: obfuscation policy missing: $POLICY" >&2; exit 1; }
export OBF_PLUGIN="$PLUGIN"
export OBF_CROWN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["crown"]["regex"])' "$POLICY")"
export OBF_SUB_CROWN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["crown"]["sub_rounds"])' "$POLICY")"
export OBF_SUB_REST="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["rest"]["sub_rounds"])' "$POLICY")"
export OBF_BCF="$(python3 -c 'import json,sys;print(1 if json.load(open(sys.argv[1]))["crown"].get("bcf") else 0)' "$POLICY")"
export OBF_FLA="$(python3 -c 'import json,sys;print(1 if json.load(open(sys.argv[1]))["crown"].get("fla") else 0)' "$POLICY")"
export RUSTC_WORKSPACE_WRAPPER="$ROOT/scripts/rustc-obfusc-wrapper.sh"
echo ">> obfuscation: crown=/$OBF_CROWN/ sub_crown=$OBF_SUB_CROWN sub_rest=$OBF_SUB_REST bcf=$OBF_BCF fla=$OBF_FLA"

# Layer 2.3: path remapping. Specific (rust-src, under RUSTUP_HOME) first.
SYSROOT="$(rustc "+$TOOLCHAIN" --print sysroot)"
RUSTSRC="$SYSROOT/lib/rustlib/src/rust"
REMAP="--remap-path-prefix=$RUSTSRC=/rustc"
REMAP="$REMAP --remap-path-prefix=$CARGO_HOME=/cargo"
REMAP="$REMAP --remap-path-prefix=$RUSTUP_HOME=/rustup"
REMAP="$REMAP --remap-path-prefix=$ROOT=/build"

echo ">> building ship (toolchain $TOOLCHAIN, target $TARGET, CRYPT_K=$CRYPT_K)"
# Layer 2.4: rebuild std without panic machinery; drop panic-site location detail.
RUSTFLAGS="$REMAP -Zlocation-detail=none" \
  cargo "+$TOOLCHAIN" build \
    -Z build-std=std,panic_abort \
    -Z build-std-features=panic_immediate_abort \
    --target "$TARGET" \
    --no-default-features --features anti-tamper \
    --profile ship

BIN="target/$TARGET/ship/re_protection_test"

# Layer 5.6: seal LAST, after strip, with the SAME CRYPT_K (else key diverges).
# The sealer is a host tool -- build it without the obfuscation wrapper.
echo ">> sealing $BIN (page-size $PAGE_SIZE)"
env -u RUSTC_WORKSPACE_WRAPPER CRYPT_K="$CRYPT_K" \
  cargo "+$TOOLCHAIN" run -q -p crypt --bin seal -- \
  "$BIN" --page-size "$PAGE_SIZE"

# Layer 2.6: refuse to ship a binary that leaks.
echo ">> verifying $BIN"
python3 "$ROOT/scripts/verify_ship.py" "$BIN"

echo ">> OK: $BIN"
