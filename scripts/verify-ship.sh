#!/usr/bin/env bash
# Layer 2.6: build-time leak gate. Scans a shipped binary for things that must
# never appear in it and exits non-zero (REFUSE) on any hit, so a regression that
# reintroduces a leak fails the build instead of shipping quietly.
#
# Two scans:
#   1. forbidden strings (paths, panic residue, dev-only strings)
#   2. float immediates (Layer 3 acceptance): the f64 constants that go through
#      encf! MUST be absent as cleartext -- if one is present, encryption
#      regressed. Plus an advisory scan for other "round" f64s.
#
# Usage: scripts/verify-ship.sh <binary>
set -euo pipefail

BIN="${1:?usage: verify-ship.sh <binary>}"
[ -f "$BIN" ] || { echo "verify: no such file: $BIN" >&2; exit 2; }

# -- 1. forbidden strings ----------------------------------------------------
FORBIDDEN=(
  # Machine / build-tree paths (Layer 2.3)
  "/home/"
  "vsemenyakin"
  ".cargo"
  ".rustup"
  # std / rustc residue (Layer 2.4)
  "/rustc/"
  "panicked at"
  "RUST_BACKTRACE"
  # First-party source paths (Layer 2.3/2.4)
  "src/main.rs"
  "src/pipeline.rs"
  "src/sha256.rs"
  "crates/crypt"
  # Dev-only strings that must be gated out of ship (Layer 1)
  "cannot read"
  "testdata"
  "fixed_input"
  "bytes from"
  # Anti-tamper literals that must be obfstr!-encrypted (Layer 2.2)
  "/proc/self/"
  "TracerPid"
  "LD_PRELOAD"
)

leaks=0
dump="$(strings -a "$BIN")"
for s in "${FORBIDDEN[@]}"; do
  n=$(printf '%s\n' "$dump" | grep -c -F -- "$s" || true)
  if [ "$n" -ne 0 ]; then
    echo "verify: STRING LEAK: \"$s\" x$n" >&2
    leaks=$((leaks + 1))
  fi
done

# -- 2. float-immediate scan (Layer 3 acceptance) ----------------------------
if command -v python3 >/dev/null 2>&1; then
  if ! python3 - "$BIN" <<'PY'
import sys, struct
data = open(sys.argv[1], "rb").read()

# f64 values that pass through encf! and therefore MUST NOT appear as cleartext
# little-endian doubles. Mirror src/pipeline.rs run() + decoys().
sensitive = [1.35, 0.5,
             0.485, 0.456, 0.406, 0.229, 0.224, 0.225, 1.0 / 255.0,
             0.25, 0.45, 0.50, 0.65, 0.70]
# Plaintext f64 that legitimately appear (not secret): our own 255.0/1000.0 plus
# 2.0, a benign constant pulled in by std. Excluded from the advisory.
whitelist = {255.0, 1000.0, 2.0}

leaks = 0
for v in sensitive:
    if struct.pack("<d", v) in data:
        print(f"verify: FLOAT LEAK: {v!r} present as cleartext f64", file=sys.stderr)
        leaks += 1

# Advisory: any other "round" f64 present (what an attacker's float-scan targets).
cands = [i / 20 for i in range(1, 20)] + [float(i) for i in range(1, 65)]
adv = sorted({v for v in cands if v not in whitelist and struct.pack("<d", v) in data})
if adv:
    print("verify: NOTE round f64 immediates present (verify none are secret): "
          + ", ".join(repr(x) for x in adv), file=sys.stderr)

sys.exit(1 if leaks else 0)
PY
  then
    leaks=$((leaks + 1))
  fi
else
  echo "verify: NOTE python3 missing -- skipping float-immediate scan" >&2
fi

# -- verdict -----------------------------------------------------------------
if [ "$leaks" -ne 0 ]; then
  echo "verify: REFUSE -- $leaks leak(s) present in $BIN" >&2
  exit 1
fi
echo "verify: PASS -- no forbidden strings or cleartext secret floats in $BIN"
