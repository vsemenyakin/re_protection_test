#!/usr/bin/env python3
"""Layer 2.6 build-time leak gate.

Scans a shipped binary for things that must never appear in it and exits non-zero
(REFUSE) on any hit, so a regression that reintroduces a leak fails the build
instead of shipping quietly.

Two scans:
  1. forbidden strings -- machine/build-tree paths, std/rustc residue, first-party
     source paths, dev-only strings, and anti-tamper literals that must be
     obfstr!-encrypted. Extracts printable runs itself (like `strings`), so it
     needs no binutils.
  2. float immediates (Layer 3 acceptance) -- the f64 constants that pass through
     encf! MUST be absent as cleartext; if one is present, encryption regressed.
     Plus an advisory NOTE for other "round" f64s an attacker's scan would target.

Usage: verify_ship.py <binary>
"""

import struct
import sys

# -- 1. forbidden strings ----------------------------------------------------
FORBIDDEN = [
    # Machine / build-tree paths (Layer 2.3)
    "/home/",
    "vsemenyakin",
    ".cargo",
    ".rustup",
    # std / rustc residue (Layer 2.4)
    "/rustc/",
    "panicked at",
    "RUST_BACKTRACE",
    # First-party source paths (Layer 2.3/2.4)
    "src/main.rs",
    "src/pipeline.rs",
    "src/sha256.rs",
    "crates/crypt",
    # Dev-only strings that must be gated out of ship (Layer 1)
    "cannot read",
    "testdata",
    "fixed_input",
    "bytes from",
    # Anti-tamper literals that must be obfstr!-encrypted (Layer 2.2)
    "/proc/self/",
    "TracerPid",
    "LD_PRELOAD",
]

# -- 2. float immediates -----------------------------------------------------
# f64 values that pass through encf! and therefore MUST NOT appear as cleartext
# little-endian doubles. Mirror src/pipeline.rs run() + decoys().
SENSITIVE_F64 = [
    1.35, 0.5,
    0.485, 0.456, 0.406, 0.229, 0.224, 0.225, 1.0 / 255.0,
    0.25, 0.45, 0.50, 0.65, 0.70,
]
# Plaintext f64 that legitimately appear (not secret): our own 255.0/1000.0 plus
# 2.0, a benign constant pulled in by std. Excluded from the advisory.
ROUND_WHITELIST = {255.0, 1000.0, 2.0}


def printable_runs(data, minlen=4):
    """Printable-ASCII runs of length >= minlen, like `strings -a`."""
    runs = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                runs.append(cur.decode("ascii"))
            cur.clear()
    if len(cur) >= minlen:
        runs.append(cur.decode("ascii"))
    return runs


def main(argv):
    if len(argv) != 2:
        print("usage: verify_ship.py <binary>", file=sys.stderr)
        return 2
    path = argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"verify: cannot read {path}: {e}", file=sys.stderr)
        return 2

    leaks = 0

    # 1. forbidden strings (count matching printable runs, like `strings | grep -c`).
    runs = printable_runs(data)
    for s in FORBIDDEN:
        n = sum(1 for r in runs if s in r)
        if n:
            print(f'verify: STRING LEAK: "{s}" x{n}', file=sys.stderr)
            leaks += 1

    # 2. secret float immediates -- hard failure.
    for v in SENSITIVE_F64:
        if struct.pack("<d", v) in data:
            print(f"verify: FLOAT LEAK: {v!r} present as cleartext f64", file=sys.stderr)
            leaks += 1

    # Advisory: any other "round" f64 present (what an attacker's float-scan targets).
    cands = [i / 20 for i in range(1, 20)] + [float(i) for i in range(1, 65)]
    adv = sorted({v for v in cands
                  if v not in ROUND_WHITELIST and struct.pack("<d", v) in data})
    if adv:
        print("verify: NOTE round f64 immediates present (verify none are secret): "
              + ", ".join(repr(x) for x in adv), file=sys.stderr)

    # -- verdict --
    if leaks:
        print(f"verify: REFUSE -- {leaks} leak(s) present in {path}", file=sys.stderr)
        return 1
    print(f"verify: PASS -- no forbidden strings or cleartext secret floats in {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
