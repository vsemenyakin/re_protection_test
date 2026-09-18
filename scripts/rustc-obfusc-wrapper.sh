#!/usr/bin/env bash
# RUSTC_WORKSPACE_WRAPPER: cargo invokes this as `wrapper <rustc> <args...>` for
# workspace members ONLY -- not for registry deps and not for build-std. So the
# OLLVM-style plugin is loaded only when compiling our own crates (crypt +
# re_protection_test); std, obfstr, libc, and the rebuilt build-std stay clean.
#
# It only loads the plugin (`-Zllvm-plugins`); the plugin itself reads the policy
# from the environment (OBF_CROWN / OBF_SUB_CROWN / OBF_SUB_REST / OBF_BCF /
# OBF_VERBOSE), because a plugin's options load too late for `-Cllvm-args`. Those
# env vars are set by build-ship.sh from policy.json and inherited here.
#   OBF_PLUGIN  absolute path to Obfusc.so (required to activate obfuscation)
set -euo pipefail

REAL="$1"
shift

# Pass probe/version invocations straight through untouched.
for a in "$@"; do
  case "$a" in
    --print*|-vV|--version|-V) exec "$REAL" "$@" ;;
  esac
done

# Only meaningful when a plugin path is provided.
if [ -z "${OBF_PLUGIN:-}" ]; then
  exec "$REAL" "$@"
fi

exec "$REAL" "$@" "-Zllvm-plugins=$OBF_PLUGIN"
