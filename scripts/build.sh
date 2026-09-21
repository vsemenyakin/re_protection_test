#!/usr/bin/env bash
# Deprecated: superseded by build-ship.sh, which does the full hardened build
# (path remapping, build-std without panic strings, strip, seal, and the leak
# verifier) with the correct shared CRYPT_K. Kept as a thin shim.
set -euo pipefail
# Invoke via `bash` (not a direct exec) so it works even when the +x bit was lost
# in a Windows->Pi sync (tar does not carry an execute bit).
exec bash "$(dirname "$0")/build-ship.sh" "$@"
