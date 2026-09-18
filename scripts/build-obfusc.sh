#!/usr/bin/env bash
# Build the Obfusc LLVM pass plugin against LLVM 20 (same major as rustc's LLVM).
# Produces obfusc/build/Obfusc.so. Run once on the build host before build-ship.sh
# (which also invokes it).
set -euo pipefail

cd "$(dirname "$0")/.."
LLVM_CMAKE="$(llvm-config-20 --cmakedir)"

cmake -S obfusc -B obfusc/build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR="$LLVM_CMAKE"
cmake --build obfusc/build

echo ">> built $(ls -l obfusc/build/Obfusc.so | awk '{print $5}') bytes: obfusc/build/Obfusc.so"
