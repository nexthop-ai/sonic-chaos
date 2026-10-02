#!/bin/bash
# Build the SAI shim and refuse to ship one the syncd container could not load.
#
#   ./build.sh                              build here, check the ABI, run the tests
#   SONIC_CHAOS_BUILD_IMAGE=debian:bookworm ./build.sh    build inside a container instead
#
# The ABI check is the point. A .so linked against a glibc newer than the syncd container's
# fails to preload, and the loader only says so in a warning nobody reads -- syncd comes up
# with no shim and the run silently proves nothing. Better to fail here.
set -eu

cd "$(dirname "${BASH_SOURCE[0]}")"

# 202511.2 images are Debian 13 (glibc 2.41); the floor is set for bookworm so the same
# binary also loads on a 202411-era container. Raise it only with a reason.
MAX_GLIBC="${SONIC_CHAOS_MAX_GLIBC:-2.36}"
OUT="build/sonic_chaos_sai.so"

if [ -n "${SONIC_CHAOS_BUILD_IMAGE:-}" ]; then
    echo "building in ${SONIC_CHAOS_BUILD_IMAGE}"
    docker run --rm -v "$PWD:/shim" -w /shim -u "$(id -u):$(id -g)" \
        "$SONIC_CHAOS_BUILD_IMAGE" make clean all
else
    make clean all
fi

[ -f "$OUT" ] || { echo "build produced no $OUT"; exit 1; }

echo
echo "checking the shim can load in a syncd container"

exported=$(nm -D --defined-only "$OUT" | awk '$2 == "T" {print $3}')
if [ "$exported" != "sai_api_query" ]; then
    echo "FAIL: expected to export only sai_api_query, got: ${exported:-nothing}"
    exit 1
fi
echo "  exports only sai_api_query"

needed=$(objdump -T "$OUT" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -u -V | tail -1)
highest=$(printf '%s\n%s\n' "$needed" "$MAX_GLIBC" | sort -V | tail -1)
if [ "$highest" != "$MAX_GLIBC" ]; then
    echo "FAIL: needs glibc $needed but the floor is $MAX_GLIBC."
    echo "      Build in an older container: SONIC_CHAOS_BUILD_IMAGE=debian:bookworm ./build.sh"
    exit 1
fi
echo "  needs glibc $needed (floor $MAX_GLIBC)"

echo
./test/run_tests.sh

echo
echo "$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")  $(stat -c %s "$OUT") bytes"
echo "injectors/sai.py will pick it up from there."
