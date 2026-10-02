#!/bin/bash
# Prove the SAI shim on the build host, before it is ever loaded into syncd.
#
# fakesai.so provides sai_api_query and two API tables with the real slot layout and the real
# argument counts; fakesyncd calls through them. Preloading the shim between the two is the
# same thing that happens on a switch, minus the switch.
#
#   make test          (or)   ./test/run_tests.sh
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
BUILD="${BUILD:-$ROOT/build}"
CC="${CC:-gcc}"
SHIM="$BUILD/sonic_chaos_sai.so"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CONTROL="$WORK/control.json"
STATS="$WORK/stats.json"
export SONIC_CHAOS_SAI_CONTROL="$CONTROL"
export SONIC_CHAOS_SAI_STATS="$STATS"

passed=0
failed=0

fail() {
    printf '  FAIL %s\n' "$1"
    failed=$((failed + 1))
}

ok() {
    printf '  ok   %s\n' "$1"
    passed=$((passed + 1))
}

# assert <description> <expected-line>
assert_line() {
    if grep -qxF "$2" "$WORK/out"; then
        ok "$1"
    else
        fail "$1 (wanted '$2')"
        sed 's/^/       /' "$WORK/out"
    fi
}

assert_missing() {
    if grep -qxF "$2" "$WORK/out"; then
        fail "$1 (did not want '$2')"
    else
        ok "$1"
    fi
}

# run <preload:yes|no> <mode> <repeats>
run() {
    if [ "$1" = yes ]; then
        LD_PRELOAD="$SHIM" "$BUILD/fakesyncd" "$2" "${3:-1}" >"$WORK/out" 2>"$WORK/err"
    else
        "$BUILD/fakesyncd" "$2" "${3:-1}" >"$WORK/out" 2>"$WORK/err"
    fi
}

arm() {
    printf '%s' "$1" >"$CONTROL.new" && mv "$CONTROL.new" "$CONTROL"
}

echo "building the fake vendor library and a stand-in syncd"
mkdir -p "$BUILD"
$CC -O1 -g -std=gnu11 -Wall -Wextra -Werror -fPIC -shared \
    -o "$BUILD/libfakesai.so" "$HERE/fakesai.c" || exit 1
$CC -O1 -g -std=gnu11 -Wall -Wextra -Werror \
    -o "$BUILD/fakesyncd" "$HERE/fakesyncd.c" -L"$BUILD" -lfakesai -Wl,-rpath,"$BUILD" || exit 1
[ -f "$SHIM" ] || { echo "no $SHIM -- run make first"; exit 1; }

echo
echo "1. without the shim, calls reach the vendor untouched"
rm -f "$CONTROL" "$STATS"
run no basic 2
assert_line "route creates land" "reached.route_create=2"
assert_line "vlan member removes land" "reached.vlan_member_remove=2"
assert_line "create returns the vendor's status" "route_create.0 rc=0"

echo
echo "2. shim loaded, nothing armed: still a straight pass-through"
rm -f "$CONTROL" "$STATS"
run yes basic 2
assert_line "route creates still land" "reached.route_create=2"
assert_line "vlan member removes still land" "reached.vlan_member_remove=2"
assert_line "status is unchanged" "route_create.0 rc=0"
if [ -s "$WORK/err" ]; then
    fail "shim wrote to stderr: $(head -1 "$WORK/err")"
else
    ok "shim is silent on stderr"
fi

echo
echo "3. failing one object type and operation (the stale-member shape)"
arm '{"seq":1,"hook":["vlan_member"],"rules":{"vlan_member":{"remove":{"status":-7}}}}'
run yes basic 3
assert_line "vlan member remove returns ITEM_NOT_FOUND" "vlan_member_remove.0 rc=-7"
assert_line "and never reaches the ASIC" "reached.vlan_member_remove=0"
assert_line "routes are untouched" "reached.route_create=3"
assert_line "route status is untouched" "route_create.0 rc=0"

echo
echo "4. count: only the first call is failed"
arm '{"seq":2,"hook":["vlan_member"],"rules":{"vlan_member":{"remove":{"status":-7,"count":1}}}}'
run yes basic 3
assert_line "first remove fails" "vlan_member_remove.0 rc=-7"
assert_line "second remove succeeds" "vlan_member_remove.1 rc=0"
assert_line "third remove succeeds" "vlan_member_remove.2 rc=0"
assert_line "two of three reached the vendor" "reached.vlan_member_remove=2"

echo
echo "5. drop: success reported, vendor never called"
arm '{"seq":3,"hook":["route_entry"],"rules":{"route_entry":{"remove":{"drop":true}}}}'
run yes basic 2
assert_line "remove claims success" "route_remove.0 rc=0"
assert_line "but nothing reached the vendor" "reached.route_remove=0"
assert_line "create still passes through" "reached.route_create=2"

echo
echo "6. delay is really spent"
arm '{"seq":4,"hook":["route_entry"],"rules":{"route_entry":{"create":{"delay_ms":150}}}}'
run yes basic 2
elapsed=$(sed -n 's/^elapsed_ms=//p' "$WORK/out")
if [ "${elapsed:-0}" -ge 300 ]; then
    ok "two 150 ms delays cost ${elapsed} ms"
else
    fail "expected at least 300 ms, measured ${elapsed:-none} ms"
fi
assert_line "the call still reaches the vendor after the delay" "reached.route_create=2"

echo
echo "7. arguments survive the trampoline, including the seventh on the stack"
arm '{"seq":5,"hook":["vlan_member","route_entry"],"rules":{"vlan_member":{"remove":{"delay_ms":1}}}}'
run yes bulk
assert_line "seven-argument bulk create reaches the vendor" "reached.vlan_member_bulk=1"
assert_line "sixth argument arrives intact" "vlan_member_bulk.arg6_ok=1"
assert_line "seventh argument arrives intact" "vlan_member_bulk.arg7_ok=1"
assert_line "six-argument bulk create reaches the vendor" "reached.route_bulk=1"
run yes basic 1
assert_line "three-argument create forwards its attr_count" "forwarded.route_create_attr_count=3"
assert_line "one-argument remove forwards its object id" "forwarded.vlan_member_remove_oid=0x1000"

echo
echo "8. a wildcard rule covers every hooked object type"
arm '{"seq":6,"hook":["route_entry","vlan_member"],"rules":{"*":{"*":{"status":-1}}}}'
run yes basic 1
assert_line "route create fails" "route_create.0 rc=-1"
assert_line "vlan member remove fails" "vlan_member_remove.0 rc=-1"
assert_line "nothing reached the vendor" "reached.route_create=0"

echo
echo "9. a named rule beats the wildcard"
arm '{"seq":7,"hook":["route_entry","vlan_member"],"rules":{"*":{"*":{"status":-1}},
      "vlan_member":{"remove":{"status":-7}}}}'
run yes basic 1
assert_line "wildcard still applies to route create" "route_create.0 rc=-1"
assert_line "named rule wins for vlan member remove" "vlan_member_remove.0 rc=-7"

echo
echo "10. an unparseable control file disarms instead of guessing"
arm '{"seq":8,"hook":["vlan_member"],"rules":{"vlan_member":{"remove":{"status":'
run yes basic 2
assert_line "calls pass through" "reached.vlan_member_remove=2"
assert_line "and return the vendor's status" "vlan_member_remove.0 rc=0"

echo
echo "11. an object type that was never hooked cannot be armed later"
arm '{"seq":9,"hook":["route_entry"],"rules":{"route_entry":{"create":{"status":-7}}}}'
run yes basic 1
assert_line "the hooked type is armed" "route_create.0 rc=-7"
arm '{"seq":10,"hook":["route_entry"],"rules":{"vlan_member":{"remove":{"status":-7}}}}'
run yes basic 1
assert_line "a type hooked by its own rule is armed on the next start" "vlan_member_remove.0 rc=-7"

echo
echo "12. rearming mid-run needs no restart"
arm '{"seq":11,"hook":["route_entry","vlan_member"],"rules":{"route_entry":{"create":{"status":-7}}}}'
(
    sleep 0.3
    arm '{"seq":12,"hook":["route_entry","vlan_member"],"rules":{"route_entry":{"create":{"status":-13}}}}'
) &
run yes retune 1
wait
assert_line "first round uses the original status" "route_create.0 rc=-7"
if grep -A20 -- '--- retune ---' "$WORK/out" | grep -qxF "route_create.0 rc=-13"; then
    ok "second round picked up the rewritten control file"
else
    fail "second round did not pick up the new status"
    sed 's/^/       /' "$WORK/out"
fi

echo
echo "13. the stats file reports what is hooked and what was hit"
arm '{"seq":20,"hook":["vlan_member"],"rules":{"vlan_member":{"remove":{"status":-7}}}}'
run yes basic 2
if [ -f "$STATS" ]; then
    ok "stats file written"
    python3 - "$STATS" <<'PY' && ok "stats content is correct" || fail "stats content is wrong"
import json, sys
data = json.load(open(sys.argv[1]))
assert "vlan_member" in data["hooked"], data["hooked"]
assert data["seq"] == 20, data["seq"]
row = [r for r in data["rules"] if r["object_type"] == "vlan_member" and r["op"] == "remove"]
assert row and row[0]["armed"] and row[0]["injected"] == 2, row
PY
else
    fail "no stats file at $STATS"
fi

echo
echo "14. the published count includes the call that triggered the write"
# The flush happens from inside the call path, so ordering matters. Publishing before
# incrementing left every counter one call behind: on a switch between bursts of SAI traffic,
# adding a single route looked as though the shim had not seen it at all.
# Hook the type but arm no rule: this is about accounting, not injection.
rm -f "$STATS"
arm '{"seq":40,"hook":["route_entry"],"rules":{}}'
run yes published 3
reached=$(sed -n 's/^reached.route_create=//p' "$WORK/out")
published=$(sed -n 's/^published.route_create=//p' "$WORK/out")
if [ "$published" = "$reached" ]; then
    ok "after $reached creates the file already says $published"
else
    fail "the vendor saw $reached creates but the file published $published"
fi

echo
printf '%d passed, %d failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
