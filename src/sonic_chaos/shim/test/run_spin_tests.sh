#!/bin/bash
# Prove the spin interposer on the build host, before it is ever loaded into orchagent.
#
# fakeloop is an epoll loop on two threads: one stands in for orchagent's single dispatch loop,
# the other for the notification threads that must be left alone. Preloading the interposer
# between them is the same thing that happens in the swss container, minus the switch.
#
#   make spin-test     (or)   ./test/run_spin_tests.sh
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
BUILD="${BUILD:-$ROOT/build}"
CC="${CC:-gcc}"
SPIN="$BUILD/sonic_chaos_spin.so"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CONTROL="$WORK/spin_control.json"
STATS="$WORK/spin_stats.json"
export SONIC_CHAOS_SPIN_CONTROL="$CONTROL"
export SONIC_CHAOS_SPIN_STATS="$STATS"

passed=0
failed=0

ok()   { printf '  ok   %s\n' "$1"; passed=$((passed + 1)); }
fail() { printf '  FAIL %s\n' "$1"; failed=$((failed + 1)); sed 's/^/       /' "$WORK/out"; }

arm() { printf '%s' "$1" >"$CONTROL.new" && mv "$CONTROL.new" "$CONTROL"; }

# run <preload:yes|no> <mode> <seconds>
run() {
    if [ "$1" = yes ]; then
        LD_PRELOAD="$SPIN" "$BUILD/fakeloop" "$2" "$3" >"$WORK/out" 2>"$WORK/err"
    else
        "$BUILD/fakeloop" "$2" "$3" >"$WORK/out" 2>"$WORK/err"
    fi
}

field() { sed -n "s/^$1=//p" "$WORK/out"; }
# The shim's own account of itself, from the stats file it writes.
stat_field() { grep -oE "\"$1\":[0-9]+" "$STATS" 2>/dev/null | grep -oE '[0-9]+$'; }

# at_least <description> <field> <floor>
at_least() {
    local got; got=$(field "$2")
    if [ "${got:-0}" -ge "$3" ]; then ok "$1 ($2=$got)"; else fail "$1 (wanted $2 >= $3, got ${got:-none})"; fi
}

at_most() {
    local got; got=$(field "$2")
    if [ "${got:-999999999}" -le "$3" ]; then ok "$1 ($2=$got)"; else fail "$1 (wanted $2 <= $3, got ${got:-none})"; fi
}

echo "building the stand-in daemon"
mkdir -p "$BUILD"
$CC -O1 -g -std=gnu11 -Wall -Wextra -Werror -o "$BUILD/fakeloop" "$HERE/fakeloop.c" -lpthread || exit 1
[ -f "$SPIN" ] || { echo "no $SPIN -- run make first"; exit 1; }

echo
echo "1. without the interposer, an idle daemon costs nothing"
rm -f "$CONTROL" "$STATS"
run no idle 2
at_most "main thread is idle" main_cpu_pct 5
at_most "worker thread is idle" worker_cpu_pct 5

echo
echo "2. interposer loaded, nothing armed: still a straight pass-through"
rm -f "$CONTROL" "$STATS"
run yes idle 2
at_most "main thread is still idle" main_cpu_pct 5
if [ -s "$WORK/err" ]; then fail "wrote to stderr: $(head -1 "$WORK/err")"; else ok "silent on stderr"; fi

echo
echo "3. armed: the main thread burns CPU while doing nothing (the live-lock signature)"
arm '{"seq":1,"percent":90}'
run yes idle 3
at_least "main thread is pegged" main_cpu_pct 80
at_most "main thread is not over-spun" main_cpu_pct 99

echo
echo "4. the other threads are left alone"
at_most "worker thread untouched" worker_cpu_pct 5
at_least "worker thread still turning" worker_iterations 2

echo
echo "5. at 100 a daemon with a backlog stops draining it"
# The point of the whole injector: CPU reads 100% either way, so only throughput tells the
# difference between "busy and productive" and "live-locked". This is the stall, so it is
# measured at 100: below that the daemon keeps its share of every period and drains in bursts,
# which is what section 5b checks.
rm -f "$CONTROL" "$STATS"
run no ready 2
free=$(field main_iterations)
arm '{"seq":2,"percent":100}'
run yes ready 2
held=$(field main_iterations)
if [ "$held" -lt $((free / 1000)) ]; then
    ok "throughput collapsed from $free to $held"
else
    fail "expected a collapse, went from $free to $held"
fi
at_least "and it still looks busy" main_cpu_pct 90

echo
echo "5b. below 100 the share holds under load, not only when idle"
# The regression this guards. The burn used to be charged to every epoll_wait call, which is
# only the requested share while each call then waits out the rest of its period. A daemon with
# a backlog never waits, so it burned back to back: on a lab switch a requested 70 ran at 93%, and
# here 70 read as 100% with more bursts than there were periods. main_cpu_pct cannot show this
# -- a ready loop reads 100% with or without the shim -- so the shim's own spun_ms and cycles
# are what is checked.
rm -f "$CONTROL" "$STATS"
arm '{"seq":20,"percent":50}'
run yes ready 3
spun=$(stat_field spun_ms)
cycles=$(stat_field cycles)
share=$(( ${spun:-0} * 100 / 3000 ))
if [ "$share" -ge 45 ] && [ "$share" -le 58 ]; then
    ok "burn share holds at 50 under load (${share}%)"
else
    fail "burn share at 50 under load was ${share}%, wanted 45-58"
fi
if [ "${cycles:-999}" -le 32 ]; then
    ok "at most one burst per 100 ms period (${cycles} bursts in 30 periods)"
else
    fail "${cycles:-none} bursts in 30 periods: the burn is being charged per call again"
fi
at_least "and the daemon keeps draining its share" main_iterations 1000

echo
echo "6. rearming mid-run needs no restart"
arm '{"seq":3,"percent":10}'
( sleep 1; arm '{"seq":4,"percent":90}' ) &
run yes idle 3
wait
seq=$(sed -n 's/.*"seq":\([0-9]*\).*/\1/p' "$STATS")
if [ "$seq" = "4" ]; then ok "picked up the rewritten control file (seq=$seq)"; else fail "stats still at seq=$seq"; fi

echo
echo "7. removing the control file disarms, mid-run"
arm '{"seq":5,"percent":90}'
( sleep 1; rm -f "$CONTROL" ) &
run yes idle 3
wait
pct=$(sed -n 's/.*"percent":\([0-9]*\).*/\1/p' "$STATS")
if [ "$pct" = "0" ]; then ok "disarmed without a restart"; else fail "still armed at $pct%"; fi
at_most "so most of the run was free" main_cpu_pct 60

echo
echo "8. an unparseable control file disarms instead of guessing"
rm -f "$STATS"
arm '{"seq":6,"percent":'
run yes idle 2
at_most "fell back to pass-through" main_cpu_pct 5

echo
echo "9. 100 is a total stall: the loop does not turn at all"
# The distinction the injector exists for. Below 100 the caller still rounds its loop ~10x a
# second, which starves but does not stop it.
rm -f "$CONTROL" "$STATS"
arm '{"seq":7,"percent":99}'
run yes ready 3
starved=$(field main_iterations)
arm '{"seq":8,"percent":100}'
run yes ready 3
stalled=$(field main_iterations)
if [ "$starved" -gt 5 ]; then ok "99% still turns the loop ($starved iterations)"; else fail "99% should still turn ($starved)"; fi
if [ "$stalled" -le 1 ]; then ok "100% does not ($stalled iterations)"; else fail "100% should not turn, got $stalled"; fi

echo
echo "10. release still lands from inside a total stall, with no signal"
arm '{"seq":9,"percent":100}'
( sleep 1; rm -f "$CONTROL" ) &
run yes ready 4
wait
freed=$(field main_iterations)
if [ "$freed" -gt 100 ]; then ok "rejoined the normal path on its own ($freed iterations)"; else fail "still stalled after disarm ($freed)"; fi

echo
printf '%d passed, %d failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
