#!/bin/bash
# Prove the *deployment* half of the shim lane, in a container, on a laptop.
#
# test/run_tests.sh proves the interposition logic. This proves the part that actually bites
# on a switch: that the binary loads on the container's glibc, that the supervisord edit lands
# in the right section and reverses cleanly, and that arming and disarming work through a file
# rather than an environment variable.
#
#   ./test/run_container_test.sh [image]        default: debian:bookworm
#
# Not run by `make test` -- it needs docker. Run it after a build, before the first DUT.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
BUILD="${BUILD:-$ROOT/build}"
IMAGE="${1:-debian:bookworm}"

for artefact in sonic_chaos_sai.so libfakesai.so fakesyncd; do
    [ -f "$BUILD/$artefact" ] || { echo "missing $BUILD/$artefact -- run make test first"; exit 1; }
done

command -v docker >/dev/null || { echo "no docker; skipping"; exit 0; }

echo "deploying into $IMAGE the way injectors/sai.py deploys into the syncd container"

docker run --rm -i -v "$BUILD:/in:ro" "$IMAGE" bash -s <<'INSIDE'
set -u
passed=0; failed=0
ok()   { echo "  ok   $1"; passed=$((passed+1)); }
bad()  { echo "  FAIL $1"; failed=$((failed+1)); }

echo "  container glibc $(ldd --version | head -1 | grep -o '[0-9]\+\.[0-9]\+$')"
mkdir -p /sonic-chaos
cp /in/sonic_chaos_sai.so /in/libfakesai.so /in/fakesyncd /sonic-chaos/
chmod 0755 /sonic-chaos/sonic_chaos_sai.so

# 1. The probe injectors/sai.py runs before it edits anything. A shim built against too new a
#    glibc fails here as a loader warning -- which is exactly why we look.
out=$(LD_PRELOAD=/sonic-chaos/sonic_chaos_sai.so /bin/true 2>&1); rc=$?
if [ $rc -eq 0 ] && [ -z "$out" ]; then ok "loads cleanly on this glibc"
else bad "probe: rc=$rc out='$out'"; fi

# 2. The supervisord edit: same sed injectors/sai.py ships, against the real file shape.
CONF=/etc/supervisor/conf.d/supervisord.conf
BAK=$CONF.sonic-chaos-bak
mkdir -p "$(dirname $CONF)"
cat > $CONF <<'CONF_EOF'
[supervisord]
logfile_maxbytes=1MB

[program:rsyslogd]
command=/usr/sbin/rsyslogd -n
priority=1

[program:syncd]
command=/usr/bin/syncd_start.sh
priority=3
autostart=false
CONF_EOF

[ -f $BAK ] || cp $CONF $BAK
sed -i '/^\[program:syncd\]$/a environment=LD_PRELOAD="/sonic-chaos/sonic_chaos_sai.so"' $CONF

if sed -n '/^\[program:syncd\]$/,/^\[/p' $CONF | grep -q 'LD_PRELOAD=.*sonic_chaos_sai'; then
    ok "preload line landed inside [program:syncd]"
else
    bad "preload line is not in the syncd section"; cat $CONF
fi
if sed -n '/^\[program:rsyslogd\]$/,/^\[program:syncd\]$/p' $CONF | grep -q 'LD_PRELOAD'; then
    bad "the edit leaked into another program's section"
else
    ok "no other program picked up a preload"
fi

# 3. Only a process that reaches sai_api_query should leave anything behind.
if [ -f /sonic-chaos/sai_stats.json ]; then bad "an unrelated process wrote a stats file"
else ok "processes that never call SAI leave no trace"; fi

# 4. The real thing, loaded the way supervisord loads it and armed through the file.
cat > /sonic-chaos/sai_control.json <<'JSON'
{"seq":1,"hook":["vlan_member"],"rules":{"vlan_member":{"remove":{"status":-7}}}}
JSON
cd /sonic-chaos || exit 1
preload=$(sed -n 's/^environment=LD_PRELOAD="\(.*\)"$/\1/p' $CONF)
[ "$preload" = /sonic-chaos/sonic_chaos_sai.so ] \
    && ok "supervisord would preload $preload" || bad "unexpected preload value '$preload'"

env LD_PRELOAD="$preload" LD_LIBRARY_PATH=/sonic-chaos ./fakesyncd basic 2 >/tmp/out 2>/tmp/err

grep -qx "vlan_member_remove.0 rc=-7" /tmp/out \
    && ok "the armed fault reached the caller" || { bad "no fault injected"; cat /tmp/out /tmp/err; }
grep -qx "reached.vlan_member_remove=0" /tmp/out \
    && ok "the vendor was never called" || bad "the vendor was called anyway"
grep -qx "reached.route_create=2" /tmp/out \
    && ok "an object type that was not armed is untouched" || bad "collateral damage"
[ -s /sonic-chaos/sai_stats.json ] \
    && ok "stats published: $(sed 's/.*\("hooked":[^]]*]\).*/\1/' /sonic-chaos/sai_stats.json)" \
    || bad "no stats file"

# 5. Disarming is a file removal, with no restart of anything.
rm -f /sonic-chaos/sai_control.json
env LD_PRELOAD="$preload" LD_LIBRARY_PATH=/sonic-chaos ./fakesyncd basic 1 >/tmp/out2 2>&1
grep -qx "vlan_member_remove.0 rc=0" /tmp/out2 \
    && ok "removing the control file disarms without a restart" || { bad "still armed"; cat /tmp/out2; }

# 6. What SaiInjector.uninstall(duthost) does, and whether the config comes back as found.
[ -f $BAK ] && mv $BAK $CONF || sed -i '/sonic_chaos_sai/d' $CONF
rm -rf /sonic-chaos
if grep -q sonic-chaos $CONF; then bad "uninstall left the config modified"
else ok "uninstall restored supervisord.conf"; fi
grep -q '^\[program:syncd\]$' $CONF && ok "and left the rest of the config intact" \
    || bad "uninstall damaged the config"

echo
printf '  %d passed, %d failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
INSIDE
