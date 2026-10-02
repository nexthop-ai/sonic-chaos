# The SAI shim

Delay, fail or drop SAI calls underneath syncd, so a test can ask what orchagent does when the
ASIC misbehaves.

```
pytest ... --chaos sai=vlan_member:remove:status=SAI_STATUS_ITEM_NOT_FOUND:count=1
pytest ... --chaos sai=route_entry:create:delay=2000
pytest ... --chaos sai=mode=freeze
```

The Python side is `../injectors/sai.py`. This directory is the C half.

## Build

```
./build.sh
```

You should not normally have to. `injectors/sai.py` builds the shim itself the first time it
needs one, because `build/` is not committed and nobody should meet a build step in the middle
of a test run. Run `build.sh` by hand when you want the extras it adds: the ABI gate and the
test suite.

Needs a C compiler and nothing else — no SAI headers, no sonic-buildimage. It builds
`build/sonic_chaos_sai.so`, checks the result can actually load in a syncd container, and runs
the test suite. `build/` is not committed.

The ABI check is the point of the script. A `.so` linked against a newer glibc than the
container has does not fail loudly: the loader prints a warning nobody reads, syncd comes up
with no shim, and the run silently proves nothing. `build.sh` refuses to ship such a binary.
If you are on a host newer than the target, build in a container instead:

```
SONIC_CHAOS_BUILD_IMAGE=debian:bookworm ./build.sh
```

Before the first DUT, also run the deployment test. It does in a Debian container what
`injectors/sai.py` does in the syncd container -- installs the shim, proves it loads on that
glibc, arms and disarms through the control file, and uninstalls:

```
./test/run_container_test.sh            # or: ./test/run_container_test.sh debian:trixie
```

On a claimed testbed, a site's own staging script runs the same ladder against real syncd and a
real vendor libsai, stopping short of the restart unless told otherwise. A site package ships
it as, for example, `validate_shim_on_dut.sh`:

```
validate_shim_on_dut.sh <testbed>              # install and probe only, nothing disrupted
validate_shim_on_dut.sh <testbed> --restart    # the rest, including one syncd restart
validate_shim_on_dut.sh <testbed> --uninstall  # put the box back as found
```

## How it attaches

syncd does not call SAI through named symbols that could simply be overridden. It calls
`sai_api_query(api, &table)` once per API at start-up, keeps the returned pointer, and calls
through the function pointers inside it forever after.

1. `LD_PRELOAD` on syncd's supervisord entry puts our `sai_api_query` ahead of the vendor's.
2. We call the real one via `dlsym(RTLD_NEXT, ...)` and get the vendor's table.
3. We overwrite selected slots with trampolines, remembering the originals.
4. Each trampoline reads the control file, then delays, returns a chosen status, drops, or
   calls the original.

Because the patch lands in the table rather than behind a flag, **arming and disarming
afterwards are just writes to a file**. The shim notices within 250 ms. Only the *first* use of
an object type needs a syncd restart, and `injectors/sai.py` works out whether it needs one by
asking the shim what it already hooked.

### One trampoline shape for every entry point

A trampoline cannot know the signature of the function it stands in for, and there are
hundreds. It does not need to. Every SAI entry point takes at most eight integer or pointer
arguments and returns `sai_status_t` — no floats, nothing by value. Under the SysV AMD64 ABI a
function declared with eight pointer arguments forwards all of them unchanged, and a callee
taking fewer ignores the rest. `test/` proves this against functions taking one, three, six and
seven arguments, the last of which is passed on the stack.

### Where the slot numbers come from

`hs_tags.h` is generated from the SAI headers by `gen_tags.py`, because in every API struct the
four operations of one object type are four consecutive members (`create_X`, `remove_X`,
`set_X_attribute`, `get_X_attribute`) and the bulk pair is `create_<plural>` /
`remove_<plural>`. Reading them beats hand-maintaining 756 offsets and getting one wrong.

Re-run after a SAI bump — it writes both the C table and `../sai_catalog.py`, which is what
lets `--chaos sai=...` reject a typo before any DUT is touched:

```
./gen_tags.py --sai-inc /path/to/sonic-buildimage/src/sonic-sairedis/SAI/inc
```

## Files

| File | What |
|---|---|
| `sonic_chaos_sai.c` | the interposer: trampolines, patching, control reload, stats |
| `hs_json.c/.h` | a strict reader for the control file's JSON subset (no libc extras) |
| `hs_tags.h` | generated: object type to API and slot numbers, plus the trampoline list |
| `gen_tags.py` | the generator, for `hs_tags.h` and `../sai_catalog.py` |
| `build.sh` | build, ABI gate, tests |
| `test/run_tests.sh` | a fake libsai and a stand-in syncd: the whole mechanism, proven on a laptop |
| `test/run_container_test.sh` | the deployment half, proven in a Debian container (needs docker) |
| `validate_shim_on_dut.sh` (site package) | the same staged against a real switch, disruptive step last |

## On the box

Everything lives in `/sonic-chaos/` inside the syncd container. The shim is loaded by an
`environment=LD_PRELOAD=...` line added to `[program:syncd]` in the container's
`/etc/supervisor/conf.d/supervisord.conf`, with the original kept alongside as
`supervisord.conf.sonic-chaos-bak` for uninstall to restore.

| Path | What |
|---|---|
| `/sonic-chaos/sonic_chaos_sai.so` | the shim |
| `/sonic-chaos/sai_control.json` | what is armed. Written by `injectors/sai.py`, re-read on change |
| `/sonic-chaos/sai_stats.json` | what the shim hooked and how often each rule was hit |

Control file, if you ever need to write one by hand:

```json
{
  "seq": 1,
  "hook": ["vlan_member"],
  "rules": {
    "vlan_member": {
      "remove": {"delay_ms": 0, "status": -7, "drop": false, "count": 1}
    }
  }
}
```

`hook` lists the object types to patch, and a rule implies its own type. `"*"` works for both
the object type and the operation. Deleting the file disarms everything.

## What a given object type can actually be told to do

Not every operation exists for every type, and `injectors/sai.py` refuses the combinations that
would arm a rule with nothing behind it.

| | |
|---|---|
| `create` `remove` `set` `get` | all 126 types, by construction: the generator only emits a type when all four sit together |
| `bulk_create` `bulk_remove` | **20 types only.** On the other 106 there is no bulk entry point to patch, so the rule would arm, nothing would hook, `matched` would stay 0, and the run would report that the system held under a fault that was never applied |
| `drop` | safe exactly when the call hands nothing back: always for `remove` and `set`; for `create` only on the 10 entry-style types, whose create takes no output parameter |

That last row is worth knowing for a different reason. `sai=route_entry:create:drop=true` is
"the ASIC accepted every route and installed none" -- APPL_DB fills up, ASIC_DB does not, and
the oracle's route invariant sees the gap. It is the cleanest divergence the two databases can
be made to show.

The shim logs to syslog under syncd's own identity, and SONiC sends container logs to
rsyslog, so on a DUT:

```
grep sonic_chaos /var/log/syslog
```
```
syncd#syncd: sonic_chaos: hooked 6 entry point(s) in SAI API 6 (6 total)
syncd#syncd: sonic_chaos: control seq 2 applied: 1 rule(s) from /sonic-chaos/sai_control.json
syncd#syncd: sonic_chaos: delaying route_entry create by 5 ms
syncd#syncd: sonic_chaos: control file /sonic-chaos/sai_control.json removed, disarmed
```

## Validated on hardware

a lab switch, `master.1208586`, syncd container Debian 13 / glibc 2.41, vendor
`/usr/lib/libsai.so.1.0`, 51218 routes and 5 BGP neighbours live throughout.

| What | Result |
|---|---|
| Loads on the real container glibc | yes (built needing 2.34) |
| Hooks the real Broadcom table | `"hooks":6, "hooked":["route_entry"]` |
| Sees real traffic with nothing armed | 102,437 `create_route_entry` calls counted, `matched:0` |
| Injects when armed | 5 ms delay, `matched:3 injected:3 remaining:17` of a `count:20` budget |
| Arms and disarms with no restart | control-file write, then removal; `matched` froze while `calls` kept climbing |
| Box afterwards | 51218 routes, 17 containers, no new cores |

A later run on a lab switch found the one bug hardware was always going to find and a laptop never
would. The counters are flushed from inside the call path, and the flush ran *before* the
increment, so every count published excluded the very call that triggered the write. During
start-up, when syncd programs a hundred thousand routes, nobody notices being one behind. On a
settled switch it is the whole signal: add a single route and the file does not move, so the
shim looks as though it missed the call entirely. Test 14 covers it.

One thing the box taught us: `systemctl restart syncd` on its own is not survivable here.
Stopping syncd takes swss out with it and systemd brings neither back, so the switch sits with
no data plane until `config reload`. Restart **swss** instead, which bounces the pair cleanly —
`injectors/sai.py` and the site staging script both do.

## Why it only patches what you ask for

`hs_tags.h` knows 126 object types, but the shim patches only the ones the control file names.
The generated table comes from the SAI headers in this tree, and the vendor library may have
been built against an older SAI whose API structs are shorter. syncd would not notice — it
never calls the members added since — but writing a trampoline into a slot past the end of the
vendor's struct would corrupt whatever sits after it. Patching only what was asked for keeps us
inside the long-settled head of each struct.

The cost is that arming a *new* object type needs a syncd restart. That is deliberate, and
`injectors/sai.py` restarts only when the shim reports the type is not already hooked.

## Safety

* **One program, not the whole container.** The shim rides syncd's supervisord entry rather
  than `/etc/ld.so.preload`, so `docker exec`, the other supervisord children and anything
  else in the container never load it.
* **No constructor.** Even so, nothing happens at load time: all state is statically
  initialised and the first work happens inside `sai_api_query`. A process that never calls
  it never runs a line of the shim.
* **Loading is proved before it is enabled.** `injectors/sai.py` runs `LD_PRELOAD=... /bin/true`
  in the container and refuses to edit supervisord's config unless it comes back clean.
* **A bad control file disarms** rather than acting on a half-parsed rule.
* **Dead-man timer.** Every apply arms a detached timer on the DUT that removes the control
  file, so a test that dies without releasing does not leave a switch injecting faults.
* **`drop` is refused for `create` and `get`**, whose output parameters would be left unwritten.
* **Release does not uninstall.** An unarmed shim is a direct call through, and removing it
  costs another syncd restart. Call `SaiInjector.uninstall(duthost)` when you are done with a
  testbed and want it handed back as found.

The restart itself is the sharp edge. On a real ASIC it re-initialises the chip, and orchagent
hits its sairedis timeout on the way — which is the DNX cold-restart path. Do first-arm runs on a
reserved box, and prefer `mode=freeze` when you only need "SAI stopped answering".

---

# The spin interposer

Peg a daemon's event loop at 100% CPU while it services nothing — the *live-lock* shape.

```
pytest ... --chaos spin=orchagent:95
```

The Python side is `../injectors/spin.py`. `sonic_chaos_spin.c` is the C half, and it shares
`hs_json.c` and the installer (`../preload.py`) with the SAI shim.

## Why it is not `cpu` or `hog` or `pause`

| | orchagent CPU | its event loop | other orchs |
|---|---|---|---|
| `cpu=orchagent:3` (cap) | 1–3% | running, slowly | **all serviced**, just slower |
| `hog=swss:cpu=90` | low | running | all serviced |
| `pause=orchagent:10` (SIGSTOP) | **0%** | stopped dead | none serviced |
| `spin=orchagent:95` | **100%** | stuck inside one call | **none serviced** |

The bottom row is RouteOrch-livelock and an RFC5549 case. orchagent dispatches every orch from a
single `m_select->select()` loop (`orchdaemon.cpp:1276`), so a stuck handler starves PortOrch,
NeighOrch, FdbOrch and CoppOrch too. A test asserting "a LAG member change is still processed
while routes churn" *passes* under a cap and *fails* under the real bug — so a cap is not a
weaker version of this fault, it is a different one.

## How it attaches

`swss::Select::select()` bottoms out at `::epoll_wait()` (`sonic-swss-common/common/select.cpp:100`),
a plain C symbol. The interposer busy-spins for part of every 100 ms period, then forwards with
the timeout clamped to what is left. Gated on `gettid() == getpid()`: orchagent has other threads
that reach `epoll_wait`, and spinning one of those would be a different fault wearing this name.

## 1..99 starves, 100 stalls

Below 100 the call still forwards, so the caller rounds its loop ~10x a second. That is a severe
slowdown, **not** a stall — a daemon that pops a batch per dispatch still makes progress, and on
a lab switch a VLAN add landed within a second or two at 99%. Measured with the stand-in: 99% left the
loop turning 31 times in three seconds, 100% left it turning **zero**.

At 100 the call never forwards, so the loop does not turn and nothing is serviced at all. The
cost is that orchagent only checks `gOrchShutdownRequested` *after* select returns, so while this
is armed it cannot see a shutdown request and supervisord falls back to SIGKILL. Release does not
need that — the spin re-reads the control file every 250 ms and rejoins the normal path on its
own, proven by test 10.

## Wired into the launcher, not supervisord

The swss container's `/usr/bin/docker-init.sh` re-renders
`/etc/supervisor/conf.d/supervisord.conf` from a j2 template on **every** container start. An
`environment=LD_PRELOAD=` line there is wiped by the very restart meant to activate it: it looks
installed, comes back absent, and the run silently proves nothing. Found on a lab switch.

`/usr/bin/orchagent.sh` is not in that render list and ends in `exec`, so the export goes there
instead. That also makes activation far cheaper — `supervisorctl restart orchagent` re-execs the
script and picks it up **without bouncing the container**, so no ASIC re-initialisation and no
systemd. (The syncd container does not template its supervisord.conf, which is why the SAI shim
still uses the `environment=` route.)

## Validated on hardware

a lab switch, 16 cores, swss container Debian 13 / glibc 2.41 (the .so needs 2.34).

| What | Result |
|---|---|
| Loads into the real orchagent | yes, `mapped=5`, container never stopped |
| Costs nothing when disarmed | 0.1% over three windows, `cycles:0` |
| Arms | **0.0% → 98.1%** on a settled orchagent |
| Starves a non-route consumer | `config vlan add` reached CONFIG_DB; ASIC_DB VLAN count did **not** move in 20 s |
| Stalls totally at 100 | 5,000 routes in zebra + a VLAN queued, **asic +0, vlans +0** over 30 s at 100.7% CPU |
| Disarms | **98.1% → 0.2% → 0.0%**, control file removed, `percent:0` |
| Uninstall | launcher unwired, `.so` gone, orchagent back to 0.0%, 0 cores |

### Restart the container, not the daemon

`supervisorctl restart orchagent` is tempting — it loads the interposer without bouncing the
container — and it works on a settled, near-empty box. On a lab switch with real state it left
orchagent pegged at 100% and silent in syslog for minutes with ASIC_DB shrinking under it, and it
never settled: restarting orchagent while syncd keeps its view means orchagent comes up empty and
reconciles against it. `systemctl restart <container>` bounces syncd too, so both cold-start and
there is nothing to reconcile. That costs an ASIC re-init, once per box.

### Do not arm into a restart

The first run armed immediately after restarting orchagent and produced the lane's worst
measurement: the fault landed on top of orchagent's post-restart view rebuild, so the 100%
reading could not be attributed to the fault, and **lifting the fault did not bring orchagent
back** — it sat at 100%, with the VLAN still unprogrammed, until it was restarted again.

The interposer was provably innocent (control file gone, stats `percent:0`, `cycles` frozen), and
the same fault on a *settled* orchagent released cleanly. `apply()` now waits for the daemon to
drop below 20% CPU before arming, and fails loudly rather than arming into a rebuild.

## Two things a 100% stall did to a real orchagent

Both found on a lab switch, both worth knowing before you write a test against this.

**It can abort orchagent — observed once.** During a ~80 s hold at 100%, orchagent died with

    ERR orchagent: waitForGetResponse: logic error, get response returned 0 values!
    terminate called after throwing an instance of 'std::runtime_error'   (signal 6)

and left a core: a stalled loop never reads the sairedis synchronous GET response in time, so
sairedis throws and orchagent aborts.

Do not read a threshold into that. It is **n=1**, and two things argue against generalising it:
a 95% hold of the *same* length (82.65 s) did not crash, and that 100% run predates the change
that made 100 a true total stall — at the time it still forwarded with a 0 ms timeout, so the
loop was turning roughly as it does at 99 today. A 30 s hold on the current build did not abort
it. The honest guidance is that a long hold *can* end in an abort, which trips `no_cores` and
restarts the daemon under your test, so check `/var/core` after one.

**It can produce a lost wakeup.** After a 30 s stall was released, orchagent sat at **0.2% CPU
with 5,000 route entries still queued in APPL_DB** and programmed none of them. No error, no
crash, no CPU — just a daemon that had stopped consuming work it could see. It stayed that way
until one unrelated route arrived, at which point all 5,002 objects programmed at once.

The observation is solid; the mechanism is a hypothesis — the consumer side is woken by a redis
keyspace notification, and a stall long enough to lose or coalesce that edge leaves the work
sitting in the KEY_SET with nothing to nudge it. This is the failure mode worth hunting: not the
crash, which is loud, but the silent stop that looks healthy on every dashboard.

## What it does not reproduce

The retry set growing, the O(K²) cost, the memory growth, or the fact that the real live-lock
never recovers. This one disarms in 250 ms. It reproduces the *state*, not the root cause: right
for "what breaks downstream when orchagent live-locks", wrong for "does the RouteOrch fix work".
