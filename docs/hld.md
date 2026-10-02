# sonic-chaos: fault injection for sonic-mgmt — High Level Design

| | |
|---|---|
| Status | Draft, for review before any upstream PR |
| Scope | sonic-mgmt test infrastructure; no change to any SONiC image |
| Package | `sonic-chaos` (import `sonic_chaos`), Apache-2.0 |

## 1. Problem

sonic-mgmt tests prove a switch works on a quiet box. Production is not quiet: orchagent is busy
when a port flaps, syncd answers slowly, a daemon restarts mid-operation, a table fills. Many of
the bugs that reach the field need two things at once: a normal operation, and something going
wrong underneath it. Today a test author who wants that writes one-off shell against the DUT,
and most tests never get it.

A fault-injection tool is only worth running if it can tell three outcomes apart, and most cannot:

1. the fault landed and the switch held,
2. the fault landed and the switch broke,
3. **the fault never landed**, so the pass proves nothing.

A CPU cap on an idle daemon, a SAI error on an object type nothing creates, a freeze of a process
that was never running: each passes, and each is outcome 3 reported as outcome 1.

## 2. Goals and non-goals

Goals:

- Run any existing sonic-mgmt test under a fault with no code change (`--chaos <fault>`), or add
  one fault to one test with a marker.
- Grade every test under fault as HELD, BROKE or INCONCLUSIVE.
- After every fault, check the switch agrees with itself (APPL_DB vs ASIC_DB vs FRR, daemon
  health) within a recovery budget, and report only divergences that were not already present.
- Put the switch back on every exit path, including a harness that dies mid-test.
- Cost nothing when not asked for: no fixture requested, no command run.
- Usable outside sonic-mgmt: a library, a CLI, and a generic pytest plugin.

Non-goals: traffic generation (sonic-chaos drives the control plane and the ASIC interface; traffic
remains PTF's job), changes to any SONiC daemon or image, fault injection in production.

## 3. Architecture

```
 entry points     sonic-chaos CLI · Python API (Chaos, @fault) · pytest plugin · sonic-mgmt adapter · console
      |
 engine           Runner: preflight -> gate -> apply -> settle -> measure -> check -> release -> recover -> report
      |           Experiment (seeded schedule) · Session (LIFO release) · verdicts, repro bundles
 catalogue        injectors (12) · invariants (11, grouped) · target profiles · spec grammar
      |           all extensible through entry points
 transport        one duck type: duthost.shell / .copy / .hostname
      |           (a sonic-mgmt duthost as-is, or SshDut / CommandDut / LocalDut)
 on the switch    a stdlib-only agent (cgroups, dead-man timers) · two LD_PRELOAD shims · stock tools
```

No layer imports a layer above it: the engine does not import pytest, and injectors never know how
their commands reach the switch.

### 3.1 In sonic-mgmt

sonic-mgmt gains one module, `tests/common/plugins/sonic_chaos/__init__.py`, listed in
`tests/conftest.py`'s `pytest_plugins`. It loads the plugin from the installed package; the package
is pip-installed into docker-sonic-mgmt the way `ptf` is. If the package is missing, ordinary runs
are unaffected, marked tests are skipped, and only a run that asks for a fault stops with an
install hint.

The plugin uses sonic-mgmt's `duthosts`, requests `sanity_check` so faults go in after pre-test
sanity and come out before post-test sanity, and adds each fault's own expected syslog (for
example supervisor's exit messages after a kill) to `loganalyzer`'s ignore list. Nothing else is
ignored: a daemon's complaint about a fault is the finding.

## 4. Faults

| lane | injector | what it does to the switch |
|---|---|---|
| lifecycle | `kill` | `kill -9`, `supervisorctl restart` or `docker restart`, then waits for recovery; judges a container restart by `StartedAt`, stops at systemd's start limit |
| | `pause` | SIGSTOP/SIGCONT or `docker pause`, with a switch-side timer that thaws it anyway |
| | `corrupt` | overwrites a DB field, restores every field exactly on release |
| | `redis` | severs one daemon's redis connections, or `DEBUG SLEEP`s the bus |
| | `syslog` | floods the logging path from a daemon's container, with a disk guard |
| ASIC interface | `sai` | delays, fails or drops chosen SAI calls inside syncd (LD_PRELOAD on `sai_api_query`) |
| | `spin` | holds a daemon's event loop at N% per 100 ms period (LD_PRELOAD on `epoll_wait`/`poll`) |
| resources | `cpu` | a cgroup v2 `cpu.max` ceiling, per daemon or per container |
| | `mem` | `docker update --memory`, fixed or ramped, with a did-it-recover verdict |
| | `hog` | bounds a container's CPU and spends it from inside, so it really reads N% |
| tables | `exhaust` | fills a CRM table past its limit and back, and asserts CRM returns to baseline |
| | `storm` | flaps a LAG member to flood netlink, and asserts neighbours re-resolve |

Every injector validates its spec before any switch is touched, reports what it measured
(`status()`), says whether it engaged (`fired()`), and releases idempotently. A spec is one string:
`kill=orchagent:how=restart`, `sai=route_entry:create:delay=2000`.

## 5. The oracle

Invariants read a snapshot (APPL_DB, ASIC_DB, STATE_DB, COUNTERS_DB name maps) or ask the switch
directly, and return divergences. Three groups:

- **parity** — LAG, LAG member, neighbour, VLAN and VLAN member agree across APPL_DB and ASIC_DB;
  `route_check.py` agrees with FRR.
- **health** — critical processes running, no systemd start-limit hit, no core files, BGP peers
  Established (read through vtysh, so it works whether or not bgpmon runs).
- **signal** — `*_KEY_SET` backlogs that never drain.

A check that cannot run (a map absent on this platform) reports *unchecked*, never pass. The
steady state before the first fault is the baseline: what was already wrong is not a finding.

## 6. Verdicts and evidence

| verdict | meaning | pytest | CLI exit |
|---|---|---|---|
| HELD | the fault engaged and every invariant held | pass | 0 |
| BROKE | an invariant diverged or recovery missed its budget | fail | 1 |
| INCONCLUSIVE | no fault engaged | pass with a warning; fail with `--chaos-strict` | 5 |
| INVALID | the steady-state gate failed before any fault | — | 3 |
| (release failed) | a fault may still be applied; outranks every verdict | error | 6 |

Every failure under fault writes a repro bundle: the exact command to rerun it (with the seed),
the fault recipe, what each fault measured, the syslog window, and the oracle's before/after
snapshots and diff. `--chaos-repeat N` turns one test into N runs and reports "20 runs / 3 FAIL",
which separates an intermittent failure from a deterministic one.

## 7. Safety

- Nothing touches a switch without an explicit fault; `--chaos-dry-run` prints the plan only.
- Protected targets (redis, the database container) are refused unless forced.
- Every fault that holds state arms a switch-side dead-man (a systemd transient timer) before it
  applies, so a killed harness still releases it.
- Arming an interposer that would restart swss is refused on a box already at systemd's start limit.
- Release is LIFO, runs for every applied fault even when one release fails, and runs on
  KeyboardInterrupt and session teardown.

## 8. Configuration

```
--chaos INJECTOR=SPEC     repeatable, held for each module
--chaos-file FILE|NAME    a seeded experiment; one scheduled fault per test, in order
--chaos-seed N            replay a schedule exactly
--chaos-repeat N          run every test N times
--chaos-dry-run           plan only
--chaos-oracle GROUP      parity (default), health, signal, all, none
--chaos-recover SECONDS   recovery budget (default 60)
--chaos-profile FILE|NAME the platform's containers and daemons, over the default profile
--chaos-strict            fail INCONCLUSIVE tests
--chaos-bundle-dir DIR    where repro bundles go (default out/chaos)
@pytest.mark.chaos(injector, spec, **params)
```

Experiment files are YAML (`version: 1`) with a JSON Schema (`sonic-chaos schema`).

## 9. Extensibility

Three entry-point groups let another package add without forking: `sonic_chaos.injectors`,
`sonic_chaos.invariants`, and `sonic_chaos.transports` / `sonic_chaos.profiles` for a lab's own
way into its switches and its platform's container set.

## 10. Testing

- Unit tests with a recording DUT, including pytest-in-pytest tests of the plugin lifecycle.
- Golden transcripts: the exact commands every injector sends, so a refactor that changes what the
  switch sees shows up as a reviewable diff.
- The C shims have their own test suites against a fake libsai and a fake event loop, plus an ABI
  check (only `sai_api_query` exported, glibc floor 2.36).
- A live check that every injector applies, takes effect and is undone on a real switch.

## 11. Upstreaming plan

1. This HLD, reviewed with the sonic-mgmt maintainers.
2. docker-sonic-mgmt installs `sonic-chaos`.
3. sonic-mgmt PR 1: the adapter, the `pytest_plugins` line, docs, one example test.
4. PR 2: experiment files and a periodic run on a KVM testbed.

## 12. Open questions

- Whether the shim lanes (`sai`, `spin`) go in PR 1. The one sonic-mgmt example proven on hardware
  so far uses `spin`.
- The Python floor: tested on 3.11 and 3.12.
