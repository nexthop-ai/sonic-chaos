# sonic-chaos in sonic-mgmt

sonic-chaos runs a fault under any existing sonic-mgmt test: pick a daemon, pick a fault, run the
suite, and read which verdicts flip. This folder is everything sonic-mgmt needs, in the shape of
the change an upstream PR would make:

| path | what |
|---|---|
| `tests/common/plugins/sonic_chaos/__init__.py` | the adapter: loads the plugin from the installed `sonic-chaos` package |
| `sonic-mgmt.patch` | the whole change as one patch: the adapter, one `pytest_plugins` line, one example test |

The plugin itself stays in the `sonic-chaos` package, pip-installed into docker-sonic-mgmt the way
`ptf` is, so the sonic-mgmt tree carries no copy that could drift from it.

## Setting it up

```sh
pip install sonic-chaos                    # in the sonic-mgmt container; or pip install -e <this repo>/lib
cd <sonic-mgmt>
git apply <this repo>/integration/sonic-mgmt/sonic-mgmt.patch
```

The patch was checked with `git apply --check` against sonic-mgmt master. It:

- adds `tests/common/plugins/sonic_chaos/__init__.py`,
- lists `tests.common.plugins.sonic_chaos` in `tests/conftest.py`'s `pytest_plugins`,
- adds `test_port_toggle_orchagent_busy` to `tests/platform_tests/test_port_toggle.py`: the
  existing port-toggle test, unchanged, with orchagent held at 70% CPU for its duration by one
  marker.

**Registering it costs nothing.** With no `--chaos*` option and no `chaos` marker the plugin
requests no fixture and runs no command. If `sonic-chaos` is not installed, ordinary runs are
unaffected as well: the options still parse, tests marked `chaos` are skipped, and only a run that
passes `--chaos` stops, with the install hint.

## Running it

```sh
./run_tests.sh -n vms-t1 -c platform_tests/test_port_toggle.py -e "--log-cli-level=info"
./run_tests.sh -n vms-t1 -c bgp/test_bgp_fact.py -e "--chaos kill=bgpd --chaos-oracle parity,health"
./run_tests.sh -n vms-t1 -c ... -e "--chaos-file orchagent-restart --chaos-seed 20260911"
```

`--log-cli-level=info` surfaces the plugin's own `[chaos]` lines. A green test does not prove a
fault was applied; those lines do, and so does the verdict each test gets: **HELD** (the fault
engaged and the switch held), **BROKE** (an invariant diverged or recovery missed its budget) or
**INCONCLUSIVE** (the fault never engaged -- the pass proves nothing; `--chaos-strict` fails it).

What a run looks like:

```
[chaos] apply spin(container=swss,percent=70,process=orchagent,ttl=600) on <dut>
[spin] restarting swss on <dut> to load the interposer into orchagent (...)   <- first run only
[chaos] dead-man spin-orchagent armed on <dut>: fires in 600s
Toggling ports: [...]                                                          <- test body
[chaos] measured: ... achieved={'percent': 70, 'cycles': ..., 'spun_ms': ...}
[chaos] release spin(...) on <dut>
```

## Adding a fault to any test

One extra fault for one test, applied before its body and released after:

```python
@pytest.mark.chaos("spin", "orchagent:70:ttl=600")
def test_something(...):
    ...

from sonic_chaos import fault

@fault("kill=orchagent:how=restart")          # the same marker, from the library
def test_something_else(...):
    ...
```

A fault at an exact point in the test, and an oracle check as one assert:

```python
def test_something(chaos, ...):
    with chaos.pause("orchagent", seconds=30):
        ...                                    # runs with orchagent frozen
    chaos.assert_recovers(within=90)
```

Or no code change at all -- any existing test, session-wide: `-e "--chaos spin=orchagent:70"`.

`ttl` is the switch-side safety net if the harness dies mid-test, not the hold time. It only has to
outlast the test.

## Things to know before running it on a shared testbed

- **The first `spin` or `sai` on a box restarts all of swss**, not only orchagent: that takes
  syncd with it, re-initialises the ASIC, and spends one of systemd's swss starts. It happens once
  per box; the interposer stays loaded, disarmed, afterwards. Three swss starts in twenty minutes
  lock the box, and the plugin refuses to arm a box that is already at that limit.
- **`kill` of any daemon swss lists as critical restarts the whole container.** Give recovery a
  budget that fits the box: a switch with ~100k routes needs minutes after a swss restart before
  `route_check` is clean (`--chaos-recover`, or `contract.recover_within` in an experiment).
- The `sai` and `spin` shims are built from C sources on first use (`sonic-chaos shim build`
  builds them ahead of time). The sonic-mgmt container has gcc; the build refuses a binary that
  needs a newer glibc than the switch's containers.
