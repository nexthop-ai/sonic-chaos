"""Contract self-check. No DUT, no pytest session, no sonic-mgmt runtime. From anywhere:

    sonic-chaos selftest            (or: python3 -m sonic_chaos.selftest)

Exercises the spec grammar, the registry, plan building and validation, ChaosSession release
semantics, and oracle.diff. Green means the hour-0 contract is intact and lanes may build on it.
Run it before every push.
"""
import base64
import contextlib
import glob
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import tempfile

from .injector import (  # noqa: E402
    REGISTRY, ChaosPlan, ChaosSession, ChaosUsageError, get, split_spec,
    parse_hgetall, parse_supervisor_status, poll, deadman_tag, quote,
)
from .experiment import Experiment  # noqa: E402
from .conditions import parse_conditions  # noqa: E402
from . import bundle  # noqa: E402
from . import injectors  # noqa: F401,E402
from . import oracle  # noqa: E402
from . import invariants  # noqa: E402


class _FakeSyncdDut(object):
    """Enough of a DUT to exercise the shim lane's control file without a switch.

    Only the handful of command shapes injectors/sai.py emits are understood: a base64 write
    into the syncd container, a read back, and a remove. Anything else succeeds silently,
    which is right -- this is here to pin down the merge, not to re-implement docker.
    """

    def __init__(self, hostname="dut-shim"):
        self.hostname = hostname
        self.files = {}

    def shell(self, command, module_ignore_errors=False):
        # The sudo prefix is optional on purpose: under pytest the plugin runs as root and there
        # is none, over ssh it lands as admin and every docker/systemctl call carries one.
        # Modelling only the root shape is how the sai lane passed here while being unusable from
        # the console's default ssh runner.
        write = re.search(
            r"^echo (\S+) \| (?:sudo -n )?docker exec -i \S+ sh -c .*mv \S+ (/\S+?)'", command)
        if write:
            self.files[write.group(2)] = base64.b64decode(write.group(1)).decode("utf-8")
            return {"rc": 0, "stdout": "", "stderr": ""}
        read = re.search(r"cat (/\S+) 2>/dev/null", command)
        if read:
            if read.group(1) not in self.files:
                return {"rc": 1, "stdout": "", "stderr": "No such file"}
            return {"rc": 0, "stdout": self.files[read.group(1)], "stderr": ""}
        remove = re.search(r"rm -f (/\S+?)'", command)
        if remove:
            self.files.pop(remove.group(1), None)
        return {"rc": 0, "stdout": "", "stderr": ""}


def _check_shim_lane():
    """The Shim lane: spec validation, the control document, and the shared-file merge."""
    from .injectors import sai as sai_injector
    from . import sai_catalog

    # The generated catalog and the generated C table must describe the same object types,
    # or a spec would validate here and then find nothing to hook on the box.
    header = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shim", "hs_tags.h")
    with open(header) as fh:
        in_header = set(re.findall(r'^    \{ "([a-z0-9_]+)",', fh.read(), re.M))
    assert in_header == set(sai_catalog.OBJECT_TYPES), \
        "sai_catalog.py and shim/hs_tags.h disagree; re-run shim/gen_tags.py"
    assert "vlan_member" in in_header and "my_sid_entry" in in_header

    # Specs that must fail, every one of them before a DUT is touched.
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:create"])              # no effect
    _expect_error(ChaosPlan.from_args, ["sai=rout_entry:create:delay=1"])       # typo
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:nope:delay=1"])        # unknown op
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:create:status=ENOENT"])  # not a SAI status
    _expect_error(ChaosPlan.from_args,
                  ["sai=route_entry:create:status=SAI_STATUS_SUCCESS"])         # injects nothing
    _expect_error(ChaosPlan.from_args, ["sai=lag:create:drop=true"])            # unwritten oid
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:get:drop=true"])       # unfilled attrs
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:create:delay=-1"])     # negative delay
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:create:delay=1:mode=lolno"])
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:mode=freeze"])        # freeze is global

    # Bulk exists on only 20 of the 126 types. Naming it on one of the other 106 used to
    # validate and then hook nothing at all, so the fault never fired and the run reported that
    # the system held under a fault that was never applied.
    assert len(sai_catalog.BULK_TYPES) == 20, len(sai_catalog.BULK_TYPES)
    assert sai_catalog.BULK_TYPES < set(sai_catalog.OBJECT_TYPES)
    ChaosPlan.from_args(["sai=route_entry:bulk_create:delay=100"])          # has bulk
    _expect_error(ChaosPlan.from_args, ["sai=acl_entry:bulk_create:delay=1"])   # has none
    _expect_error(ChaosPlan.from_args, ["sai=acl_table:bulk_remove:delay=1"])

    # drop is decided per operation, not by a blanket list: it is safe exactly when the call
    # hands nothing back. Entry-style creates take no output parameter, so dropping one is the
    # "ASIC said yes and installed nothing" fault -- the cleanest divergence the oracle can see.
    assert sai_catalog.ENTRY_TYPES < set(sai_catalog.OBJECT_TYPES)
    assert "route_entry" in sai_catalog.ENTRY_TYPES
    assert "lag" not in sai_catalog.ENTRY_TYPES and "vlan_member" not in sai_catalog.ENTRY_TYPES
    ChaosPlan.from_args(["sai=route_entry:create:drop=true"])    # no output parameter
    ChaosPlan.from_args(["sai=my_sid_entry:create:drop=true"])
    ChaosPlan.from_args(["sai=vlan_member:remove:drop=true"])    # remove hands nothing back
    ChaosPlan.from_args(["sai=acl_entry:set:drop=true"])
    _expect_error(ChaosPlan.from_args, ["sai=lag:create:drop=true"])          # returns an oid
    _expect_error(ChaosPlan.from_args, ["sai=vlan_member:create:drop=true"])
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:get:drop=true"])     # fills attrs
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:bulk_remove:drop=true"])  # statuses
    # status= has the same flaw on a bulk call: it returns without calling the vendor, syncd's
    # zero-filled per-object statuses read as SUCCESS, and every object is recorded with RID 0x0 --
    # a fault that fools the oracle. Refused, including op=all on a type that has bulk.
    for spec in ("sai=route_entry:bulk_create:status=SAI_STATUS_TABLE_FULL",
                 "sai=route_entry:bulk_remove:status=SAI_STATUS_TABLE_FULL",
                 "sai=route_entry:all:status=SAI_STATUS_TABLE_FULL"):
        _expect_error(ChaosPlan.from_args, [spec])
    ChaosPlan.from_args(["sai=route_entry:bulk_create:delay=2000"])      # calls through: fine
    ChaosPlan.from_args(["sai=next_hop:create:status=SAI_STATUS_ITEM_NOT_FOUND:count=1"])
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:all:drop=true"])     # covers get

    # A bad object type says what to use instead rather than just "no".
    try:
        ChaosPlan.from_args(["sai=vlan_membr:remove:drop=true"])
        raise AssertionError("expected a usage error")
    except ChaosUsageError as err:
        assert "vlan_member" in str(err), err

    # The stale-member spec, and the document it produces for the shim.
    [failing] = ChaosPlan.from_args(
        ["sai=vlan_member:remove:status=SAI_STATUS_ITEM_NOT_FOUND:count=1"]).injectors
    document = failing.control()
    assert document["hook"] == ["vlan_member"], document
    rule = document["rules"]["vlan_member"]["remove"]
    assert rule["status"] == -7 and rule["count"] == 1 and rule["drop"] is False, rule
    assert rule["status_name"] == "SAI_STATUS_ITEM_NOT_FOUND", rule

    [slow] = ChaosPlan.from_args(["sai=route_entry:create:delay=2000"]).injectors
    assert slow.control()["rules"]["route_entry"]["create"] == {
        "delay_ms": 2000, "status": None, "drop": False, "count": 0}
    [every_op] = ChaosPlan.from_args(["sai=lag_member:all:delay=100"]).injectors
    assert list(every_op.control()["rules"]["lag_member"]) == ["*"], "op=all means every op"
    _expect_error(ChaosPlan.from_args, ["sai=lag_member:all:drop=true"])   # all covers create

    # freeze needs no object type and no build, and the old spelling still resolves to it.
    [frozen] = ChaosPlan.from_args(["sai=mode=freeze"]).injectors
    assert frozen.params["object_type"] == "all" and frozen.params["mode"] == "freeze"
    assert ChaosPlan.from_args(["sai=mode=sigstop"]).injectors[0].params["mode"] == "freeze"
    assert ChaosPlan.from_args(
        ["sai=route_entry:create:delay=1:mode=shim"]).injectors[0].params["mode"] == "intercept"
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:create:delay=1:mode=wat"])

    # Advanced parameters have to agree with each other, not just with their own bounds.
    ChaosPlan.from_args(["sai=route_entry:create:delay=65000"])        # past the sairedis timeout
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:create:delay=600000"])   # use freeze
    ChaosPlan.from_args(["sai=route_entry:create:delay=2000:count=50"])
    # 500 x 2 s = 1000 s of latency against a 600 s dead-man: it would disarm mid-fault
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:create:delay=2000:count=500"])
    ChaosPlan.from_args(["sai=route_entry:create:delay=2000:count=500:ttl=1200"])

    # Two faults share one control file on the box, so each owns a slice of it and releasing
    # one must leave the other armed.
    dut = _FakeSyncdDut()
    failing._merge_control(dut, failing.control())
    slow._merge_control(dut, slow.control())
    live = json.loads(dut.files[sai_injector.CONTROL_FILE])
    assert sorted(live["hook"]) == ["route_entry", "vlan_member"], live["hook"]
    assert set(live["rules"]) == {"route_entry", "vlan_member"}, live["rules"]
    assert live["seq"] == 2, live["seq"]

    slow._merge_control(dut, None)
    live = json.loads(dut.files[sai_injector.CONTROL_FILE])
    assert live["hook"] == ["vlan_member"], live["hook"]
    assert set(live["rules"]) == {"vlan_member"}, live["rules"]

    failing._merge_control(dut, None)
    assert sai_injector.CONTROL_FILE not in dut.files, "last release should remove the file"

    # status() reads the counters the shim publishes.
    dut.files[sai_injector.STATS_FILE] = json.dumps({
        "pid": 42, "seq": 2, "hooks": 6, "hooked": ["vlan_member"],
        "rules": [{"object_type": "vlan_member", "op": "remove", "armed": True,
                   "calls": 9, "matched": 1, "injected": 1}],
    })
    state = failing.status(dut)
    assert state["active"] and state["achieved"]["injected"] == 1, state
    assert state["hooked"] == ["vlan_member"], state

    # A shim that never hooked says so rather than reporting a fault that is not there.
    assert _FakeSyncdDut() and failing.status(_FakeSyncdDut())["active"] is False


class _FakeDut(object):
    def __init__(self, hostname):
        self.hostname = hostname

    def shell(self, *args, **kwargs):
        raise AssertionError("selftest must never touch a DUT")


def _expect_error(fn, *args):
    try:
        fn(*args)
    except ChaosUsageError:
        return
    raise AssertionError("expected ChaosUsageError from {}{!r}".format(getattr(fn, "__name__", fn), args))


# --------------------------------------------------------------- Squeeze lane, offline

def _load_agent():
    """chaos_agent.py is DUT-side and stdlib-only, so it is loaded by path rather than imported."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent", "chaos_agent.py")
    spec = importlib.util.spec_from_file_location("chaos_agent", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_agent(agent, argv):
    """Drive the agent through its real CLI and parse the one JSON object it prints."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = agent.main(argv)
    return rc, json.loads(buf.getvalue())


class _FakeBox(object):
    """A cgroup v2 tree and a docker CLI in a temp directory.

    Enough of a lab switch to run the agent's real apply / re-attach / release / ramp paths with no
    DUT and no root. It emulates the two kernel behaviours the agent leans on that a plain
    directory does not have: writing a pid to ``cgroup.procs`` *moves* it out of whatever cgroup
    it was in, and a cgroup's interface files never block ``rmdir`` -- only a process or a child
    cgroup still inside does.
    """

    def __init__(self, agent, root):
        self.agent, self.root = agent, root
        self.procs = {}          # pid -> comm, as /proc would report it
        self.cids = {}           # container -> id
        self.scopes = {}         # container -> its cgroup scope path
        self.limits = {}         # container -> HostConfig fields
        self.updates = []        # every `docker update` the agent issued, in order
        self.units = []          # every transient systemd unit the agent asked for
        self.stopped = []        # dead-men disarmed, so release can be checked without signalling
        self.clock = 1000.0

        self._real_try_write = agent.try_write
        self.mkcgroup(root)
        self._put(os.path.join(root, "cgroup.subtree_control"), "cpu memory")
        self.scope = self.add_container("swss")
        self.set_events()

        agent.CG_ROOT = root
        agent.CG_BASE = os.path.join(root, "sonic-chaos")
        agent.STATE_DIR = os.path.join(root, "state")
        agent.LOG = os.path.join(root, "state", "agent.log")
        agent.now = lambda: self.clock
        agent.docker = self.docker
        agent.proc_cgroup = self.proc_cgroup
        agent._is_process = lambda pid, name: self.procs.get(pid) == name
        agent.try_write = self.try_write
        agent.mkcgroup = self.mkcgroup
        agent.rmcgroup = self.rmcgroup
        agent.systemd_run = self.systemd_run
        agent.spawn = lambda argv, label: 4242
        agent.stop_deadmen = lambda state: self.stopped.append(state["kind"])

    # -- kernel emulation ------------------------------------------------------------------

    def _put(self, path, text):
        with open(path, "w") as fh:
            fh.write(text)

    def mkcgroup(self, path):
        os.makedirs(path, exist_ok=True)
        for name, body in (("cgroup.controllers", "cpuset cpu io memory pids"),
                           ("cgroup.subtree_control", ""),
                           ("cgroup.procs", ""),
                           ("cpu.stat", "usage_usec 0\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0")):
            if not os.path.exists(os.path.join(path, name)):
                self._put(os.path.join(path, name), body)
        return path

    def rmcgroup(self, path):
        children = [d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]
        if self.agent.cgroup_procs(path) or children:
            raise OSError("cgroup busy")
        shutil.rmtree(path)

    def try_write(self, path, text):
        if os.path.basename(path) != "cgroup.procs":
            return self._real_try_write(path, text)
        if not os.path.isdir(os.path.dirname(path)):
            return "{}: no such cgroup".format(path)
        pid = text.strip()
        self._forget(pid)                       # a pid lives in exactly one cgroup
        with open(path, "a") as fh:
            fh.write(pid + "\n")
        return None

    def _forget(self, pid):
        for other in glob.glob(os.path.join(self.root, "**", "cgroup.procs"), recursive=True):
            with open(other) as fh:
                kept = [x for x in fh.read().split() if x != str(pid)]
            self._put(other, "".join(x + "\n" for x in kept))   # one pid per line, as the kernel does

    def proc_cgroup(self, pid):
        for path in glob.glob(os.path.join(self.root, "**", "cgroup.procs"), recursive=True):
            with open(path) as fh:
                if str(pid) in fh.read().split():
                    return os.path.dirname(path)
        return None

    def docker(self, *args):
        args = list(args)
        if args[0] == "inspect":
            field, name = args[2], args[3]
            if name not in self.cids:
                return 1, "", "No such object: {}".format(name)
            if field == "{{.Id}}":
                return 0, self.cids[name], ""
            key = {"{{.HostConfig.NanoCpus}}": "nanocpus", "{{.HostConfig.Memory}}": "memory",
                   "{{.HostConfig.MemorySwap}}": "swap"}[field]
            return 0, str(self.limits.get(name, {}).get(key, 0)), ""
        if args[0] == "update":
            self.updates.append(args)
            store = self.limits.setdefault(args[-1], {})
            for flag in args[1:-1]:
                key, _, value = flag.partition("=")
                if key == "--cpus":
                    store["nanocpus"] = int(float(value) * 1e9)
                elif key == "--memory":
                    store["memory"] = int(value)
                elif key == "--memory-swap":
                    store["swap"] = int(value)
            return 0, "", ""
        return 127, "", "unhandled: {}".format(args)

    def systemd_run(self, unit, argv, on_active=None):
        self.units.append((unit, on_active))
        return None

    # -- things a test drives ---------------------------------------------------------------

    def add_container(self, name):
        cid = "{:0<64}".format(name.replace("-", ""))[:64]
        self.cids[name] = cid
        scope = self.mkcgroup(os.path.join(self.root, "system.slice", "docker-{}.scope".format(cid)))
        self.scopes[name] = scope
        self.set_mem(400 * 1024 * 1024, name)
        return scope

    def start(self, pid, comm, container="swss"):
        self.procs[pid] = comm
        self.try_write(os.path.join(self.scopes[container], "cgroup.procs"), str(pid))

    def kill(self, pid):
        self.procs.pop(pid, None)
        self._forget(pid)

    def set_stat(self, cgroup, usage_usec=0, nr_periods=0, nr_throttled=0, throttled_usec=0):
        self._put(os.path.join(cgroup, "cpu.stat"),
                  "usage_usec {}\nnr_periods {}\nnr_throttled {}\nthrottled_usec {}".format(
                      usage_usec, nr_periods, nr_throttled, throttled_usec))

    def set_mem(self, current, container="swss"):
        self._put(os.path.join(self.scopes[container], "memory.current"), str(current))

    def set_events(self, oom_kill=0, at_limit=0):
        self._put(os.path.join(self.scope, "memory.events"),
                  "max {}\noom 0\noom_kill {}".format(at_limit, oom_kill))


def squeeze_checks():
    """The Squeeze lane's agent, end to end, against a fake box. No DUT, no root, no docker."""
    agent = _load_agent()
    root = tempfile.mkdtemp(prefix="sonic-chaos-selftest-")
    try:
        box = _FakeBox(agent, root)
        box.start(107468, "supervisord")
        box.start(109662, "orchagent")
        leaf = os.path.join(agent.CG_BASE, "orchagent")

        # Tier 1: the daemon lands in a sibling cgroup, and *only* the daemon. Starving orchagent
        # while portsyncd and supervisord run at full speed is the whole point of the tier.
        rc, applied = _run_agent(agent, ["apply", "--kind", "cpu", "--target", "orchagent",
                                         "--container", "swss", "--how", "cgroup",
                                         "--share", "30", "--ttl", "600"])
        assert rc == 0, applied
        assert applied["pids"] == [109662] and applied["active"] is True, applied
        with open(os.path.join(leaf, "cpu.max")) as fh:
            assert fh.read() == "30000 100000", "share 30 must be 30% of one 100ms period"
        assert agent.cgroup_procs(box.scope) == [107468], "only the target may be moved"

        # The dead-man is a systemd timer, not a child process: a detached child dies with the
        # session that spawned it, which is exactly how a box gets left throttled overnight.
        armed = agent.load_state("cpu", "orchagent")["units"]
        assert armed == ["sonic-chaos-cpu-orchagent-deadman.timer",
                         "sonic-chaos-cpu-orchagent-watch.service"], armed
        assert ("sonic-chaos-cpu-orchagent-deadman", 600) in box.units, box.units

        # apply is idempotent: twice is once, and the deadline is pushed out rather than doubled
        box.clock += 5
        rc, _ = _run_agent(agent, ["apply", "--kind", "cpu", "--target", "orchagent",
                                   "--container", "swss", "--how", "cgroup", "--share", "30",
                                   "--ttl", "600"])
        state = agent.load_state("cpu", "orchagent")
        assert rc == 0 and state["reapplied"] == 1 and state["deadline"] == 1605.0, state
        assert agent.cgroup_procs(leaf) == [109662], "a second apply must not duplicate the pid"

        # achieved share is measured from the cgroup's own accounting. 3 s of CPU in 10 s of wall
        # clock is 30% of one core -- the number that makes a result under this fault falsifiable.
        box.clock += 5
        box.set_stat(leaf, usage_usec=3000000, nr_periods=100, nr_throttled=40,
                     throttled_usec=500000)
        agent.cpu_sample(state)
        assert agent.summary(state)["achieved"] == 30.0, agent.summary(state)
        assert agent.summary(state)["bit"] is True, "nr_throttled > 0 means the cap actually bit"
        assert agent.summary(state)["throttled_pct"] == 40.0

        # ...and it is cumulative from the first sample, not a rolling window: a long run reports
        # the share over the whole test, while `peak` keeps the worst single interval.
        box.clock += 10
        box.set_stat(leaf, usage_usec=4500000, nr_periods=200, nr_throttled=60,
                     throttled_usec=700000)
        agent.cpu_sample(state)
        measured = agent.summary(state)
        assert measured["achieved"] == 22.5 and measured["peak"] == 30.0, measured

        # the PID watcher. Spine's kill injector restarts swss; orchagent is reborn in the
        # container's own scope, silently un-throttled. Re-attaching is what keeps it applied.
        box.kill(109662)
        box.start(109999, "orchagent")
        assert agent.cgroup_procs(leaf) == [], "the restarted daemon is not in our cgroup yet"
        moved, failed = agent.cpu_attach(state)
        assert moved == [109999] and not failed, (moved, failed)
        assert agent.cgroup_procs(leaf) == [109999], "watcher must re-attach after a restart"
        agent.save_state(state)

        # release lifts the cap first and unwinds second, so a later failure leaves it lifted
        disarms = len(box.stopped)
        rc, released = _run_agent(agent, ["release", "--kind", "cpu", "--target", "orchagent"])
        assert rc == 0 and released["released"] is True and released["active"] is False, released
        assert not os.path.isdir(leaf), "the leaf cgroup must be gone"
        assert 109999 in agent.cgroup_procs(box.scope), "the pid must be back in its container"
        assert released["achieved"] == 22.5, "the measurement survives into the released record"
        assert len(box.stopped) > disarms, "release must disarm the dead-men it armed"

        # safe to call twice, and never raises for a fault that was never applied
        rc, again = _run_agent(agent, ["release", "--kind", "cpu", "--target", "orchagent"])
        assert rc == 0 and again["released"] is True, again
        assert released["expired"] is False, "a harness teardown is not an expiry"
        assert released["reason"] == "harness", released
        rc, missing = _run_agent(agent, ["status", "--kind", "cpu", "--target", "never-applied"])
        assert rc == 0 and missing["active"] is False and missing["achieved"] is None, missing

        # a TTL expiry is recorded as one: a fault that ran out mid-test is a different result
        # from one the teardown released, and the report must be able to tell them apart
        _run_agent(agent, ["apply", "--kind", "cpu", "--target", "orchagent", "--container",
                           "swss", "--how", "cgroup", "--share", "30", "--ttl", "60"])
        box.clock += 120
        rc, timed_out = _run_agent(agent, ["watch", "--kind", "cpu", "--target", "orchagent"])
        assert rc == 0 and timed_out["expired"] is True and timed_out["released"] is True, timed_out
        assert timed_out["reason"] == "ttl", timed_out

        # Tier 1 on a container whose only process is the target would empty its scope, and
        # systemd collects an emptied scope -- so it is refused with the tier that does work.
        box.add_container("solo")
        box.start(222333, "lonely", container="solo")
        rc, refused = _run_agent(agent, ["apply", "--kind", "cpu", "--target", "lonely",
                                         "--container", "solo", "--how", "cgroup", "--share", "20"])
        assert rc == 1 and "how=docker" in refused["error"], refused
        assert agent.cgroup_procs(box.scopes["solo"]) == [222333], "the pid must not have moved"
        assert not os.path.isdir(os.path.join(agent.CG_BASE, "lonely")), "nothing left behind"

        # Tier 0: whole container, one docker command, and an unlimited baseline restored on release
        rc, tier0 = _run_agent(agent, ["apply", "--kind", "cpu", "--target", "swss",
                                       "--container", "swss", "--how", "docker", "--share", "50"])
        assert rc == 0 and tier0["how"] == "docker", tier0
        assert ["update", "--cpus=0.500", "swss"] in box.updates, box.updates
        rc, tier0r = _run_agent(agent, ["release", "--kind", "cpu", "--target", "swss"])
        assert rc == 0 and tier0r["released"] is True
        assert ["update", "--cpus=0", "swss"] in box.updates, box.updates

        # mem: apply sets the first rung, the watcher walks the rest on `period`
        rc, ramp = _run_agent(agent, ["apply", "--kind", "mem", "--target", "swss",
                                      "--container", "swss", "--steps", "80,60,40",
                                      "--period", "20", "--settle", "0"])
        assert rc == 0 and ramp["cap_pct"] == 80, ramp
        assert ramp["cap_bytes"] == 400 * 1024 * 1024 * 80 // 100, ramp
        state = agent.load_state("mem", "swss")
        assert agent.mem_tick(state) is False, "the ramp must not step before its period elapses"
        box.clock += 20
        assert agent.mem_tick(state) is True and state["step"] == 1, state
        box.clock += 20
        assert agent.mem_tick(state) is True and state["steps"][state["step"]] == 40, state
        box.clock += 20
        assert agent.mem_tick(state) is False, "the ramp stops at its last rung"
        agent.save_state(state)

        # the finding is what RSS does AFTER the pressure lifts. Memory returned is not memory
        # recovered: a daemon that stays fat is holding state it never freed.
        box.set_mem(600 * 1024 * 1024)
        box.set_events(oom_kill=1)
        rc, leak = _run_agent(agent, ["release", "--kind", "mem", "--target", "swss"])
        assert rc == 0 and leak["released"] is True, leak
        assert leak["recovered"] is False and leak["rss_delta_pct"] == 50.0, leak
        assert leak["oom_kill"] == 1, "an OOM kill is an event fault, not graceful degradation"
        with open(os.path.join(box.scope, "memory.max")) as fh:
            assert fh.read() == "max", "the kernel knob is the authoritative un-cap"

        # a container smaller than docker's 6 MiB floor clamps rather than failing the run
        box.add_container("gnmi")
        box.set_mem(1000000, "gnmi")
        rc, tiny = _run_agent(agent, ["apply", "--kind", "mem", "--target", "gnmi",
                                      "--container", "gnmi", "--steps", "50", "--settle", "0"])
        assert rc == 0 and tiny["cap_bytes"] == agent.DOCKER_MIN_MEM, tiny
        _run_agent(agent, ["release", "--kind", "mem", "--target", "gnmi"])
    finally:
        shutil.rmtree(root, ignore_errors=True)


# --------------------------------------------------------------------------- oracle fixtures
# Shapes copied verbatim from a lab switch (202511.2, t2-single-node-min) so the invariants
# are regression-tested against what a real box actually stores -- entry keys carrying a JSON
# blob, MACs in opposite cases across databases, the empty-key artifact in the LAG name map, and
# a management-interface neighbour that is in APPL_DB and will never be in the ASIC.

LAG_OID = "oid:0x2000000000a49"
PORT12_OID = "oid:0x1000000000004"
PORT128_OID = "oid:0x1000000000021"
RIF132_OID = "oid:0x6000000000a97"
ASIC_LM = "ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:"
ASIC_NE = "ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:"


def _neigh_key(ip, rif):
    # ASIC_DB entry keys are a JSON blob, with the fields in this order on the box.
    return ASIC_NE + '{{"ip":"{}","rif":"{}","switch_id":"oid:0x21000000000000"}}'.format(ip, rif)


def _lab_snapshot(**over):
    appl = {
        "LAG_MEMBER_TABLE:PortChannel101:Ethernet12": {"status": "enabled"},
        "LAG_MEMBER_TABLE:PortChannel101:Ethernet128": {"status": "enabled"},
        "LAG_TABLE:PortChannel101": {"admin_status": "up", "oper_status": "up"},
        # front-panel neighbour: ASIC has it, uppercase MAC
        "NEIGH_TABLE:Ethernet132:10.0.0.103": {"neigh": "22:e7:e9:cc:22:46", "family": "IPv4"},
        # IPv6 written in the short form; the ASIC side uses the same address
        "NEIGH_TABLE:Ethernet132:fc00::12": {"neigh": "22:e7:e9:cc:22:47", "family": "IPv6"},
        # management neighbour: in APPL_DB forever, never programmed. Must NOT be a finding.
        "NEIGH_TABLE:eth0:192.0.2.1": {"neigh": "aa:bb:cc:dd:ee:ff", "family": "IPv4"},
    }
    asic = {
        ASIC_LM + "oid:0x1b000000000a4c": {"SAI_LAG_MEMBER_ATTR_LAG_ID": LAG_OID,
                                           "SAI_LAG_MEMBER_ATTR_PORT_ID": PORT12_OID},
        ASIC_LM + "oid:0x1b000000000a4d": {"SAI_LAG_MEMBER_ATTR_LAG_ID": LAG_OID,
                                           "SAI_LAG_MEMBER_ATTR_PORT_ID": PORT128_OID},
        "ASIC_STATE:SAI_OBJECT_TYPE_LAG:" + LAG_OID: {"SAI_LAG_ATTR_INGRESS_ACL": "oid:0xb00"},
        _neigh_key("10.0.0.103", RIF132_OID): {
            "SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS": "22:E7:E9:CC:22:46"},   # UPPERCASE on the box
        _neigh_key("fc00:0:0:0:0:0:0:12", RIF132_OID): {
            "SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS": "22:E7:E9:CC:22:47"},   # long-form IPv6
    }
    counters = {
        "COUNTERS_LAG_NAME_MAP": {"PortChannel101": LAG_OID, "": ""},   # the empty-key artifact
        "COUNTERS_PORT_NAME_MAP": {"Ethernet12": PORT12_OID, "Ethernet128": PORT128_OID,
                                   "Ethernet132": "oid:0x1000000000022"},
        "COUNTERS_RIF_NAME_MAP": {"Ethernet132": RIF132_OID, "PortChannel101": "oid:0x6000000000a50"},
    }
    tables = {"APPL_DB": appl, "ASIC_DB": asic, "COUNTERS_DB": counters, "STATE_DB": {}}
    for db, patch in over.items():
        tables[db] = dict(tables[db])
        for key, value in patch.items():
            if value is None:
                tables[db].pop(key, None)
            else:
                tables[db][key] = value
    return oracle.DbSnapshot(tables, hostname="fixture")


def _kinds(divs):
    return sorted(d.kind for d in divs)


def check_oracle_invariants():
    snap = _lab_snapshot()

    # the empty-key artifact must not become an entry
    lags = invariants.oid_to_name(snap, invariants.LAG_MAP)
    assert lags == {LAG_OID: "PortChannel101"}, lags
    assert invariants.oid_to_name(snap, invariants.VLAN_MAP) is None   # this platform has none

    # a healthy box: every cross-DB invariant clean and none left unchecked -- vlan_member resolves
    # VLANs through SAI_VLAN_ATTR_VLAN_ID, so the missing VLAN map no longer stops it
    real, notices = oracle.split_unchecked(oracle.check(snap))
    assert real == [], real
    assert notices == [], _kinds(notices)

    # MAC case and IPv6 spelling must NOT read as divergences -- proven by the clean run above,
    # so now prove the checks are actually looking at those fields rather than skipping them.
    bad_mac = _lab_snapshot(ASIC_DB={
        _neigh_key("10.0.0.103", RIF132_OID): {
            "SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS": "00:11:22:33:44:55"}})
    found = invariants.neighbor(bad_mac)
    assert len(found) == 1 and "MAC disagrees" in found[0].detail, found

    # a front-panel neighbour that never reached the ASIC
    missing = _lab_snapshot(ASIC_DB={_neigh_key("10.0.0.103", RIF132_OID): None})
    found = invariants.neighbor(missing)
    assert len(found) == 1 and "not programmed in ASIC_DB" in found[0].detail, found

    # the management neighbour is skipped in every one of those runs
    assert not any("eth0" in d.key for d in invariants.neighbor(_lab_snapshot()))
    assert not any("eth0" in d.key for d in found), found

    # LAG member removed from the ASIC -> flagged from the APPL_DB side
    gone = _lab_snapshot(ASIC_DB={ASIC_LM + "oid:0x1b000000000a4c": None})
    found = invariants.lag_member(gone)
    assert len(found) == 1 and found[0].db == "APPL_DB", found
    assert "Ethernet12" in found[0].key, found

    # a stale ASIC member with no APPL_DB counterpart -- the stale-member shape
    stale = _lab_snapshot(APPL_DB={"LAG_MEMBER_TABLE:PortChannel101:Ethernet12": None})
    found = invariants.lag_member(stale)
    assert len(found) == 1 and found[0].db == "ASIC_DB", found
    assert "stale-member" in found[0].detail, found

    # an OID that resolves to nothing is reported, never silently dropped
    dangling = _lab_snapshot(ASIC_DB={
        ASIC_LM + "oid:0xdead": {"SAI_LAG_MEMBER_ATTR_LAG_ID": "oid:0xnope",
                                 "SAI_LAG_MEMBER_ATTR_PORT_ID": PORT12_OID}})
    found = invariants.lag_member(dangling)
    assert any("does not resolve" in d.detail for d in found), found

    # LAG object missing from the ASIC
    nolag = _lab_snapshot(ASIC_DB={"ASIC_STATE:SAI_OBJECT_TYPE_LAG:" + LAG_OID: None})
    found = invariants.lag(nolag)
    assert len(found) == 1 and "no ASIC_DB LAG object" in found[0].detail, found

    # a snapshot with no name maps says "cannot check" for every cross-DB invariant and
    # never invents a violation
    bare = oracle.DbSnapshot({"APPL_DB": {}, "ASIC_DB": {}})
    real, notices = oracle.split_unchecked(oracle.check(bare))
    assert real == [], real
    assert len(notices) == 4, _kinds(notices)

    # no_start_limit reads `systemctl show` and names the unit and the fix
    class _SystemdDut(object):
        hostname = "sysd"

        def shell(self, cmd, module_ignore_errors=True):
            return {"rc": 0, "stderr": "", "stdout": (
                "swss ActiveState=failed Result=start-limit-hit \n"
                "syncd ActiveState=inactive Result=success \n"
                "bgp ActiveState=active Result=success \n"
                "pmon ActiveState=failed Result=exit-code \n")}

    sd = oracle.DbSnapshot({}, duthost=_SystemdDut())
    found = invariants.no_start_limit(sd)
    assert [d.key for d in found] == ["swss.service", "pmon.service"], found
    assert "reset-failed swss" in found[0].detail and "exit-code" in found[1].detail, found
    assert "no_start_limit" in oracle.group_members("health")

    # health invariants are inert without a DUT rather than throwing
    for name in ("critical_processes", "no_cores", "bgp_established"):
        assert oracle.INVARIANTS[name](bare) == []

    # normalisers
    assert invariants.norm_mac("AA:BB:cc") == "aa:bb:cc"
    assert invariants.norm_ip("fc00:0:0:0:0:0:0:12") == invariants.norm_ip("fc00::12")
    assert invariants.norm_ip("not-an-ip") == "not-an-ip"
    assert invariants.parse_entry_key(_neigh_key("1.2.3.4", "oid:0x1"), "NEIGHBOR_ENTRY")["ip"] == "1.2.3.4"
    assert invariants.parse_entry_key(ASIC_LM + "oid:0x1", "LAG_MEMBER") is None


def check_vlan_invariant():
    """The probe-object check behind the SAI hijack demo: a VLAN the control plane accepted but
    the ASIC never got must be a ``vlan`` divergence, on a platform with no COUNTERS_VLAN_NAME_MAP.
    """
    asic_vlan = invariants.ASIC_PREFIX + "VLAN:oid:0x260000000000ff"
    asic_default = invariants.ASIC_PREFIX + "VLAN:oid:0x26000000000001"

    # hijacked create: APPL_DB holds the intent, ASIC_DB holds only the default VLAN
    hijacked = _lab_snapshot(
        APPL_DB={"VLAN_TABLE:Vlan4001": {"admin_status": "up", "mtu": "9100"}},
        ASIC_DB={asic_default: {"SAI_VLAN_ATTR_VLAN_ID": "1"}})
    real, _notices = oracle.split_unchecked(oracle.check(hijacked, only=["vlan"]))
    assert _kinds(real) == ["vlan"], real
    assert real[0].db == "APPL_DB" and real[0].key == "VLAN_TABLE:Vlan4001", real[0]
    assert "not programmed in ASIC_DB" in real[0].detail, real[0]

    # the same VLAN programmed: clean. The ASIC default VLAN 1 is never in APPL_DB and must not
    # read as a stale entry.
    healthy = _lab_snapshot(
        APPL_DB={"VLAN_TABLE:Vlan4001": {"admin_status": "up", "mtu": "9100"}},
        ASIC_DB={asic_default: {"SAI_VLAN_ATTR_VLAN_ID": "1"},
                 asic_vlan: {"SAI_VLAN_ATTR_VLAN_ID": "4001"}})
    real, _notices = oracle.split_unchecked(oracle.check(healthy, only=["vlan"]))
    assert real == [], real

    # a VLAN only the ASIC holds is the stale-entry direction
    stale = _lab_snapshot(ASIC_DB={asic_vlan: {"SAI_VLAN_ATTR_VLAN_ID": "200"}})
    real, _notices = oracle.split_unchecked(oracle.check(stale, only=["vlan"]))
    assert _kinds(real) == ["vlan"] and real[0].db == "ASIC_DB" and "stale" in real[0].detail, real

    # keyed on the VLAN_ID attribute, so it reports a result where vlan_member can only say
    # "cannot check" for want of the name map
    assert invariants.oid_to_name(hijacked, invariants.VLAN_MAP) is None


def check_vlan_member_invariant():
    """VLAN members resolve through bridge ports, the way port_util does for fdbshow.

    Before this, SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID was looked up as a port OID, so on any box with
    real VLAN members every member read as dangling and a genuine finding would have been buried.
    """
    a = invariants.ASIC_PREFIX
    vlan1000, vlan_default = "oid:0x26000000000100", "oid:0x26000000000001"
    bp_eth12, bp_pc101 = "oid:0x3a000000000012", "oid:0x3a0000000000a9"
    member_eth12, member_pc101 = a + "VLAN_MEMBER:oid:0x27000000000001", a + "VLAN_MEMBER:oid:0x27000000000002"
    appl = {"VLAN_MEMBER_TABLE:Vlan1000:Ethernet12": {"tagging_mode": "untagged"},
            "VLAN_MEMBER_TABLE:Vlan1000:PortChannel101": {"tagging_mode": "tagged"}}
    asic = {a + "VLAN:" + vlan1000: {"SAI_VLAN_ATTR_VLAN_ID": "1000"},
            a + "VLAN:" + vlan_default: {"SAI_VLAN_ATTR_VLAN_ID": ""},   # empty on some platforms
            a + "BRIDGE_PORT:" + bp_eth12: {"SAI_BRIDGE_PORT_ATTR_PORT_ID": PORT12_OID},
            a + "BRIDGE_PORT:" + bp_pc101: {"SAI_BRIDGE_PORT_ATTR_PORT_ID": LAG_OID},
            member_eth12: {"SAI_VLAN_MEMBER_ATTR_VLAN_ID": vlan1000,
                           "SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID": bp_eth12},
            member_pc101: {"SAI_VLAN_MEMBER_ATTR_VLAN_ID": vlan1000,
                           "SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID": bp_pc101}}

    def run(appl_patch=None, asic_patch=None):
        snap = _lab_snapshot(APPL_DB=dict(appl, **(appl_patch or {})),
                             ASIC_DB=dict(asic, **(asic_patch or {})))
        real, notices = oracle.split_unchecked(oracle.check(snap, only=["vlan_member"]))
        assert notices == [], _kinds(notices)
        return real

    # healthy: an Ethernet member and a PortChannel member both resolve, no VLAN map needed
    assert run() == [], run()

    # the ASIC dropped a member the control plane still wants
    real = run(asic_patch={member_pc101: None})
    assert [(d.db, d.key) for d in real] == [("APPL_DB", "VLAN_MEMBER_TABLE:Vlan1000:PortChannel101")], real
    assert "not programmed in ASIC_DB" in real[0].detail, real[0]

    # the ASIC still holds a member the control plane removed
    real = run(appl_patch={"VLAN_MEMBER_TABLE:Vlan1000:Ethernet12": None})
    assert [(d.db, d.key) for d in real] == [("ASIC_DB", member_eth12)], real
    assert "stale" in real[0].detail, real[0]

    # a member whose bridge port, or VLAN, no longer exists is itself a finding
    real = run(asic_patch={a + "BRIDGE_PORT:" + bp_eth12: None})
    assert [(d.db, d.key) for d in real if "no such port" in d.detail] == [("ASIC_DB", member_eth12)], real
    real = run(asic_patch={a + "VLAN:" + vlan1000: None})
    assert sum("no such VLAN" in d.detail for d in real) == 2, real


def check_fault_verdict():
    """fired() and warnings() are pure functions of status/params: a never-fired fault must be
    distinguishable from a fired one (the vacuous-PASS fix), and a delay too small to observe must
    say so. These are what let the verdict layer refuse to call a no-op fault a pass.
    """
    def inj(spec):
        return ChaosPlan.from_args([spec]).injectors[0]

    hijack = inj("sai=vlan:create:status=SAI_STATUS_TABLE_FULL")
    assert hijack.fired({"achieved": {"injected": 5}}) is True
    assert hijack.fired({"achieved": {"injected": 0}}) is False    # armed, never engaged
    assert hijack.fired({"active": True}) is None                  # no counter -> cannot tell

    freeze = inj("sai=mode=freeze")
    assert freeze.fired({"active": True}) is True                  # syncd actually stopped
    assert freeze.fired({"active": False}) is False

    spin = inj("spin=orchagent:100")
    assert spin.fired({"achieved": {"spun_ms": 900}}) is True
    assert spin.fired({"achieved": {"spun_ms": 0}}) is False

    # a small delay fires but may leave no visible data-plane change; a big one is silent
    assert inj("sai=route_entry:create:delay=5000").warnings()
    assert not inj("sai=route_entry:create:delay=30000").warnings()
    assert not inj("sai=vlan:create:status=SAI_STATUS_TABLE_FULL").warnings()


def check_conditions():
    """--chaos-conditions: a JSON matrix is validated in full at configure time, names are
    unique pytest ids, and both fault shapes (spec string, experiment-file dict) parse."""
    conds = parse_conditions({"conditions": [
        {"name": "baseline", "faults": []},
        {"name": "restart", "faults": ["kill=orchagent:how=restart"], "note": "n"},
        ["pause=orchagent:3", {"corrupt": {"db": "APPL_DB", "key": "PORT_TABLE:Ethernet0", "mtu": "1"}}],
    ]})
    assert [c.name for c in conds] == ["baseline", "restart", "pause+corrupt"], [c.name for c in conds]
    assert conds[0].plan.injectors == [] and conds[0].summary() == "no fault (control)"
    assert conds[1].note == "n" and conds[1].plan.injectors[0].command().endswith("restart orchagent")
    assert conds[2].specs[1] == "corrupt=db=APPL_DB:key=[PORT_TABLE:Ethernet0]:mtu=1", conds[2].specs
    assert conds[2].plan.injectors[1].fields == {"mtu": "1"}
    assert [c.name for c in parse_conditions([["pause=orchagent:3"]])] == ["pause"]
    assert [c.name for c in parse_conditions({"conditions": [[], ["cpu=orchagent:30"]]}, only=["cpu"])] == ["cpu"]
    for bad in ({}, {"conditions": []}, {"conditions": [{"faults": "kill=orchagent"}]},
                {"conditions": [["kill=orchagnt"]]},                      # unknown target
                {"conditions": [["bogus"]]},                              # not INJECTOR=SPEC
                {"conditions": [[{"kill": "orchagent"}]]},                # dict must map to params
                {"conditions": [{"name": "a b", "faults": []}]},          # not a pytest id
                {"conditions": [{"name": "x", "faults": []}, {"name": "x", "faults": []}]}):
        _expect_error(parse_conditions, bad)
    _expect_error(lambda: parse_conditions({"conditions": [[]]}, only=["nope"]))


def main():
    # grammar
    assert split_spec("orchagent:30") == (["orchagent", "30"], {})
    assert split_spec("route_entry:create:delay=2000") == (["route_entry", "create"], {"delay": "2000"})
    assert split_spec("APPL_DB:[LAG_MEMBER_TABLE:PortChannel12:Ethernet48]:status=x") == (
        ["APPL_DB", "LAG_MEMBER_TABLE:PortChannel12:Ethernet48"], {"status": "x"})
    _expect_error(split_spec, "a:k=v:b")     # positional after keyword
    _expect_error(split_spec, "a:[b")        # unbalanced bracket

    # registry: the lanes' injectors exist and unknown names fail loudly
    assert set(REGISTRY) >= {"cpu", "sai", "kill", "corrupt", "pause", "redis",
                             "mem", "syslog", "exhaust", "storm", "hog"}, sorted(REGISTRY)
    _expect_error(get, "nope")

    # a full plan from CLI args, and the validators that stop bad specs before a DUT is touched
    plan = ChaosPlan.from_args([
        "cpu=orchagent:30",
        "sai=route_entry:create:delay=2000",
        "kill=orchagent:how=restart",
        "corrupt=APPL_DB:[LAG_MEMBER_TABLE:PortChannel12:Ethernet48]:status=garbage",
    ])
    assert [i.name for i in plan.injectors] == ["cpu", "sai", "kill", "corrupt"]
    assert plan.injectors[0].params["container"] == "swss"
    assert plan.injectors[2].command() == "docker exec swss supervisorctl restart orchagent"
    assert plan.injectors[3].fields == {"status": "garbage"}
    _expect_error(ChaosPlan.from_args, ["cpu=redis-server:10"])            # protected target
    _expect_error(ChaosPlan.from_args, ["cpu=orchagent:300"])              # share out of range
    _expect_error(ChaosPlan.from_args, ["cpu=orchagent:30:mode=contend"])  # cut from scope
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:create"])         # no effect requested
    _expect_error(ChaosPlan.from_args, ["corrupt=ASIC_DB:[x]:a=b"])        # ASIC_DB refused
    _expect_error(ChaosPlan.from_args, ["kill=nosuchdaemon"])              # not in targets.yml
    _expect_error(ChaosPlan.from_args, ["bogus"])                          # not INJECTOR=SPEC

    # the two injectors lifted from the chaos-monkey fault catalogue
    freeze = ChaosPlan.from_args(["pause=orchagent:10"]).injectors[0]
    assert freeze.freeze_cmd() == "docker exec swss pkill -STOP -x orchagent"
    assert freeze.thaw_cmd() == "docker exec swss pkill -CONT -x orchagent"
    assert ChaosPlan.from_args(["pause=swss:5:how=docker"]).injectors[0].freeze_cmd() == "docker pause swss"
    _expect_error(ChaosPlan.from_args, ["pause=orchagent:9999"])           # freeze is bounded
    assert "DEBUG SLEEP 2.0" in ChaosPlan.from_args(["redis=sleep:2000"]).injectors[0].command()
    _expect_error(ChaosPlan.from_args, ["redis=sleep:60000"])              # supervisor would restart
    _expect_error(ChaosPlan.from_args, ["redis=bogus_action:x"])
    assert ChaosPlan.from_args(["cpu=orchagent:30"]).injectors[0].quota_us() == 30000

    # hog is not a cap: it bounds the budget AND spends it, so the container really reads X%.
    # cpu.max is cpu% of `cores` cores, and the load is sized to keep that budget saturated --
    # 40% of one core needs two spinners, verified at 39.93% on a lab switch's swss.
    hog = ChaosPlan.from_args(["hog=swss:cpu=40"]).injectors[0]
    assert hog.quota() == "40000 100000" and hog.spinners() == 2
    assert ChaosPlan.from_args(["hog=swss:cpu=40:cores=2"]).injectors[0].quota() == "80000 100000"
    assert ChaosPlan.from_args(["hog=orchagent:cpu=50"]).injectors[0].params["container"] == "swss"
    assert ChaosPlan.from_args(["hog=swss:mem=30"]).injectors[0].spinners() == 0
    _expect_error(ChaosPlan.from_args, ["hog=swss"])            # neither cpu nor mem: no load
    _expect_error(ChaosPlan.from_args, ["hog=swss:cpu=0:mem=0"])  # same, said explicitly
    _expect_error(ChaosPlan.from_args, ["hog=swss:cpu=140"])     # out of range
    _expect_error(ChaosPlan.from_args, ["hog=swss:mem=90"])      # reads as a crash, not pressure
    _expect_error(ChaosPlan.from_args, ["hog=swss:cpu=40:cores=99"])
    _expect_error(ChaosPlan.from_args, ["hog=redis-server:cpu=40"])  # protected target

    # exhaust and storm used to apply() silently and inject nothing, so a run using them reported
    # a pass for a fault that never happened. exhaust now fills route/route6 for real and refuses
    # every other table loudly; storm refuses outright until a ptfhost exists.
    ex = ChaosPlan.from_args(["exhaust=route:0:over_pct=110"]).injectors[0]
    assert ex.crm_resource == "ipv4_route"
    assert ex.target_count(100, 900) == 1000            # 110% of the 1000 limit, less 100 used
    assert ex.target_count(0, 10 ** 9) == 200000        # MAX_PUSH cap
    assert list(ex.prefixes(2)) == ["100.64.0.0/32", "100.64.0.1/32"]
    assert list(ChaosPlan.from_args(["exhaust=route6:5"]).injectors[0].prefixes(1)) == \
        ["2001:db8:0:0::1/128"]
    nb = ChaosPlan.from_args(["exhaust=neighbor:500"]).injectors[0]
    assert nb.crm_resource == "ipv4_neighbor"
    assert ChaosPlan.from_args(["exhaust=nexthop:5"]).injectors[0].crm_resource == "ipv4_nexthop"
    # addresses start at .2: .0 is the subnet's network address and .1 the interface's own IP
    assert "10.200.0.%d" in nb.neigh_awk("PortChannel1", 0, 2) or "(i+2)" in nb.neigh_awk("PortChannel1", 0, 2)
    # storm: netlink runs on the DUT (LAG member flap); the packet kinds still need a PTF peer.
    sn = ChaosPlan.from_args(["storm=netlink:rate=1000:seconds=20"]).injectors[0]
    assert "ip link set dev Ethernet9 down" in sn.flap_script("Ethernet9")
    assert "sleep" not in sn.flap_script("Ethernet9")          # rate >= 200 -> tight loop
    assert "sleep 0.1000" in ChaosPlan.from_args(
        ["storm=netlink:rate=10:seconds=5"]).injectors[0].flap_script("Ethernet9")
    # acl is implemented now; fdb and mirror refuse for reasons specific to each, not a generic
    # "needs a PTF peer" -- fdb has no VLAN to learn into, mirror is not in this platform's CRM.
    ac = ChaosPlan.from_args(["exhaust=acl:500"]).injectors[0]
    assert ac.crm_resource == "acl_entry"
    assert "ACL_RULE|DATAACL|CHAOS_%d" in ac.acl_awk("DATAACL", 0, 2)
    for spec in ("exhaust=fdb:1000", "exhaust=mirror"):
        _expect_error(ChaosPlan.from_args([spec]).injectors[0].apply, None)
    # arp/nd/mac have no sender yet: refused at validate, never accepted and then failed at apply
    for spec in ("storm=arp:rate=5000", "storm=nd:rate=5000", "storm=mac:rate=20000"):
        _expect_error(ChaosPlan.from_args, [spec])
    _expect_error(ChaosPlan.from_args, ["exhaust=bogus_table"])
    _expect_error(ChaosPlan.from_args, ["exhaust=route:0:over_pct=50"])   # over_pct < 100

    # protected targets and owner-bypassing DB writes need an explicit force=true
    _expect_error(ChaosPlan.from_args, ["kill=redis-server"])
    _expect_error(ChaosPlan.from_args, ["cpu=database:20"])
    _expect_error(ChaosPlan.from_args, ["corrupt=ASIC_DB:[x]:a=b"])
    # settle is the hold, ttl the dead-man: a settle that outlives the ttl lifts the fault before
    # the check reads it, so cpu/hog/spin refuse it the way sai does.
    for spec in ("cpu=orchagent:30:settle=900:ttl=900", "spin=orchagent:100:settle=400:ttl=300",
                 "hog=swss:cpu=40:settle=900:ttl=900"):
        _expect_error(ChaosPlan.from_args, [spec])
    assert ChaosPlan.from_args(["spin=orchagent:100:settle=60"]).injectors[0].params["settle"] == "60"
    assert ChaosPlan.from_args(["kill=redis-server:force=true"]).injectors[0].params["container"] == "database"
    assert ChaosPlan.from_args(["corrupt=ASIC_DB:[x]:force=true:a=b"]).injectors[0].fields == {"a": "b"}
    assert ChaosPlan.from_args(["corrupt=APPL_DB:[x]:delete=true"]).injectors[0].delete is True

    # Squeeze: the tier is picked from the target -- a container gets Tier 0 (one docker
    # command), a daemon gets Tier 1 (a sibling cgroup), and `how=` overrides either way.
    assert ChaosPlan.from_args(["cpu=orchagent:30"]).injectors[0].how == "cgroup"
    assert ChaosPlan.from_args(["cpu=swss:50"]).injectors[0].how == "docker"
    assert ChaosPlan.from_args(["cpu=orchagent:30:how=docker"]).injectors[0].how == "docker"
    assert ChaosPlan.from_args(["cpu=orchagent:30"]).injectors[0].cgroup() == \
        "/sys/fs/cgroup/sonic-chaos/orchagent"
    _expect_error(ChaosPlan.from_args, ["cpu=orchagent:30:how=nonsense"])
    _expect_error(ChaosPlan.from_args, ["cpu=orchagent:30:ttl=5"])        # too short to be useful
    _expect_error(ChaosPlan.from_args, ["cpu=orchagent:30:ttl=99999"])    # longer than any run

    # the rest of the fault list
    assert ChaosPlan.from_args(["mem=swss:40:ramp=20"]).injectors[0].steps() == [80, 60, 40]
    assert ChaosPlan.from_args(["mem=swss:70"]).injectors[0].steps() == [70]
    assert ChaosPlan.from_args(["mem=swss:40:ramp=20:period=45"]).injectors[0].ramp_seconds() == 90
    # a ramp the dead-man would cut short is a configuration error, not a surprise at runtime
    _expect_error(ChaosPlan.from_args, ["mem=swss:40:ramp=20:period=600:ttl=60"])
    assert ChaosPlan.from_args(["exhaust=route:120000"]).injectors[0].crm_resource == "ipv4_route"
    _expect_error(ChaosPlan.from_args, ["exhaust=nosuchtable"])
    _expect_error(ChaosPlan.from_args, ["storm=nosuchkind"])
    _expect_error(ChaosPlan.from_args, ["syslog=0"])
    assert ChaosPlan.from_args(["storm=netlink:5000"]).injectors[0].params["kind"] == "netlink"
    assert ChaosPlan.from_args(["syslog=1000:seconds=10"]).injectors[0].estimated_bytes() == 2000000

    # session: dry-run never touches a DUT; release is LIFO, idempotent, and runs to completion
    duts = [_FakeDut("dut1"), _FakeDut("dut2")]
    sess = ChaosSession(duts, dry_run=True)
    for inj in plan.injectors:
        sess.apply(inj)
    assert len(sess.status()) == 8
    sess.release_all()
    assert sess.status() == []
    sess.release_all()   # second release: no-op, not an error

    # release runs to completion even when one injector raises, then re-raises the first error.
    # Both injectors here are fakes on purpose: this asserts ChaosSession's release semantics,
    # and a real injector would have to reach a DUT to do anything at all.
    released = []

    class _Recorder(object):
        name, lane, params = "rec", "test", {}

        def describe(self):
            return "rec"

        def apply(self, duthost, **kw):
            pass

        def release(self, duthost):
            released.append(duthost.hostname)
            if duthost.hostname == "dut1":
                raise RuntimeError("release blew up")

        def status(self, duthost):
            return {}

    class _Quiet(_Recorder):
        def release(self, duthost):
            released.append("quiet:" + duthost.hostname)

    live = ChaosSession(duts)
    live.apply(_Recorder())
    live.apply(_Quiet())
    try:
        live.release_all()
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected the release error to surface")
    # LIFO across the whole stack: the second injector releases before the first, and within
    # each, dut2 before dut1. dut1 raised and dut1's own release still ran.
    assert released == ["quiet:dut2", "quiet:dut1", "dut2", "dut1"], released

    # oracle.diff on plain snapshots
    key = "LAG_MEMBER_TABLE:PortChannel12:Ethernet48"
    before = oracle.DbSnapshot({"APPL_DB": {key: {"status": "enabled"}}})
    moved = oracle.DbSnapshot({"APPL_DB": {"LAG_MEMBER_TABLE:PortChannel12:Ethernet52": {"status": "enabled"}}})
    assert sorted(d.kind for d in oracle.diff(before, moved)) == ["extra", "missing"]
    changed = oracle.diff(before, oracle.DbSnapshot({"APPL_DB": {key: {"status": "disabled"}}}))
    assert changed[0].kind == "changed" and changed[0].detail == {"status": ("enabled", "disabled")}

    # denoise: the platform-telemetry churn measured on a lab switch must not reach the diff,
    # and a real change in the same snapshot must still come through.
    noisy_a = oracle.DbSnapshot({"STATE_DB": {
        "TEMPERATURE_INFO|ASIC": {"timestamp": "1", "temperature": "40"},
        "PROCESS_STATS|104557": {"cpu": "1"},
        "LAG_MEMBER_TABLE|PortChannel101|Ethernet12": {"status": "enabled"},
    }, "APPL_DB": {"GEARBOX_TABLE_KEY_SET": {"_": ["a"]}}})
    noisy_b = oracle.DbSnapshot({"STATE_DB": {
        "TEMPERATURE_INFO|ASIC": {"timestamp": "2", "temperature": "41"},
        "LAG_MEMBER_TABLE|PortChannel101|Ethernet12": {"status": "disabled"},
    }, "APPL_DB": {"GEARBOX_TABLE_KEY_SET": {"_": ["a", "b"]}}})
    quiet = oracle.diff(noisy_a, noisy_b)
    assert len(quiet) == 1 and quiet[0].key.startswith("LAG_MEMBER_TABLE"), quiet
    assert len(oracle.diff(noisy_a, noisy_b, denoise=False)) == 4   # raw sees all of it
    assert oracle.table_of("PROCESS_STATS|104557") == "PROCESS_STATS"
    assert oracle.table_of("LLDP_ENTRY_TABLE:Ethernet0") == "LLDP_ENTRY_TABLE"
    assert oracle.is_volatile_key("APPL_DB_GEARBOX_TABLE_KEY_SET")

    # narrow snapshots: every parity invariant declares what it reads, and the union is small
    pre = oracle.prefixes_for("parity")
    assert set(pre) == {"APPL_DB", "ASIC_DB"}, pre
    assert "LAG_MEMBER_TABLE:" in pre["APPL_DB"] and "NEIGH_TABLE:" in pre["APPL_DB"]
    assert oracle.prefixes_for("health") == {}                       # health asks the DUT, reads no rows
    assert oracle.prefixes_for("signal") == {"APPL_DB": ["*_KEY_SET"], "ASIC_DB": ["*_KEY_SET"]}
    for name in oracle.group_members("parity"):
        if name != "route_check":
            assert oracle.INVARIANT_PREFIXES[name], "{} declares no prefixes".format(name)

    # baseline subtraction: what was already wrong is not a finding
    d1 = oracle.Divergence("lag_member", "ASIC_DB", "k1", "stale")
    d2 = oracle.Divergence("lag_member", "ASIC_DB", "k2", "stale")
    assert oracle.subtract([d1, d2], oracle.finding_keys([d1])) == [d2]
    assert oracle.subtract([d1], None) == [d1]

    # wait_consistent polls until clean, and gives up at the budget -- with a fake clock
    class _Clock(object):
        def __init__(self):
            self.t = 0.0

        def now(self):
            return self.t

        def sleep(self, secs):
            self.t += secs

    calls = {"n": 0}
    fake = _FakeDut("fixture")            # wait_consistent logs duthost.hostname while polling
    healthy = _lab_snapshot()
    broken = _lab_snapshot(APPL_DB={"LAG_MEMBER_TABLE:PortChannel101:Ethernet12": None})
    real_snapshot_for = oracle.snapshot_for
    try:
        def flaky(dut, only):                   # divergent twice, then clean
            calls["n"] += 1
            return broken if calls["n"] <= 2 else healthy
        oracle.snapshot_for = flaky
        clk = _Clock()
        found, _, elapsed, _ = oracle.wait_consistent(fake, "parity", timeout=60, interval=5,
                                                      sleep=clk.sleep, clock=clk.now)
        assert found == [] and calls["n"] == 3 and elapsed == 10.0, (found, calls, elapsed)

        calls["n"] = 0
        oracle.snapshot_for = lambda dut, only: broken   # never recovers
        clk = _Clock()
        found, _, elapsed, _ = oracle.wait_consistent(fake, "parity", timeout=12, interval=5,
                                                      sleep=clk.sleep, clock=clk.now)
        assert len(found) == 1 and found[0].kind == "lag_member" and elapsed >= 12, (found, elapsed)
    finally:
        oracle.snapshot_for = real_snapshot_for

    # invariants are registered, and run harmlessly against a disk-loaded snapshot (no duthost)
    assert {"route_check", "key_set_backlog", "lag_member", "lag", "neighbor", "vlan_member",
            "critical_processes", "no_cores", "bgp_established", "no_start_limit"} <= set(oracle.INVARIANTS), \
        sorted(oracle.INVARIANTS)
    # A bare snapshot carries no COUNTERS_DB name maps and no duthost, so every cross-DB invariant
    # must say "cannot check" -- and none may claim a real violation out of thin air.
    real, notices = oracle.split_unchecked(oracle.check(before))
    assert real == [], real
    assert {n.kind for n in notices} == {
        "lag_member:unchecked", "lag:unchecked", "neighbor:unchecked", "vlan_member:unchecked"}, \
        sorted(n.kind for n in notices)

    # experiment files: schema validation, and a seed that replays identically
    exp = Experiment.from_dict({
        "experiment": "selftest",
        "seed": 42,
        "duration": "10m",
        "min_gap": "60s",
        "count": 10,           # explicit: this block tests seeded REPETITION; the default is one per fault
        "steady_state": ["route_check"],
        "faults": [
            {"kill": {"process": "orchagent", "how": "restart", "weight": 3, "tag": "unsupported-op"}},
            {"pause": {"process": "orchagent", "seconds": 30, "weight": 1}},
        ],
        "contract": {"recover_within": "180s", "invariants": ["route_check"]},
    })
    assert exp.duration == 600 and exp.min_gap == 60 and exp.recover_within == 180
    assert [f.tag for f in exp.faults] == ["unsupported-op", "unsupported-op"]
    first, second = exp.schedule(), exp.schedule()
    assert len(first) == 10, len(first)                       # 600s / 60s gap
    assert [f.injector.describe() for _, f in first] == [f.injector.describe() for _, f in second], \
        "same seed must replay the same fault order"
    assert [o for o, _ in first] == list(range(0, 600, 60))
    assert first != exp.schedule(seed=999) or len({f.injector.name for _, f in first}) == 1
    # Without `count`, a file schedules each fault ONCE. Filling duration with min_gap slots turned
    # one kill into six on a lab switch and locked the switch at the second; nobody writing one fault
    # means "repeat until the clock runs out".
    once = Experiment.from_dict({"experiment": "once", "seed": 42, "duration": "10m", "min_gap": "90s",
                                 "faults": [{"kill": {"process": "orchagent"}},
                                            {"pause": {"process": "orchagent", "seconds": 10}}],
                                 "contract": {"invariants": ["route_check"]}})
    sched = once.schedule()
    assert len(sched) == 2 and {f.injector.name for _, f in sched} == {"kill", "pause"}, sched
    assert [o for o, _ in sched] == [0, 90]
    assert len(Experiment.from_dict({"experiment": "solo", "faults": [{"kill": {"process": "orchagent"}}],
                                     "contract": {"invariants": ["route_check"]}}).schedule()) == 1
    assert "each once" in once.describe()
    _expect_error(Experiment.from_dict, {"experiment": "x"})                      # no faults
    _expect_error(Experiment.from_dict, {"experiment": "x", "faults": [{"nope": {}}]})
    _expect_error(Experiment.from_dict, {"experiment": "x", "faults": [
        {"kill": {"process": "orchagent", "tag": "maybe"}}]})                     # bad tag
    _expect_error(Experiment.from_dict, {"experiment": "x", "duration": "ages",
                                         "faults": [{"kill": {"process": "orchagent"}}]})
    _expect_error(Experiment.from_dict, {"experiment": "x", "faults": [
        {"kill": {"process": "redis-server"}}]})                                  # force still required

    # --- Spine: the DUT-side primitives the lifecycle faults are built from -------------------

    # sonic-db-cli prints a Python dict repr, not JSON. Verified against a live 202511.2 box.
    assert parse_hgetall("{'admin_status': 'up', 'lanes': '25,26', 'description': ''}") == {
        "admin_status": "up", "lanes": "25,26", "description": ""}
    assert parse_hgetall("f1\nv1\nf2\nv2") == {"f1": "v1", "f2": "v2"}   # raw redis-cli shape
    assert parse_hgetall("") == {} and parse_hgetall(None) == {}

    # supervisorctl status, in all three shapes it actually emits
    parsed = parse_supervisor_status(
        "orchagent      RUNNING   pid 55, uptime 0:01:37\n"
        "gearsyncd      EXITED    Sep 11 07:57 AM\n"
        "portsyncd      FATAL     Exited too quickly (process log may have details)")
    assert parsed["orchagent"] == {"state": "RUNNING", "pid": 55, "uptime": "0:01:37",
                                   "raw": "orchagent      RUNNING   pid 55, uptime 0:01:37"}
    assert parsed["gearsyncd"]["state"] == "EXITED" and parsed["gearsyncd"]["pid"] is None
    assert parsed["portsyncd"]["state"] == "FATAL"
    assert parse_supervisor_status("") == {}

    # poll returns as soon as the condition holds, and gives up at the budget
    ticks = []
    assert poll(lambda: len(ticks) >= 3 or ticks.append(1), timeout=30, interval=0,
                sleep=lambda _: None)[0] is True
    assert poll(lambda: False, timeout=0.01, interval=0, sleep=lambda _: None)[0] is False

    # dead-man tags are filename-safe even for keys full of colons and pipes
    assert deadman_tag("pause", "swss", "orchagent") == "pause-swss-orchagent"
    assert "/" not in deadman_tag("corrupt", "APPL_DB:LAG|x/y")
    assert quote("a b") == "'a b'"

    # every Spine injector builds a real command, not a placeholder
    kill_restart = ChaosPlan.from_args(["kill=orchagent:how=restart"]).injectors[0]
    assert kill_restart.command() == "docker exec swss supervisorctl restart orchagent"
    assert ChaosPlan.from_args(["kill=orchagent"]).injectors[0].command() == \
        "docker exec swss pkill -9 -x orchagent"
    assert ChaosPlan.from_args(["kill=swss:how=container"]).injectors[0].command() == "docker restart swss"
    # how=container names a container, not a daemon inside one
    _expect_error(ChaosPlan.from_args, ["kill=container=swss"])            # how=sigkill needs a daemon
    _expect_error(ChaosPlan.from_args, ["pause=seconds=10:container=swss"])   # how=signal needs a daemon

    # expected_syslog is narrow: it covers supervisor's own exit chatter and nothing else
    patterns = kill_restart.expected_syslog()
    assert any("spawned" in p for p in patterns) and any("exited" in p for p in patterns)
    assert all("orchagent" in p for p in patterns), patterns
    # corrupt deliberately hides nothing: a daemon's complaint about a bad value is the finding
    assert ChaosPlan.from_args(["corrupt=APPL_DB:[x]:a=b"]).injectors[0].expected_syslog() == ()

    # --- Spine: repro bundles and the 20 runs / 3 FAIL ledger ---------------------------------

    assert bundle.sanitize("tests/pc/test_po.py::test_x[run3]") == "tests.pc.test_po.py.test_x.run3"
    assert "/" not in bundle.sanitize("a/b::c") and bundle.sanitize("") == "unnamed"
    cmd = bundle.repro_command(["kill=orchagent"], "tests/pc/test_po.py::test_x[run4]",
                               repeat=20, seed=20260911)
    # the parametrisation is stripped: you reproduce the test, not pytest's label for it
    assert cmd == ("pytest tests/pc/test_po.py::test_x --chaos kill=orchagent "
                   "--chaos-seed 20260911 --chaos-repeat 20"), cmd

    ledger = bundle.RunLedger()
    assert ledger.split("t.py::x[run3]") == ("t.py::x", "run3")
    assert ledger.split("t.py::x") == ("t.py::x", None)
    for i in range(1, 21):
        ledger.record("t.py::x[run{}]".format(i), passed=i not in (4, 11, 17), bundle=None)
    (nodeid, verdict, failed, _), = ledger.lines()
    assert verdict == "20 runs / 3 FAIL", verdict
    assert failed == ["run4", "run11", "run17"], failed
    assert list(ledger.flaky()) == ["t.py::x"]          # some passed, some failed: a real finding
    steady = bundle.RunLedger()
    for i in range(1, 4):
        steady.record("t.py::y[run{}]".format(i), passed=False)
    assert not steady.flaky(), "failing every time is broken, not flaky"
    assert steady.lines()[0][1] == "3 runs / 3 FAIL"

    # the Squeeze agent, end to end against a fake box
    squeeze_checks()

    # groups: an end user picks parity/health/signal/all, never a list of invariant names
    assert set(oracle.GROUPS) == {"parity", "health", "signal"}, oracle.GROUPS
    assert oracle.group_members("parity") == ["lag", "lag_member", "neighbor", "route_check",
                                              "vlan", "vlan_member"], oracle.group_members("parity")
    assert oracle.group_members("health") == ["bgp_established", "critical_processes",
                                              "no_cores", "no_start_limit"], oracle.group_members("health")
    assert oracle.group_members("signal") == ["key_set_backlog"]
    assert set(oracle.resolve("all")) == set(oracle.INVARIANTS)
    assert oracle.resolve(["parity", "no_cores"]) == sorted(
        set(oracle.group_members("parity")) | {"no_cores"})
    # every invariant belongs to exactly one group -- an untagged one would vanish from "parity"
    # and from "all"-by-group, and nobody would notice it had stopped running
    assert set(oracle.INVARIANT_GROUP) == set(oracle.INVARIANTS), "an invariant has no group"

    # both default to parity, so a config need not enumerate anything
    defaults = Experiment.from_dict({"experiment": "d", "faults": [{"kill": {"process": "orchagent"}}]})
    assert defaults.steady_state == oracle.group_members("parity"), defaults.steady_state
    assert defaults.invariants == oracle.group_members("parity"), defaults.invariants
    grouped = Experiment.from_dict({"experiment": "g", "faults": [{"kill": {"process": "orchagent"}}],
                                    "steady_state": "all", "contract": {"invariants": "health"}})
    assert grouped.invariants == oracle.group_members("health"), grouped.invariants
    assert len(grouped.steady_state) == len(oracle.INVARIANTS)

    # invariant names in steady_state / contract must name something that exists, or the run
    # would report "all invariants passed" having quietly verified less than it claims
    _expect_error(Experiment.from_dict, {
        "experiment": "x", "faults": [{"kill": {"process": "orchagent"}}],
        "steady_state": ["route_check", "totally_made_up"]})
    _expect_error(Experiment.from_dict, {
        "experiment": "x", "faults": [{"kill": {"process": "orchagent"}}],
        "contract": {"invariants": ["crm_baseline"]}})     # offered by the UI, not implemented
    ok = Experiment.from_dict({
        "experiment": "x", "faults": [{"kill": {"process": "orchagent"}}],
        "steady_state": ["route_check", "lag_member"],
        "contract": {"invariants": ["no_cores"]}})
    # resolve() sorts and de-duplicates, so the stored list is canonical rather than as-typed
    assert ok.steady_state == ["lag_member", "route_check"], ok.steady_state
    assert ok.invariants == ["no_cores"], ok.invariants

    # the shipped experiment file parses and schedules
    shipped = os.path.join(os.path.dirname(os.path.abspath(__file__)), "experiments",
                           "orchagent-restart.yml")
    live = Experiment.from_file(shipped)
    assert live.seed and live.faults and live.steady_state, live.describe()
    assert len(live.schedule()) == len(live.schedule()), "schedule must be deterministic"

    _check_shim_lane()
    check_oracle_invariants()
    check_vlan_invariant()
    check_vlan_member_invariant()
    check_fault_verdict()
    check_conditions()

    print("sonic-chaos contract OK: {} injectors ({}), {} invariants ({}), "
          "squeeze + shim OK".format(
              len(REGISTRY), ", ".join(sorted(REGISTRY)),
              len(oracle.INVARIANTS), ", ".join(sorted(oracle.INVARIANTS))))
    print(plan.describe())
    print("\nexperiment {} -> {} scheduled faults, first three:".format(
        os.path.basename(shipped), len(live.schedule())))
    for offset, fault in live.schedule()[:3]:
        print("  t+{:<4}s  {}".format(offset, fault.describe()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
