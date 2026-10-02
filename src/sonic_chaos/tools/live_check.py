"""Run every Spine injector against a real SONiC box and prove it puts the box back.

    sonic-chaos tool live-check --dut ssh://admin@<switch>
    SONIC_CHAOS_SSH='sshpass -p X ssh -o StrictHostKeyChecking=no admin@10.0.0.5' python3 ... --only corrupt

Unit tests assert that an injector *issues* the right command. Only a real box can tell you the
command works: that ``docker top``'s columns are where you think, that ``sonic-db-cli`` prints a
Python dict rather than JSON, that ``pkill -x`` matches the daemon's name, and -- the one that
matters on a shared testbed -- that ``release`` actually restores the box.

Every check is its own fault-and-restore cycle and verifies the *restore*, not just the fault.
The last one deliberately skips ``release`` to prove the DUT-side dead-man timer recovers the
box on its own, which is the guarantee that a dropped SSH session cannot strand a daemon.

Exit code 0 means every injector applied, took effect, and was undone.
"""
import argparse
import sys
import time


from .. import injectors                                          # noqa: F401,E402
from ..injector import (                                         # noqa: E402
    ChaosPlan, supervisor_status, resolve_pid, hgetall, DEADMAN_DIR,
)
from . import target_dut                                # noqa: E402


class Checks(object):
    def __init__(self, dut):
        self.dut = dut
        self.results = []

    def run(self, name, fn, gate=True):
        print("\n--- {} ".format(name).ljust(78, "-"))
        start = time.time()
        try:
            if gate:
                waited = wait_healthy(self.dut)
                if waited:
                    print("    (waited {}s for the box to be healthy first)".format(waited))
            detail = fn() or ""
            ok, err = True, ""
        except Exception as exc:
            ok, err, detail = False, "{}: {}".format(type(exc).__name__, exc), ""
        elapsed = round(time.time() - start, 1)
        print("    {} {} ({}s) {}".format("PASS" if ok else "FAIL", name, elapsed, err))
        self.results.append((name, ok, err, detail, elapsed))
        return ok

    def report(self):
        failed = [r for r in self.results if not r[1]]
        print("\n" + "=" * 78)
        for name, ok, err, detail, elapsed in self.results:
            print("  {:<4} {:<26} {:>6}s  {}".format("PASS" if ok else "FAIL", name, elapsed,
                                                     detail or err))
        print("=" * 78)
        print("{} of {} checks passed".format(len(self.results) - len(failed), len(self.results)))
        return 1 if failed else 0


def build(spec):
    return ChaosPlan.from_args([spec]).injectors[0]


def wait_healthy(dut, timeout=300):
    """Block until swss is up and orchagent is RUNNING again.

    Run before every check so that one check's blast radius cannot fail the next one. It is
    needed: on a VS, ``kill -9 orchagent`` takes the whole swss container down with it and the
    box needs a couple of minutes to come back -- which is the whole-container blast radius the plan
    warns about, observed here rather than assumed.
    """
    start = time.time()
    while time.time() - start < timeout:
        entry = supervisor_status(dut, "swss", "orchagent")
        if entry.get("state") == "RUNNING":
            return round(time.time() - start, 1)
        time.sleep(5)
    raise AssertionError("orchagent was still not RUNNING after {}s -- the box has not recovered "
                         "from an earlier check and the rest cannot be trusted".format(timeout))


# ------------------------------------------------------------------------------ the checks

def check_environment(dut):
    """Every assumption the Spine injectors make about the box, verified in one pass."""
    pid = resolve_pid(dut, "orchagent", "swss")
    assert pid, "resolve_pid found no orchagent -- docker top's column layout may have changed"

    entry = supervisor_status(dut, "swss", "orchagent")
    assert entry.get("state") == "RUNNING", "supervisorctl status parse failed: {}".format(entry)
    assert entry.get("pid"), "no pid parsed out of supervisorctl status: {}".format(entry)

    res = dut.shell("sonic-db-cli APPL_DB KEYS 'PORT_TABLE:*' | head -1", module_ignore_errors=True)
    key = (res.get("stdout") or "").strip().splitlines()[-1].strip()
    assert key, "no PORT_TABLE key found in APPL_DB"
    fields = hgetall(dut, "APPL_DB", key)
    assert fields, "HGETALL parse returned nothing for {} -- the output shape may have changed".format(key)

    return "orchagent host pid {}, supervisor pid {}, {} has {} fields".format(
        pid, entry["pid"], key, len(fields))


def check_corrupt(dut):
    """Corrupt one APPL_DB field, verify it took, release, verify the original came back exactly."""
    res = dut.shell("sonic-db-cli APPL_DB KEYS 'PORT_TABLE:Ethernet*' | head -1", module_ignore_errors=True)
    key = (res.get("stdout") or "").strip().splitlines()[-1].strip()
    original = hgetall(dut, "APPL_DB", key)
    assert "mtu" in original, "expected an mtu field on {}, got {}".format(key, sorted(original))

    injector = build("corrupt=APPL_DB:[{}]:mtu=BOGUS".format(key))
    injector.apply(dut)
    try:
        assert injector.status(dut)["active"], "corruption did not take effect"
        assert hgetall(dut, "APPL_DB", key)["mtu"] == "BOGUS"
    finally:
        injector.release(dut)

    after = hgetall(dut, "APPL_DB", key)
    assert after == original, "restore was not exact:\n  before={}\n  after ={}".format(original, after)
    return "{} mtu {} -> BOGUS -> {} (exact restore of {} fields)".format(
        key, original["mtu"], after["mtu"], len(original))


def check_pause(dut):
    """SIGSTOP orchagent, confirm the kernel really stopped it, thaw, confirm it is back."""
    injector = build("pause=orchagent:5")
    injector.apply(dut)
    try:
        assert injector.status(dut)["frozen"] is True, "process is not in state T after SIGSTOP"
    finally:
        injector.release(dut)

    assert injector.status(dut)["frozen"] is False, "process still stopped after release"
    armed = dut.shell("ls {}/ 2>/dev/null".format(DEADMAN_DIR), module_ignore_errors=True)
    leftover = [f for f in (armed.get("stdout") or "").split() if "pause" in f]
    assert not leftover, "release left dead-man files behind: {}".format(leftover)
    return "orchagent frozen (state T), thawed, dead-man disarmed"


def check_deadman(dut):
    """Freeze and then *walk away*: the box must thaw itself with no help from us.

    This is the guarantee that matters on a shared testbed. If the harness is killed, the SSH
    session drops, or someone hits Ctrl-C at the wrong moment, the daemon still comes back.
    """
    injector = build("pause=orchagent:2")
    injector.apply(dut)
    assert injector.status(dut)["frozen"] is True, "freeze did not take"

    # Deliberately no release(). The DUT-side timer is the only thing that can save us.
    deadline = time.time() + 60
    while time.time() < deadline:
        if injector.status(dut)["frozen"] is False:
            waited = round(60 - (deadline - time.time()), 1)
            dut.shell("rm -rf {}".format(DEADMAN_DIR), module_ignore_errors=True)
            return "box thawed itself after {}s with no release() call".format(waited)
        time.sleep(2)

    injector.release(dut)      # the dead-man failed; do not leave the box frozen regardless
    raise AssertionError("dead-man never fired: orchagent was still frozen after 60s")


def check_kill(dut):
    """kill -9 orchagent and confirm supervisor brings it back with a new pid."""
    # 240s, not 20s: on this platform killing orchagent takes the swss container down with it,
    # so "recovery" is a full container restart. A VS-sized settle would report a false finding.
    injector = build("kill=orchagent:settle=240")
    event = injector.apply(dut)
    assert event["recovered"], "orchagent did not come back within 240s (pid_before={}, after={})".format(
        event["pid_before"], event["pid_after"])
    assert event["pid_after"] != event["pid_before"], "pid unchanged: the kill did not land"
    return "pid {} -> {} in {}s".format(event["pid_before"], event["pid_after"],
                                        event["recovered_after_s"])


def check_redis(dut):
    """Resolve orchagent's redis connections and sever them.

    Attribution is the hard part and the reason this check exists: every client in CLIENT LIST
    has the same unix-socket address and an empty name, so the resolver pairs socket inodes.

    What the check asserts is that the *injection* worked -- connections were attributed to
    orchagent and killed. Whether orchagent then reconnects is the DUT's behaviour, which is the
    question the fault exists to ask, so it is polled for and reported rather than asserted. On
    a 202511.2 VS it does not: orchagent stays up on the same pid, logs one
    ``poll_descriptors: readData error`` per severed connection, and does not re-establish them
    while idle. That is a finding to hand to the Oracle lane, not a broken injector.
    """
    injector = build("redis=client_kill:orchagent")
    event = injector.apply(dut)
    assert event["client_ids"] > 0, "resolved no connections for orchagent"
    assert event["killed"] > 0, "CLIENT KILL reported 0 killed"

    connections, waited = poll_reconnect(injector, dut, budget=30)
    verdict = "reconnected {} within {}s".format(connections, waited) if connections else \
        "did NOT reconnect within 30s (finding: orchagent stays up, connections stay gone)"
    return "resolved {}, killed {}; orchagent {}".format(
        event["client_ids"], event["killed"], verdict)


def poll_reconnect(injector, dut, budget):
    """How many connections the target holds again, and how long that took."""
    start = time.time()
    while time.time() - start < budget:
        count = injector.status(dut)["achieved"]["connections_now"]
        if count:
            return count, round(time.time() - start, 1)
        time.sleep(3)
    return 0, budget


def check_syslog(dut):
    """Flood syslog briefly and assert lines were actually DELIVERED.

    This check exists because its absence hid a bug. apply() used to report a successful flood
    while delivering nothing: `docker cp` failed because DEADMAN_DIR does not exist inside the
    container, its rc was never checked, and the `docker exec -d` that followed returns 0
    whether or not the script is there. Every layer above the box agreed the flood had run.

    So the assertion here is deliberately on delivery, not on the injector's own report. An
    injector that grades its own homework is how that bug survived.
    """
    ident = "chaoslive{}".format(int(time.time()) % 100000)
    injector = build("syslog=2000:seconds=5:ident={}".format(ident))
    event = injector.apply(dut)
    assert event["verified_running"], "apply returned without confirming the generator was alive"
    assert injector._running(dut), "generator is not in the container's process table"

    time.sleep(8)                                   # let the bounded flood finish
    state = injector.status(dut)
    injector.release(dut)

    delivered = state["delivered"]
    assert delivered > 0, (
        "the flood reported success but delivered 0 lines tagged {!r} -- this is exactly the "
        "silent failure the check was added for".format(ident))
    assert not injector._running(dut), "generator still alive after release"
    return "{} of {} attempted lines delivered ({}% dropped), /var/log at {}%".format(
        delivered, state["attempted"], state["achieved"]["drop_pct"], state["achieved"]["disk_pct"])


def check_kill_restart(dut):
    """The cold-restart route-loss shape: a cold, orchagent-only restart via supervisorctl."""
    injector = build("kill=orchagent:how=restart:settle=240")
    event = injector.apply(dut)
    assert event["recovered"], "orchagent did not come back after supervisorctl restart"
    return "supervisorctl restart -> pid {} in {}s".format(event["pid_after"], event["recovered_after_s"])


# Cheapest and least disruptive first, so a failure early is a harness problem rather than the
# wreckage of the previous check. kill last: it is the one that cycles a whole container.
CHECKS = [
    ("environment", check_environment),
    ("corrupt", check_corrupt),
    ("pause", check_pause),
    ("deadman", check_deadman),
    ("redis", check_redis),
    ("syslog", check_syslog),
    ("kill-restart", check_kill_restart),
    ("kill", check_kill),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="*", help="run only these checks")
    args = parser.parse_args()

    dut = target_dut()
    print("sonic-chaos live check against {}".format(dut.hostname))

    checks = Checks(dut)
    for name, fn in CHECKS:
        if args.only and name not in args.only:
            continue
        checks.run(name, lambda fn=fn: fn(dut))
    return checks.report()


if __name__ == "__main__":
    sys.exit(main())
