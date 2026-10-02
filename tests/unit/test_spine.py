"""Unit tests for the sonic-chaos Spine lane: lifecycle faults and the harness around them.

No DUT and no testbed. ``FakeDut`` records every command the injector issues and replays canned
output for it, so these tests assert the two things that actually matter about a fault injector
and cannot be checked by reading the code:

  * it issues the *right command* against the DUT, and
  * it *puts the box back* -- exactly, on every path, including the ones where something broke.

The canned output is copied from a live 202511.2 SONiC box (``supervisorctl status``,
``sonic-db-cli HGETALL``, ``docker top``), so a change in those formats fails here rather than
silently returning None on a testbed at hour 14.

Ported from sonic-mgmt ``tests/common/unit_tests/hypersonic/unit_test_spine.py``
(hypersonic @ b401b85d4). ``FakeDut`` is now ``sonic_chaos.testing.RecordingDut``; the tests are
unchanged. Run from the repo root::

    python3 -m pytest tests/unit/test_spine.py
"""
import os
import re
import shlex

import pytest

from sonic_chaos import bundle                                    # noqa: E402
from sonic_chaos import injectors                                 # noqa: F401,E402  registers them
from sonic_chaos.testing import RecordingDut                   # noqa: E402
from sonic_chaos.injector import (                                # noqa: E402
    ChaosPlan, ChaosSession, ChaosUsageError, DEADMAN_DIR,
)

# Real output, copied off a live box. If SONiC changes these shapes, these tests are the alarm.
SUPERVISOR_RUNNING = "orchagent                        RUNNING   pid 55, uptime 0:01:37"
SUPERVISOR_RESTARTED = "orchagent                        RUNNING   pid 912, uptime 0:00:02"
SUPERVISOR_FATAL = "orchagent                        FATAL     Exited too quickly (process log may have details)"
HGETALL_PORT = ("{'admin_status': 'up', 'alias': 'fortyGigE0/0', 'index': '0', "
                "'lanes': '25,26,27,28', 'mtu': '9100', 'speed': '40000'}")
# resolve_pid pushes its awk to the DUT, so the shell returns just the pid, not the table.
# (The awk itself is covered by the live check in scripts/live_check.py, against a real box.)
DOCKER_TOP_PID = "8016"
REDIS_TOP_PID = "1156"


# The recorder these tests were written against, now shared by every suite here.
FakeDut = RecordingDut


def tokens(cmd):
    """Shell-tokenise a command so assertions test the *arguments*, not shlex's quoting taste.

    ``shlex.quote`` only adds quotes when a value needs them, so ``PORT_TABLE:Ethernet0`` comes
    through bare while ``PORTCHANNEL_MEMBER|PortChannel12|Ethernet48`` is quoted. Both are
    correct; asserting on the literal string would make the tests fail for the wrong reason.
    """
    return shlex.split(cmd)


def hset_fields(cmd):
    """``sonic-db-cli APPL_DB HSET key f1 v1 f2 v2`` -> ``{"f1": "v1", "f2": "v2"}``."""
    parts = tokens(cmd)
    rest = parts[parts.index("HSET") + 2:]
    return dict(zip(rest[::2], rest[1::2]))


def build(spec):
    """``build("kill=orchagent")`` -> the configured injector, through the real CLI path."""
    return ChaosPlan.from_args([spec]).injectors[0]


def running_dut(**kwargs):
    """A DUT where the container is up and orchagent is RUNNING."""
    responses = [(r"docker inspect .*State\.Running", 0, "true"),
                 (r"supervisorctl status", 0, SUPERVISOR_RUNNING)]
    return FakeDut(responses=responses, **kwargs)


# ------------------------------------------------------------------------------- kill

class TestKill(object):
    """The headline Spine fault: an event injector whose release is a no-op by design."""

    def test_sigkill_issues_pkill_and_waits_for_a_new_pid(self):
        dut = FakeDut(responses=[(r"docker inspect .*State\.Running", 0, "true")],
                      sequences={r"supervisorctl status": [SUPERVISOR_RUNNING, SUPERVISOR_RESTARTED]})
        event = build("kill=orchagent").apply(dut)

        assert dut.ran_once(r"pkill") == "docker exec swss pkill -9 -x orchagent"
        # Recovery means a *different* pid: supervisor restarts fast enough that a status check
        # right after the kill can still report the old, already-dead process.
        assert event["pid_before"] == 55 and event["pid_after"] == 912
        assert event["recovered"] is True

    def test_restart_uses_supervisorctl_not_a_signal(self):
        dut = running_dut()
        build("kill=orchagent:how=restart").apply(dut)
        assert dut.ran_once(r"supervisorctl restart") == "docker exec swss supervisorctl restart orchagent"
        assert not dut.ran(r"pkill")

    def test_container_restart_targets_the_container(self):
        dut = FakeDut(responses=[(r"docker inspect .*State\.Running", 0, "true"),
                                 (r"supervisorctl status", 0, SUPERVISOR_RUNNING)])
        build("kill=swss:how=container").apply(dut)
        assert dut.ran_once(r"docker restart") == "docker restart swss"

    def test_a_daemon_that_never_comes_back_is_a_finding_not_an_error(self):
        """The box failing to recover is the *result*, so apply must not raise.

        A fixture that raised here would turn the most interesting outcome sonic-chaos can
        produce into a pytest ERROR pointing at our own harness instead of at the bug.
        """
        dut = FakeDut(responses=[(r"docker inspect .*State\.Running", 0, "true"),
                                 (r"supervisorctl status", 0, SUPERVISOR_FATAL)])
        event = build("kill=orchagent:settle=0").apply(dut)
        assert event["recovered"] is False
        assert build("kill=orchagent:settle=0").status(dut)["state"] == "FATAL"

    def test_a_failed_injection_does_raise(self):
        """Our own command failing is our bug, and must never be reported as 'no divergence'."""
        dut = FakeDut(responses=[(r"docker inspect", 0, "true"),
                                 (r"supervisorctl status", 0, SUPERVISOR_RUNNING),
                                 (r"pkill", 1, "Error: No such container: swss")])
        with pytest.raises(RuntimeError, match="injection command failed"):
            build("kill=orchagent").apply(dut)

    def test_release_touches_nothing(self):
        dut = running_dut()
        build("kill=orchagent").release(dut)
        assert dut.commands == []

    def test_targets_by_process_or_by_container(self):
        """A daemon name and a container name both work, and each resolves to the other."""
        daemon = build("kill=orchagent")
        assert daemon.params["process"] == "orchagent" and daemon.params["container"] == "swss"
        whole = build("kill=swss:how=container")
        assert whole.params["process"] is None and whole.params["container"] == "swss"
        explicit = build("kill=container=swss:how=container")
        assert explicit.command() == "docker restart swss"
        assert build("kill=process=bgpd:how=restart").params["container"] == "bgp"

    def test_a_process_contradicting_its_container_is_refused(self):
        with pytest.raises(ChaosUsageError, match="runs in container 'swss', not 'bgp'"):
            build("kill=process=orchagent:container=bgp")

    def test_a_daemon_action_needs_a_daemon(self):
        """`pkill -x swss` matches nothing, so a container name with how=sigkill is a silent
        no-op. Refuse it and say which flag to use instead."""
        with pytest.raises(ChaosUsageError, match="acts on a daemon"):
            build("kill=container=swss")

    def test_a_container_target_still_describes_its_own_syslog(self):
        patterns = build("kill=swss:how=container").expected_syslog()
        assert patterns and all(isinstance(x, str) for x in patterns)

    def test_expected_syslog_covers_supervisor_noise_only(self):
        patterns = build("kill=orchagent").expected_syslog()
        assert any(re.search(p, ".* INFO spawned: 'orchagent' with pid 912") for p in patterns)
        # The daemon's own errors must still reach loganalyzer -- they are the finding.
        assert not any(re.search(p, "ERR swss#orchagent: :- handleSaiFailure: ASIC sync failed")
                       for p in patterns)


# ------------------------------------------------------------------------------- corrupt

class TestCorrupt(object):
    """A state fault: what it changes, it must change back exactly."""

    def test_sets_the_field_and_restores_the_original_on_release(self):
        dut = FakeDut(sequences={r"HGETALL": [HGETALL_PORT,
                                              HGETALL_PORT.replace("'up'", "'garbage'")]})
        injector = build("corrupt=APPL_DB:[PORT_TABLE:Ethernet0]:admin_status=garbage")
        injector.apply(dut)
        assert tokens(dut.ran_once(r"HSET")) == [
            "sonic-db-cli", "APPL_DB", "HSET", "PORT_TABLE:Ethernet0", "admin_status", "garbage"]

        dut.commands = []
        injector.release(dut)
        restored = hset_fields(dut.ran_once(r"HSET"))
        # Every original field goes back, not just the one we changed.
        assert restored["admin_status"] == "up" and restored["mtu"] == "9100"
        assert not dut.ran(r"HDEL")          # we invented nothing, so nothing to delete

    def test_release_deletes_fields_that_did_not_exist_before(self):
        """Restoring a superset of the truth is still a corrupted box."""
        dut = FakeDut(sequences={r"HGETALL": [HGETALL_PORT,
                                              HGETALL_PORT[:-1] + ", 'invented': 'x'}"]})
        injector = build("corrupt=APPL_DB:[PORT_TABLE:Ethernet0]:invented=x")
        injector.apply(dut)
        dut.commands = []
        injector.release(dut)
        assert tokens(dut.ran_once(r"HDEL")) == [
            "sonic-db-cli", "APPL_DB", "HDEL", "PORT_TABLE:Ethernet0", "invented"]

    def test_a_key_we_created_is_deleted_on_release(self):
        dut = FakeDut(sequences={r"HGETALL": ["", "{'a': 'b'}"]})
        injector = build("corrupt=APPL_DB:[NEW_TABLE:x]:a=b")
        injector.apply(dut)
        dut.commands = []
        injector.release(dut)
        assert tokens(dut.ran_once(r"DEL")) == ["sonic-db-cli", "APPL_DB", "DEL", "NEW_TABLE:x"]

    def test_delete_saves_the_hash_first_then_restores_it(self):
        dut = FakeDut(sequences={r"HGETALL": [HGETALL_PORT, ""]})
        injector = build("corrupt=APPL_DB:[PORT_TABLE:Ethernet0]:delete=true")
        injector.apply(dut)
        assert dut.ran_once(r" DEL ")
        dut.commands = []
        injector.release(dut)
        assert hset_fields(dut.ran_once(r"HSET"))["admin_status"] == "up"

    def test_applying_twice_still_restores_the_pristine_value(self):
        """Idempotent apply: the second apply must not record our own corruption as 'original'."""
        corrupted = HGETALL_PORT.replace("'up'", "'garbage'")
        dut = FakeDut(sequences={r"HGETALL": [HGETALL_PORT, corrupted, corrupted, corrupted]})
        injector = build("corrupt=APPL_DB:[PORT_TABLE:Ethernet0]:admin_status=garbage")
        injector.apply(dut)
        injector.apply(dut)
        dut.commands = []
        injector.release(dut)
        assert hset_fields(dut.ran_once(r"HSET"))["admin_status"] == "up"

    def test_release_is_safe_twice_and_without_apply(self):
        dut = FakeDut()
        injector = build("corrupt=APPL_DB:[PORT_TABLE:Ethernet0]:admin_status=x")
        injector.release(dut)                 # never applied here
        assert dut.commands == []

    def test_a_write_that_did_not_take_raises(self):
        """The owning daemon overwriting us instantly would otherwise look like a clean run."""
        dut = FakeDut(sequences={r"HGETALL": [HGETALL_PORT, HGETALL_PORT]})
        with pytest.raises(RuntimeError, match="did not take effect"):
            build("corrupt=APPL_DB:[PORT_TABLE:Ethernet0]:admin_status=garbage").apply(dut)

    def test_deleting_a_key_that_is_not_there_raises(self):
        dut = FakeDut(sequences={r"HGETALL": [""]})
        with pytest.raises(RuntimeError, match="nothing to delete"):
            build("corrupt=APPL_DB:[GONE:x]:delete=true").apply(dut)


# ------------------------------------------------------------------------------- pause

class TestPause(object):
    """A freeze must be undone by either of two independent paths."""

    def test_freezes_and_arms_a_dut_side_thaw(self):
        dut = FakeDut(responses=[(r"mkdir -p .*cat >", 0, "4242")])
        event = build("pause=orchagent:10").apply(dut)

        assert dut.ran_once(r"pkill -STOP") == "docker exec swss pkill -STOP -x orchagent"
        # The dead-man is what makes this safe on a shared box: if the harness dies here, the
        # box thaws itself anyway.
        armed = dut.ran_once(r"nohup setsid")
        assert "pkill -CONT -x orchagent" in armed
        assert "sleep 20" in armed, "thaw must outlast the 10 s freeze, with grace"
        assert event["deadman_pid"] == 4242

    def test_apply_does_not_block_for_the_freeze_duration(self):
        """The test is what should experience the freeze, not the fixture that set it up."""
        import time
        dut = FakeDut()
        start = time.time()
        build("pause=orchagent:300").apply(dut)
        assert time.time() - start < 5

    def test_release_thaws_and_disarms(self):
        dut = FakeDut()
        injector = build("pause=orchagent:10")
        injector.apply(dut)
        dut.commands = []
        injector.release(dut)
        assert dut.ran_once(r"pkill -CONT") == "docker exec swss pkill -CONT -x orchagent"
        assert dut.ran(r"rm -f {}".format(DEADMAN_DIR)), "the dead-man must be cancelled"

    def test_release_is_safe_twice(self):
        dut = FakeDut()
        injector = build("pause=orchagent:10")
        injector.release(dut)
        injector.release(dut)     # thawing a running process is harmless by design

    def test_status_reads_the_stopped_process_state(self):
        frozen = FakeDut(responses=[(r"ps -o stat", 0, "T    orchagent")])
        assert build("pause=orchagent:10").status(frozen)["frozen"] is True
        awake = FakeDut(responses=[(r"ps -o stat", 0, "Ssl  orchagent")])
        assert build("pause=orchagent:10").status(awake)["frozen"] is False

    def test_targets_by_process_or_by_container(self):
        daemon = build("pause=orchagent:10")
        assert daemon.params["process"] == "orchagent" and daemon.params["container"] == "swss"
        assert daemon.freeze_cmd() == "docker exec swss pkill -STOP -x orchagent"

        whole = build("pause=swss:10:how=docker")
        assert whole.params["process"] is None
        assert whole.freeze_cmd() == "docker pause swss"
        assert build("pause=seconds=10:container=swss:how=docker").freeze_cmd() == "docker pause swss"
        assert build("pause=10:process=bgpd").params["container"] == "bgp"

    def test_a_process_contradicting_its_container_is_refused(self):
        with pytest.raises(ChaosUsageError, match="runs in container 'swss', not 'bgp'"):
            build("pause=10:process=orchagent:container=bgp")

    def test_freezing_a_daemon_needs_a_daemon(self):
        """`pkill -STOP -x swss` matches no process, so this would freeze nothing at all."""
        with pytest.raises(ChaosUsageError, match="freezes a daemon"):
            build("pause=seconds=10:container=swss")

    def test_a_container_freeze_describes_its_own_syslog(self):
        assert build("pause=swss:10:how=docker").expected_syslog()

    def test_a_failed_freeze_raises(self):
        dut = FakeDut(responses=[(r"pkill -STOP", 1, "no process found")])
        with pytest.raises(RuntimeError, match="freeze failed"):
            build("pause=orchagent:10").apply(dut)


# ------------------------------------------------------------------------------- redis

class TestRedis(object):
    """Attribution is the whole difficulty: every client looks identical in CLIENT LIST."""

    def test_client_kill_resolves_through_the_dut_side_resolver(self):
        dut = FakeDut(responses=[
            (r"docker top database", 0, REDIS_TOP_PID),
            (r"docker top swss", 0, DOCKER_TOP_PID),
            (r"redis_clients\.py", 0,
             '{"target_sockets": 640, "matched_fds": 600, "client_ids": 600, "killed": 600}'),
        ])
        event = build("redis=client_kill:orchagent").apply(dut)
        assert event["killed"] == 600 and event["client_ids"] == 600
        # The resolver is pushed and run on the box: 600 CLIENT KILLs from here would be 600
        # round trips.
        assert dut.ran(r"cat > {}/redis_clients.py".format(DEADMAN_DIR))
        assert "kill" in dut.ran_once(r"python3 .*redis_clients\.py")

    def test_killing_zero_connections_raises(self):
        """A fault that did nothing must not be reported as 'ran clean, no divergence'."""
        dut = FakeDut(responses=[
            (r"docker top database", 0, REDIS_TOP_PID),
            (r"docker top swss", 0, DOCKER_TOP_PID),
            (r"redis_clients\.py", 0, '{"target_sockets": 0, "matched_fds": 0, "client_ids": 0, "killed": 0}'),
        ])
        with pytest.raises(RuntimeError, match="resolved 0 redis connections"):
            build("redis=client_kill:orchagent").apply(dut)

    def test_a_dead_target_raises_rather_than_killing_nothing(self):
        dut = FakeDut(responses=[(r"docker top", 0, "")])   # awk matched nothing: not running
        with pytest.raises(RuntimeError, match="not running"):
            build("redis=client_kill:orchagent").apply(dut)

    def test_sleep_blocks_the_bus_and_self_releases(self):
        dut = FakeDut()
        build("redis=sleep:2000").apply(dut)
        assert dut.ran_once(r"DEBUG SLEEP") == "sonic-db-cli APPL_DB DEBUG SLEEP 2.0"
        dut.commands = []
        build("redis=sleep:2000").release(dut)
        assert dut.commands == []

    def test_sleep_is_capped_below_the_supervisor_health_check(self):
        with pytest.raises(ChaosUsageError, match="supervisor restarts containers"):
            build("redis=sleep:60000")


# ------------------------------------------------------------------------------- syslog

def flooding_dut(**kwargs):
    """A DUT with disk headroom where the generator does come up."""
    return FakeDut(responses=[(r"df --output=pcent", 0, " 12%"),
                              (r"grep -c", 0, "0"),
                              (r"pgrep -f", 0, "yes")], **kwargs)


class TestSyslog(object):

    def test_refuses_to_flood_a_disk_that_is_already_full(self):
        dut = FakeDut(responses=[(r"df --output=pcent", 0, " 91%")])
        with pytest.raises(RuntimeError, match="Refusing to flood"):
            build("syslog=5000:seconds=30").apply(dut)

    def test_starts_a_bounded_generator_and_stops_it_on_release(self):
        dut = flooding_dut()
        injector = build("syslog=5000:seconds=30")
        injector.apply(dut)
        assert dut.ran(r"docker exec -d swss sh")
        assert dut.ran(r"nohup setsid"), "the flood needs a dead-man too"
        dut.commands = []
        injector.release(dut)
        assert dut.ran(r"pkill -f")
        # Truncating the log would destroy the evidence the flood exists to threaten.
        assert not dut.ran(r"truncate|rm -f /var/log|> /var/log/syslog")

    # -- the silent-success bug, found on a real box ----------------------------------------

    def test_a_generator_that_did_not_start_raises(self):
        """`docker exec -d` returns 0 whether or not the script exists, because a detached exec
        never waits. Trusting that rc is what let this injector report a flood it never ran."""
        dut = FakeDut(responses=[(r"df --output=pcent", 0, " 12%"),
                                 (r"grep -c", 0, "0"),
                                 (r"pgrep -f", 0, "no")])       # nothing running afterwards
        with pytest.raises(RuntimeError, match="not running"):
            build("syslog=5000:seconds=30").apply(dut)

    def test_detached_exec_returning_zero_is_not_treated_as_success(self):
        dut = FakeDut(responses=[(r"df --output=pcent", 0, " 12%"),
                                 (r"grep -c", 0, "0"),
                                 (r"docker exec -d", 0, ""),     # the lie
                                 (r"pgrep -f", 0, "no")])
        with pytest.raises(RuntimeError):
            build("syslog=5000:seconds=30").apply(dut)

    # -- severity, and the parameter name that used to collide ------------------------------

    def test_floods_at_the_requested_facility_and_severity(self):
        dut = flooding_dut()
        injector = build("syslog=5000:seconds=30:severity=debug:facility=local0")
        assert "-p local0.debug" in injector.generator_script()
        injector.apply(dut)

    def test_rejects_a_severity_syslog_does_not_have(self):
        with pytest.raises(ChaosUsageError, match="severity must be one of"):
            build("syslog=100:severity=loud")

    def test_counts_delivery_with_sudo(self):
        """/var/log/syslog is root:adm 0640, so an unprivileged read returns nothing."""
        dut = flooding_dut()
        build("syslog=100:ident=xyz").status(dut)
        assert dut.ran(r"sudo grep -c"), dut.commands

    def test_an_unreadable_log_reports_unknown_not_zero(self):
        """Reporting 0 delivered for a log we could not read invents a 100% drop rate."""
        dut = FakeDut(responses=[(r"grep -c", 2, "Permission denied"),
                                 (r"pgrep -f", 0, "no")])
        state = build("syslog=100:seconds=10").status(dut)
        assert state["delivered"] is None
        assert state["achieved"]["drop_pct"] is None, "a failed measurement is not a finding"

    def test_a_genuinely_absent_tag_is_a_real_zero(self):
        dut = FakeDut(responses=[(r"grep -c", 1, ""),          # grep: no match
                                 (r"pgrep -f", 0, "no")])
        injector = build("syslog=100:seconds=10")
        assert injector._delivered(dut) == 0

    def test_every_flooded_line_is_unique(self):
        """rsyslog collapses repeated identical messages, so a constant payload floods nothing:
        a 3 s run at 2000/s delivered one line on a real box until the counter was added."""
        script = build("syslog=2000:seconds=3").generator_script()
        assert "$n-$i" in script, script

    def test_the_script_is_passed_inline_not_copied(self):
        """The container's /tmp is a tmpfs, which docker cp cannot write into."""
        dut = flooding_dut()
        build("syslog=100:seconds=5").apply(dut)
        assert not dut.ran(r"docker cp"), "docker cp into a tmpfs /tmp always fails"
        assert dut.ran(r"docker exec -d swss sh -c")

    # -- targeting: a process, a container, or neither --------------------------------------

    def test_a_process_resolves_to_its_own_container(self):
        """Naming a daemon is the useful form: the flood then competes with that daemon's own
        logging, which is the question this fault asks."""
        assert build("syslog=5000:process=orchagent").params["container"] == "swss"
        assert build("syslog=5000:process=bgpd").params["container"] == "bgp"

    def test_a_container_may_still_be_named_directly(self):
        assert build("syslog=5000:container=bgp").params["container"] == "bgp"

    def test_neither_falls_back_to_swss(self):
        assert build("syslog=5000").params["container"] == "swss"

    def test_a_process_and_its_own_container_agree(self):
        assert build("syslog=5000:process=orchagent:container=swss").params["container"] == "swss"

    def test_a_process_contradicting_its_container_is_refused(self):
        """Silently preferring one over the other would flood a container nobody asked for."""
        with pytest.raises(ChaosUsageError, match="runs in container 'swss', not 'bgp'"):
            build("syslog=5000:process=orchagent:container=bgp")

    def test_an_unknown_process_fails_at_configure_time(self):
        with pytest.raises(ChaosUsageError, match="unknown target"):
            build("syslog=5000:process=nosuchdaemon")

    def test_a_protected_process_needs_force_like_every_other_injector(self):
        with pytest.raises(ChaosUsageError, match="protected"):
            build("syslog=5000:process=redis-server")

    def test_the_flood_runs_in_the_resolved_container(self):
        dut = FakeDut(responses=[(r"df --output=pcent", 0, " 12%"), (r"grep -c", 0, "0"),
                                 (r"pgrep -f", 0, "yes")])
        build("syslog=5000:seconds=5:process=bgpd").apply(dut)
        assert dut.ran(r"docker exec -d bgp sh -c"), dut.commands

    def test_the_logger_ident_is_not_called_tag(self):
        """`tag` is reserved by experiment.py for scheduling metadata; see TestExperiment."""
        injector = build("syslog=100:ident=myflood")
        assert injector.params["ident"] == "myflood"
        assert "tag" not in injector.defaults
        assert "-t myflood" in injector.generator_script()


# ------------------------------------------------------------------------------- session + bundles

class TestSession(object):

    def test_release_runs_for_every_dut_even_when_one_raises(self):
        class Boom(object):
            name, lane, params = "boom", "test", {}
            released = []

            def describe(self):
                return "boom"

            def apply(self, duthost, **kw):
                pass

            def release(self, duthost):
                self.released.append(duthost.hostname)
                raise RuntimeError("release blew up")

            def status(self, duthost):
                return {}

        duts = [FakeDut("dut1"), FakeDut("dut2")]
        session = ChaosSession(duts)
        injector = Boom()
        session.apply(injector)
        with pytest.raises(RuntimeError):
            session.release_all()
        assert injector.released == ["dut2", "dut1"], "one failure must not strand the other DUT"
        assert session.applied == []

    def test_status_of_a_broken_injector_does_not_break_the_release_path(self):
        class Angry(object):
            name, lane, params = "angry", "test", {}

            def describe(self):
                return "angry"

            def apply(self, duthost, **kw):
                pass

            def release(self, duthost):
                pass

            def status(self, duthost):
                raise RuntimeError("status exploded")

        session = ChaosSession([FakeDut()])
        session.apply(Angry())
        assert "error" in session.status()[0][2]

    def test_dry_run_never_touches_a_dut(self):
        dut = FakeDut()
        session = ChaosSession([dut], dry_run=True)
        session.apply(build("kill=orchagent"))
        session.release_all()
        assert dut.commands == []


class TestBundle(object):

    def test_writes_the_four_files_a_finding_needs(self, tmp_path):
        repro = bundle.ReproBundle("tests/pc/test_po.py::test_x[run4]", root=str(tmp_path))
        path = repro.write(repro="pytest tests/pc/test_po.py::test_x --chaos kill=orchagent",
                           fault={"recipe": "kill(process=orchagent)"},
                           outcome="failed", syslog="Sep 11 orchagent crashed")
        written = sorted(os.listdir(path))
        assert written == ["fault.json", "outcome.txt", "repro.sh", "syslog.txt"]
        assert "--chaos kill=orchagent" in open(os.path.join(path, "repro.sh")).read()

    def test_an_unwritable_bundle_never_fails_the_run(self, tmp_path):
        """A bundle is evidence for a verdict that already exists; it must not create one."""
        blocked = tmp_path / "file"
        blocked.write_text("not a directory")
        repro = bundle.ReproBundle("t::x", root=str(blocked))
        with pytest.raises(OSError):
            repro.ensure()
        assert repro.add("x.txt", "y") is None      # add() swallows it

    def test_syslog_window_captures_only_this_test(self):
        dut = FakeDut(sequences={r"wc -l": ["100", "140"]},
                      responses=[(r"tail -n \+101", 0, "line101\nline102")])
        window = bundle.SyslogWindow(dut).open()
        assert window.read() == "line101\nline102"
        assert dut.ran(r"tail -n \+101 /var/log/syslog")

    def test_syslog_window_notices_a_rotation(self):
        dut = FakeDut(sequences={r"wc -l": ["100", "5"]},
                      responses=[(r"tail -n 4000", 0, "fresh")])
        window = bundle.SyslogWindow(dut).open()
        assert "log rotated" in window.read()

    def test_syslog_window_survives_an_unreachable_dut(self):
        """The DUT being down is when the log matters most, and when the capture is likeliest
        to fail. It must degrade to an empty window, never to an exception."""

        class Dead(FakeDut):
            def shell(self, *a, **kw):
                raise IOError("host unreachable")

        assert bundle.SyslogWindow(Dead()).open().read() == ""


class TestExperimentReservedKeys(object):
    """An experiment file must never silently discard an injector parameter."""

    def test_an_injector_may_not_own_a_scheduling_key(self):
        from sonic_chaos.experiment import Experiment, RESERVED_KEYS
        from sonic_chaos.injector import REGISTRY

        # weight and tag are popped as scheduling metadata before the injector is built, so an
        # injector parameter by either name could never be set from a file.
        for name, cls in REGISTRY.items():
            clash = RESERVED_KEYS & set(cls.defaults)
            assert not clash, "injector {!r} has reserved param(s) {}".format(name, sorted(clash))

        # and the guard fires rather than losing the value, if one ever does
        cls = REGISTRY["syslog"]
        original = dict(cls.defaults)
        cls.defaults = dict(original, tag="sonic-chaos")
        try:
            with pytest.raises(ChaosUsageError, match="reserved for scheduling metadata"):
                Experiment.from_dict({"experiment": "x",
                                      "faults": [{"syslog": {"rate": 100, "tag": "supported-op"}}]})
        finally:
            cls.defaults = original
