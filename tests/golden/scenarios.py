"""The switches the golden transcripts are recorded against.

Two kinds of box:

* ``bare`` -- every command succeeds and prints nothing. It drives every injector down its
  refusal and error paths, which are as much a part of the behaviour as the happy path and are
  the first thing a refactor breaks.
* ``healthy`` -- a box that answers the way a live 202511.2 switch does. The canned output is
  the same text the spine unit tests use, copied off a real box. It exists only where that
  output is known; nothing here is made up to get a path to run. Injectors without a healthy
  scenario (squeeze agent JSON, CRM tables, LAG membership, shim stats) are pinned bare-box only
  until someone captures the real output.
"""

SUPERVISOR_RUNNING = "orchagent                        RUNNING   pid 55, uptime 0:01:37"
SUPERVISOR_RESTARTED = "orchagent                        RUNNING   pid 912, uptime 0:00:02"
HGETALL_PORT = ("{'admin_status': 'up', 'alias': 'fortyGigE0/0', 'index': '0', "
                "'lanes': '25,26,27,28', 'mtu': '9100', 'speed': '40000'}")
DOCKER_TOP_PID = "8016"
REDIS_TOP_PID = "1156"
STARTED_BEFORE = "2026-09-28T08:00:00.000000000Z"
STARTED_AFTER = "2026-09-28T08:00:41.000000000Z"

_CONTAINER_UP = (r"docker inspect -f '\{\{\.State\.Running\}\}'", 0, "true")
_SYSTEMD_OK = (r"systemctl show \S+ -p Result", 0, "success")


class Scenario(object):
    """One injector, one spec, one box. ``needs_shim`` scenarios build the C interposer."""

    def __init__(self, name, spec, box="bare", responses=(), sequences=None, needs_shim=False):
        self.name = name
        self.spec = spec
        self.box = box
        self.responses = list(responses)
        self.sequences = dict(sequences or {})
        self.needs_shim = needs_shim


def _bare(name, spec, **kw):
    return Scenario(name, spec, box="bare", **kw)


SCENARIOS = [
    # -- healthy box: the spine lane, from real output ------------------------------------------
    Scenario("kill-sigkill-healthy", "kill=orchagent", box="healthy",
             responses=[_CONTAINER_UP, _SYSTEMD_OK,
                        (r"inspect --format '\{\{\.State\.StartedAt\}\}'", 0, STARTED_BEFORE)],
             sequences={r"supervisorctl status": [SUPERVISOR_RUNNING, SUPERVISOR_RESTARTED]}),
    Scenario("kill-restart-healthy", "kill=orchagent:how=restart", box="healthy",
             responses=[_CONTAINER_UP, _SYSTEMD_OK,
                        (r"inspect --format '\{\{\.State\.StartedAt\}\}'", 0, STARTED_BEFORE)],
             sequences={r"supervisorctl status": [SUPERVISOR_RUNNING, SUPERVISOR_RESTARTED]}),
    Scenario("kill-container-healthy", "kill=swss:how=container", box="healthy",
             responses=[_CONTAINER_UP, _SYSTEMD_OK,
                        (r"supervisorctl status", 0, SUPERVISOR_RESTARTED)],
             sequences={r"inspect --format '\{\{\.State\.StartedAt\}\}'": [STARTED_BEFORE, STARTED_AFTER]}),
    Scenario("pause-healthy", "pause=orchagent:10", box="healthy",
             responses=[(r"mkdir -p .*cat >", 0, "4242")],
             sequences={r"ps -o stat=": ["Tl orchagent", "Tl orchagent", "Sl orchagent"]}),
    Scenario("corrupt-healthy", "corrupt=APPL_DB:[PORT_TABLE:Ethernet0]:admin_status=garbage", box="healthy",
             sequences={r"HGETALL": [HGETALL_PORT, HGETALL_PORT.replace("'up'", "'garbage'"), HGETALL_PORT]}),
    Scenario("redis-client-kill-healthy", "redis=client_kill:orchagent", box="healthy",
             responses=[(r"docker top database", 0, REDIS_TOP_PID),
                        (r"docker top swss", 0, DOCKER_TOP_PID),
                        (r"redis_clients\.py", 0,
                         '{"target_sockets": 640, "matched_fds": 600, "client_ids": 600, "killed": 600}')]),
    Scenario("redis-sleep-healthy", "redis=sleep:2000", box="healthy",
             responses=[(r"PING", 0, "PONG")]),
    Scenario("syslog-healthy", "syslog=5000:seconds=30", box="healthy",
             responses=[(r"df --output=pcent", 0, " 12%"), (r"grep -c", 0, "0"), (r"pgrep -f", 0, "yes")]),

    # -- bare box: every injector's refusal and error paths ------------------------------------
    _bare("kill-sigkill-bare", "kill=orchagent"),
    _bare("kill-restart-bare", "kill=orchagent:how=restart"),
    _bare("kill-container-bare", "kill=swss:how=container"),
    _bare("pause-signal-bare", "pause=orchagent:10"),
    _bare("pause-docker-bare", "pause=swss:5:how=docker"),
    _bare("corrupt-bare", "corrupt=APPL_DB:[PORT_TABLE:Ethernet0]:mtu=1500"),
    _bare("corrupt-delete-bare", "corrupt=APPL_DB:[PORT_TABLE:Ethernet0]:delete=true"),
    _bare("redis-client-kill-bare", "redis=client_kill:orchagent"),
    _bare("redis-sleep-bare", "redis=sleep:2000"),
    _bare("syslog-bare", "syslog=1000:seconds=10"),
    _bare("cpu-cgroup-bare", "cpu=orchagent:30"),
    _bare("cpu-docker-bare", "cpu=swss:50"),
    _bare("mem-bare", "mem=swss:40"),
    _bare("mem-ramp-bare", "mem=swss:40:ramp=20"),
    _bare("hog-cpu-bare", "hog=swss:cpu=40"),
    _bare("hog-mem-bare", "hog=lldp:mem=25"),
    _bare("exhaust-route-bare", "exhaust=route:20000"),
    _bare("exhaust-nhg-bare", "exhaust=nhg:0:over_pct=110"),
    _bare("exhaust-neighbor-bare", "exhaust=neighbor:500"),
    _bare("exhaust-acl-bare", "exhaust=acl:500"),
    _bare("storm-netlink-bare", "storm=netlink:rate=1000:seconds=20"),
    _bare("sai-delay-bare", "sai=route_entry:create:delay=2000", needs_shim=True),
    _bare("sai-status-bare", "sai=vlan:create:status=SAI_STATUS_TABLE_FULL", needs_shim=True),
    _bare("sai-freeze-bare", "sai=mode=freeze"),
    _bare("spin-bare", "spin=orchagent:70", needs_shim=True),
]
