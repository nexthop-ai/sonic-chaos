"""Spine lane -- hurt the bus every SONiC daemon talks over, without touching the daemons.

    --chaos redis=client_kill:orchagent     drop orchagent's redis connections; does it resubscribe?
    --chaos redis=sleep:2000                block the redis instance for 2 s; who times out?

Two faults, one target. Both are one redis command and both are bounded.

**client_kill** severs a consumer's subscription mid-flight. The interesting question is not
whether the daemon reconnects -- it does -- but whether it *resyncs*: a ConsumerStateTable that
reconnects without replaying loses every notification sent while it was gone, which is the
swallowed-TABLE_FULL "APPL_DB has the intent, ASIC_DB never got it" shape with no crash to point at.

**sleep** uses ``DEBUG SLEEP``, which blocks the whole single-threaded redis server. Everything
stalls at once: orchagent, syncd, every mgrd, and the supervisor health checks. Keep it short.

Attributing a connection to a daemon
------------------------------------
Measured on a 202511.2 box: **every** redis client connects over the unix socket
``/var/run/redis/redis.sock`` and **no** client sets a name, so every row of ``CLIENT LIST``
carries the identical ``addr``/``laddr`` and an empty ``name=``. Matching on those -- which is
the obvious approach -- silently selects every daemon at once, or nothing.

What does work is pairing socket inodes, entirely on the DUT::

    target's /proc/<pid>/fd/*  -> socket:[inode]      the client end
    ss -x                      -> local inode, peer inode for each unix socket
    redis's  /proc/<pid>/fd/*  -> socket:[inode]      the server end, and the fd CLIENT LIST prints

A redis fd whose socket's peer inode belongs to the target process is a connection from that
target, and ``CLIENT LIST`` maps that fd back to the id ``CLIENT KILL ID`` needs. The resolver
runs on the box in one round trip because a busy orchagent holds hundreds of connections.

Safety: ``DEBUG SLEEP`` is self-releasing, so ``release`` is a no-op for it; the risk is running
it long enough that supervisor declares a critical process dead and restarts containers. The
validator caps it at 10 s for that reason. Targeting the database *container* (docker pause,
restart) stays refused via targets.yml -- that cascades with no clean recovery path.
"""
import json
import logging

from ..injector import (
    Injector, ChaosUsageError, register, require_target, as_bool,
    run, quote, resolve_pid, sudo_prefix, DEADMAN_DIR,
)

logger = logging.getLogger(__name__)

# Runs on the DUT. stdlib only (python3 is on every SONiC image), reads /proc and `ss`, and
# does the kill there too -- a daemon can hold hundreds of connections and one CLIENT KILL per
# round trip would take minutes.
RESOLVER = r'''
import json, os, subprocess, sys

target_pid, redis_pid, db, do_kill = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4] == "kill"


def socket_inodes(pid):
    """{inode: fd} for every socket the process holds."""
    out, base = {}, "/proc/%d/fd" % pid
    try:
        names = os.listdir(base)
    except OSError as err:
        print(json.dumps({"error": "cannot read %s: %s" % (base, err)}))
        raise SystemExit(1)
    for name in names:
        try:
            link = os.readlink(os.path.join(base, name))
        except OSError:
            continue            # fd closed while we walked; normal on a live process
        if link.startswith("socket:["):
            out[link[8:-1]] = int(name)
    return out


target = set(socket_inodes(target_pid))
server = socket_inodes(redis_pid)           # inode -> the fd CLIENT LIST reports

pairs = subprocess.run(["ss", "-x"], capture_output=True, text=True).stdout.splitlines()[1:]
fds = set()
for line in pairs:
    f = line.split()
    if len(f) >= 4 and f[-3] in server and f[-1] in target:
        fds.add(server[f[-3]])

listing = subprocess.run(["sonic-db-cli", db, "CLIENT", "LIST"], capture_output=True, text=True).stdout
ids = []
for line in listing.splitlines():
    row = dict(p.split("=", 1) for p in line.split() if "=" in p)
    if row.get("fd", "").isdigit() and int(row["fd"]) in fds:
        ids.append(row["id"])


def db_index(name):
    """DB name -> redis numeric index, straight off the box's own config."""
    try:
        with open("/var/run/redis/sonic-db/database_config.json") as handle:
            return int(json.load(handle)["DATABASES"][name]["id"])
    except (OSError, KeyError, ValueError, TypeError):
        return 0


killed = 0
if do_kill and ids:
    # Redis 7.0 (what 202511.2 ships) accepts exactly ONE id per CLIENT KILL: the multi-id form
    # is Redis 8, and MAXAGE is 7.4. Verified on the box -- both return "ERR syntax error".
    # A daemon can hold hundreds of connections, so spawning sonic-db-cli per id would take
    # minutes; instead every kill goes down a single redis-cli stdin pipe. CLIENT KILL is
    # connection-scoped, so which db index that connection uses does not matter.
    script = "".join("CLIENT KILL ID {}\n".format(i) for i in ids)
    proc = subprocess.run(["docker", "exec", "-i", "database", "redis-cli", "-n", str(db_index(db))],
                          input=script, capture_output=True, text=True)
    killed = sum(1 for line in proc.stdout.split() if line.strip() == "1")

print(json.dumps({"target_sockets": len(target), "matched_fds": len(fds),
                  "client_ids": len(ids), "killed": killed}))
'''


@register
class RedisInjector(Injector):
    name = "redis"
    lane = "spine"
    positional = ("action", "target")
    defaults = {"action": "client_kill", "db": "APPL_DB"}

    ACTIONS = ("client_kill", "sleep")
    MAX_SLEEP_MS = 10000
    RESOLVER_PATH = DEADMAN_DIR + "/redis_clients.py"

    def validate(self):
        p = self.params
        if p["action"] not in self.ACTIONS:
            raise ChaosUsageError("redis: action must be one of {}, got {!r}".format(
                "/".join(self.ACTIONS), p["action"]))

        if p["action"] == "client_kill":
            if "target" not in p:
                raise ChaosUsageError("redis: client_kill needs a process, e.g. redis=client_kill:orchagent")
            # Resolve so a typo fails here rather than silently killing nothing on the DUT.
            p["container"] = require_target(
                p["target"], as_bool(p.get("force", False), "redis: force"), "redis")
        else:
            if "target" not in p:
                raise ChaosUsageError("redis: sleep needs milliseconds, e.g. redis=sleep:2000")
            try:
                ms = int(p["target"])
            except ValueError:
                raise ChaosUsageError("redis: sleep takes milliseconds, got {!r}".format(p["target"]))
            if not 1 <= ms <= self.MAX_SLEEP_MS:
                raise ChaosUsageError(
                    "redis: sleep must be 1..{} ms -- longer and supervisor restarts containers "
                    "(got {})".format(self.MAX_SLEEP_MS, ms))

    def command(self):
        p = self.params
        if p["action"] == "sleep":
            return "sonic-db-cli {} DEBUG SLEEP {}".format(p["db"], int(p["target"]) / 1000.0)
        return "CLIENT KILL ID <ids of {}'s connections>".format(p["target"])

    # -- lifecycle ---------------------------------------------------------------------------

    def apply(self, duthost, **params):
        if self.params["action"] == "sleep":
            return self._sleep(duthost)
        return self._client_kill(duthost, kill=True)

    def release(self, duthost):
        # Both actions are self-releasing: a killed client reconnects, a DEBUG SLEEP expires.
        # Recovery is the thing under test, so there is deliberately nothing to undo here.
        logger.info("[redis] release is a no-op (self-releasing fault): %s on %s",
                    self.describe(), duthost.hostname)

    def status(self, duthost):
        if self.params["action"] == "sleep":
            rc, out, _ = run(duthost, "sonic-db-cli {} PING".format(self.params["db"]))
            return {"active": False, "responsive": out.strip() in ("True", "PONG"),
                    "achieved": {"slept_ms": int(self.params["target"])}}
        last = (self.events() or [{}])[-1]
        # Re-resolve: the count coming back up is the daemon having reconnected.
        current = self._client_kill(duthost, kill=False)
        return {
            "active": False,
            "killed": last.get("killed"),
            "achieved": {"killed": last.get("killed"),
                         "connections_now": current.get("client_ids"),
                         "reconnected": bool(current.get("client_ids"))},
        }

    # -- helpers -----------------------------------------------------------------------------

    def _sleep(self, duthost):
        cmd = self.command()
        rc, out, err = run(duthost, cmd)
        detail = (err or out).strip()
        if rc != 0:
            if "debug" in detail.lower():
                # redis >= 7 ships enable-debug-command=no by default (redis 8 on SONiC 202511),
                # so DEBUG SLEEP is refused outright -- not a transient failure. Say so plainly.
                raise ChaosUsageError(
                    "redis: DEBUG SLEEP is disabled on {} (this redis is built with "
                    "enable-debug-command=no, as on SONiC 202511's redis 8), so the sleep fault "
                    "cannot run here. Use redis=client_kill:<process> instead.".format(duthost.hostname))
            raise RuntimeError("redis: DEBUG SLEEP failed on {} (rc={}): {}".format(
                duthost.hostname, rc, detail[:300]))
        logger.info("[redis] %s on %s: %s", self.describe(), duthost.hostname, cmd)
        return self.record(duthost, action="redis_sleep", command=cmd, ms=int(self.params["target"]))

    def _client_kill(self, duthost, kill):
        """Resolve (and optionally kill) the target's redis connections. Returns the resolver's dict."""
        p = self.params
        target_pid = resolve_pid(duthost, p["target"], p["container"])
        redis_pid = resolve_pid(duthost, "redis-server", "database")
        if target_pid is None or redis_pid is None:
            missing = p["target"] if target_pid is None else "redis-server"
            if not kill:
                return {"error": "{} not running".format(missing)}
            raise RuntimeError("redis: {} is not running on {}, so there are no connections to "
                               "kill".format(missing, duthost.hostname))

        self._push_resolver(duthost)
        rc, out, err = run(duthost, "{}python3 {} {} {} {} {}".format(
            sudo_prefix(duthost),
            self.RESOLVER_PATH, target_pid, redis_pid, quote(p["db"]), "kill" if kill else "list"))
        try:
            result = json.loads((out or "").strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise RuntimeError("redis: connection resolver failed on {} (rc={}): {}".format(
                duthost.hostname, rc, ((err or out) or "no output").strip()[:300]))
        if "error" in result:
            raise RuntimeError("redis: connection resolver on {}: {}".format(duthost.hostname, result["error"]))

        if kill:
            if not result.get("client_ids"):
                raise RuntimeError(
                    "redis: resolved 0 redis connections for {} (pid {}) on {}. A fault that killed "
                    "nothing would be reported as 'no divergence found'.".format(
                        p["target"], target_pid, duthost.hostname))
            logger.info("[redis] %s on %s: killed %s of %s connection(s) held by %s (pid %s)",
                        self.describe(), duthost.hostname, result.get("killed"),
                        result.get("client_ids"), p["target"], target_pid)
            return self.record(duthost, action="redis_client_kill", target=p["target"],
                               target_pid=target_pid, db=p["db"], **result)
        return result

    def _push_resolver(self, duthost):
        """Copy the resolver to the DUT. Rewritten every time: cheap, and never a stale copy."""
        run(duthost, "mkdir -p {d} && cat > {p} <<'CHAOS_RESOLVER_EOF'\n{body}\nCHAOS_RESOLVER_EOF".format(
            d=DEADMAN_DIR, p=self.RESOLVER_PATH, body=RESOLVER))

    def expected_syslog(self):
        """A severed connection is logged by the daemon that owns it, and by redis.

        The reconnect chatter is expected. Whether the daemon *resyncs* after reconnecting is the
        finding, and nothing here hides that -- a lost update shows up as a DB divergence, not a
        log line.
        """
        return (
            r".* ERR .*: :- .*Connection reset by peer.*",
            r".* WARNING .*redis.*connection.*lost.*",
            r".* NOTICE .*redis.*Client closed connection.*",
        )
