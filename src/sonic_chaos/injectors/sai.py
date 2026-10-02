"""Shim lane -- delay, fail, or drop SAI calls underneath syncd.

    --chaos sai=route_entry:create:delay=2000                       every route create waits 2 s
    --chaos sai=vlan_member:remove:status=SAI_STATUS_ITEM_NOT_FOUND:count=1   stale-member, once
    --chaos sai=route_entry:remove:drop=true                        pretend it worked
    --chaos sai=mode=freeze                                         stop syncd; every call blocks

Mechanism: ``shim/sonic_chaos_sai.so``, preloaded into the syncd container. SAI is reached
through a struct of function pointers rather than named symbols, so the shim interposes
``sai_api_query``, calls the real one, and swaps selected slots of the returned table for
trampolines that consult a control file. ``shim/README.md`` has the details.

What that buys, and what it costs:

* Arming, re-arming and disarming are writes to a JSON file the shim re-reads within 250 ms.
  No restart, so a test can change the fault between cases.
* Patching a slot, though, can only happen while syncd is starting -- so the *first* use of an
  object type costs one syncd restart. ``apply`` works out whether it needs one by asking the
  shim what it already hooked, and does nothing if it does not. On real hardware that restart
  is itself a dataplane event that trips the DNX cold-restart path, so it is worth avoiding.
* ``mode=freeze`` (formerly ``sigstop``) is the fallback that needs no shim at all: SIGSTOP syncd and every SAI call
  blocks until release, which is the sairedis 60 s timeout path. Crude, but it needs no build
  and no restart, and on hardware that makes it the gentler way in.

Both modes carry a dead-man timer on the DUT. A test that dies without releasing leaves a
frozen syncd or an armed fault otherwise, and that is a wedged testbed for whoever is next.
"""
import difflib
import json
import logging
import os
import re
import time

from ..injector import (
    Injector, ChaosUsageError, register, as_bool,
    run, arm_deadman, disarm_deadman, deadman_tag, poll, sudo_prefix,
)
from ..preload import Preload, INSTALL_DIR
from ..sai_catalog import (
    BULK_TYPES, ENTRY_TYPES, OBJECT_TYPES, OPS, SAI_VERSION, STATUS_CODES,
)

logger = logging.getLogger(__name__)

_HERE = os.path.dirname(os.path.abspath(__file__))
SHIM_BINARY = os.path.normpath(os.path.join(_HERE, os.pardir, "shim", "build",
                                            "sonic_chaos_sai.so"))

CONTAINER = "syncd"
CONTROL_FILE = INSTALL_DIR + "/sai_control.json"
STATS_FILE = INSTALL_DIR + "/sai_stats.json"

SYNCD_READY_TIMEOUT = 300
RELOAD_SETTLE = 1.0      # the shim re-reads the control file at most every 250 ms

# Install, probe, wire into supervisord, uninstall: shared with the spin injector, which does
# the same six steps against orchagent in the swss container.
PRELOAD = Preload("sai", CONTAINER, "syncd", "sonic_chaos_sai.so", SHIM_BINARY)
FREEZE_HINT = "\nOr use the mode that needs no build at all: --chaos sai=mode=freeze"


@register
class SaiInjector(Injector):
    name = "sai"
    lane = "shim"
    positional = ("object_type", "op")
    defaults = {"op": "all", "delay": "0", "status": "", "drop": "false", "count": "0",
                "mode": "intercept", "ttl": "600", "settle": "20"}

    # What the fault does, named for the effect rather than the mechanism. The old spellings
    # are still accepted so experiment files and anyone's muscle memory keep working.
    MODES = ("intercept", "freeze")
    MODE_ALIASES = {"shim": "intercept", "sigstop": "freeze"}
    MAX_DELAY_MS = 300000

    # ----------------------------------------------------------------- spec

    def validate(self):
        params = self.params
        params["mode"] = self.MODE_ALIASES.get(params["mode"], params["mode"])
        if params["mode"] not in self.MODES:
            raise ChaosUsageError(
                "sai: mode must be {} (delay/fail/drop chosen calls) or {} (stop syncd so every "
                "call blocks), got {!r}".format(*(self.MODES + (params["mode"],))))
        params["ttl"] = self._integer("ttl", minimum=0)
        params["settle"] = self._integer("settle", minimum=0)

        if params["mode"] == "freeze":
            # The freeze is process-wide, so an object type would only be misleading.
            if params.get("object_type") not in (None, "", "all"):
                raise ChaosUsageError(
                    "sai: mode=freeze stops all of syncd, so it takes no object type; "
                    "drop {!r} or use mode=intercept".format(params["object_type"]))
            params["object_type"] = "all"
            params["op"] = "all"
            return

        object_type = params.get("object_type")
        if not object_type:
            raise ChaosUsageError(
                "sai: needs an object type, e.g. sai=route_entry:create:delay=2000")
        if object_type not in OBJECT_TYPES:
            raise ChaosUsageError("sai: unknown object type {!r}; {}".format(
                object_type, self._suggest(object_type)))
        if params["op"] not in OPS + ("all",):
            raise ChaosUsageError("sai: op must be one of {}, got {!r}".format(
                "/".join(OPS + ("all",)), params["op"]))
        # Only 20 of the 126 types carry a bulk create/remove pair. Naming one on any of the
        # other 106 used to validate and then hook nothing: the rule armed, the trampoline was
        # never installed, `matched` stayed 0, and the run reported that the system held under a
        # fault that was never applied. Refuse it here instead, where it costs nothing.
        if params["op"] in ("bulk_create", "bulk_remove") and object_type not in BULK_TYPES:
            raise ChaosUsageError(
                "sai: {} has no bulk API in SAI {}, so {} would hook nothing and the fault "
                "would silently never fire. Use create or remove on {}, or pick a type that "
                "has bulk: {}, ...".format(
                    object_type, SAI_VERSION, params["op"], object_type,
                    ", ".join(sorted(BULK_TYPES)[:6])))

        delay = self._integer("delay", minimum=0)
        params["delay"] = delay
        params["count"] = self._integer("count", minimum=0)
        drop = as_bool(params["drop"], "sai: drop")
        params["drop"] = "true" if drop else "false"

        status = params["status"]
        if status:
            if status not in STATUS_CODES:
                raise ChaosUsageError(
                    "sai: {!r} is not a SAI status; try SAI_STATUS_ITEM_NOT_FOUND, "
                    "SAI_STATUS_TABLE_FULL, SAI_STATUS_NOT_EXECUTED or another "
                    "SAI_STATUS_* name".format(status))
            if STATUS_CODES[status] == 0:
                raise ChaosUsageError(
                    "sai: status=SAI_STATUS_SUCCESS injects nothing; use drop=true to skip the "
                    "call while still reporting success")
        bulk = self._returns_bulk_statuses(object_type, params["op"])
        if status and bulk:
            raise ChaosUsageError(
                "sai: status={} on {} {} returns the error without calling the ASIC, so the "
                "per-object status array is never written. syncd zero-fills that array and zero is "
                "SAI_STATUS_SUCCESS, so it records every object as created with RID 0x0 and the run "
                "reports a consistent box that was never under fault. Use delay= on the bulk op, or "
                "status= on a single create/remove.".format(status, object_type, params["op"]))
        if drop:
            refusal = self._undroppable(object_type, params["op"])
            if refusal:
                raise ChaosUsageError(
                    "sai: drop returns SUCCESS without calling the ASIC, so {} would leave {} "
                    "never written and syncd would read uninitialised memory -- a crash that "
                    "says nothing about the product. {}".format(
                        params["op"], refusal,
                        "Use delay= instead." if bulk else "Use status=SAI_STATUS_* instead."))
        if not (delay or status or drop):
            raise ChaosUsageError(
                "sai: nothing to inject; give delay=<ms>, status=<SAI_STATUS_*>, or drop=true")

        # A delay longer than sairedis' own 60 s response timeout is not a slow call any more:
        # orchagent gives up and aborts. That is a real fault, but mode=freeze is the honest way
        # to ask for it, and past a few minutes the only thing left to test is the dead-man.
        if delay > self.MAX_DELAY_MS:
            raise ChaosUsageError(
                "sai: delay={} ms is longer than this injector will go ({} ms). Past sairedis' "
                "60 s response timeout orchagent aborts rather than waits, so anything beyond "
                "that is testing the timeout, not the latency -- use mode=freeze to stop syncd "
                "outright.".format(delay, self.MAX_DELAY_MS))

        # The dead-man is the only thing that releases a fault when a test dies. If the rule
        # could still be spending latency after it fires, it disarms mid-fault and the run
        # reports a partial injection as if it were the whole one.
        ttl = params["ttl"]
        count = params["count"]

        # `settle` is how long the fault is held before the invariants are read; `ttl` is the
        # switch-side dead-man that lifts it if the harness dies. The dead-man therefore has to
        # outlast the hold. When it does not, the fault is gone before anything looks at it and
        # the run reports a clean box that was never actually under fault -- which reads as a
        # pass. Refuse instead: this is the one misconfiguration that fails silently.
        if ttl and params["settle"] >= ttl:
            raise ChaosUsageError(
                "sai: settle={}s is not shorter than ttl={}s, so the switch would lift the fault "
                "before the check reads it and the run would pass without ever testing anything. "
                "ttl is a dead-man for a dead harness, not the hold time -- raise ttl above the "
                "settle, or lower the settle.".format(params["settle"], ttl))

        if delay and count and ttl:
            spend = delay * count / 1000.0
            if spend > ttl:
                raise ChaosUsageError(
                    "sai: {} calls delayed {} ms each can spend {:.0f} s, longer than the {} s "
                    "dead-man, so it would disarm mid-fault and the run would report a partial "
                    "injection. Raise ttl, or lower delay or count.".format(
                        count, delay, spend, ttl))

    @staticmethod
    def _returns_bulk_statuses(object_type, op):
        """Whether `op` hooks a bulk call, whose per-object status array syncd trusts as written.

        A status or drop fault returns without calling the vendor, so that array stays as syncd
        zero-initialised it -- all SAI_STATUS_SUCCESS. op=all includes the bulk ops of a type that
        has them.
        """
        return op in ("bulk_create", "bulk_remove") or (op == "all" and object_type in BULK_TYPES)

    @staticmethod
    def _undroppable(object_type, op):
        """What a dropped `op` would leave unwritten, or "" when dropping it is safe.

        Decided per operation rather than by a blanket list, because it genuinely differs:

          remove, set    nothing is handed back -- always safe
          create         safe only for the entry-style types, whose create takes no output
                         parameter. An object-style create returns a new object id.
          get            fills the caller's attribute list
          bulk_create    returns object ids and a per-object status array
          bulk_remove    returns a per-object status array
          all            covers get, so it is never safe
        """
        if op in ("remove", "set"):
            return ""
        if op == "create":
            return "" if object_type in ENTRY_TYPES else "the new object id"
        if op == "get":
            return "the attribute list"
        if op == "bulk_create":
            return "the object ids and the per-object status array"
        if op == "bulk_remove":
            return "the per-object status array"
        return "the outputs of the get and create it also covers"   # op=all

    def _integer(self, key, minimum=None):
        try:
            value = int(self.params[key])
        except (TypeError, ValueError):
            raise ChaosUsageError("sai: {} must be an integer, got {!r}".format(
                key, self.params[key]))
        if minimum is not None and value < minimum:
            raise ChaosUsageError("sai: {} must be >= {}, got {}".format(key, minimum, value))
        return value

    @staticmethod
    def _suggest(object_type):
        near = difflib.get_close_matches(object_type, sorted(OBJECT_TYPES), n=3, cutoff=0.6)
        near += [t for t in sorted(OBJECT_TYPES)
                 if object_type in t and t not in near][:3 - len(near)]
        if near:
            return "did you mean {}?".format(" or ".join(near))
        return "see sonic_chaos/sai_catalog.py for the {} known types".format(len(OBJECT_TYPES))

    def _deadman_tag(self):
        return deadman_tag("sai", self.params["mode"])

    # ----------------------------------------------------------------- control file

    def control(self):
        """This injector's contribution to the shim's control file."""
        params = self.params
        status = params["status"]
        rule = {
            "delay_ms": int(params["delay"]),
            "status": STATUS_CODES[status] if status else None,
            "drop": params["drop"] == "true",
            "count": int(params["count"]),
        }
        if status:
            rule["status_name"] = status   # for whoever reads the file on the box
        op = "*" if params["op"] == "all" else params["op"]
        return {"hook": [params["object_type"]],
                "rules": {params["object_type"]: {op: rule}}}

    def _owner(self):
        """Key this injector's slice of the shared control file, so release removes only ours."""
        return self.describe()

    def _merge_control(self, duthost, contribution):
        """Read-modify-write the control file, replacing just this injector's slice.

        Several --chaos sai= flags can be live at once, so the file is a merge of everyone's
        rules keyed by owner. Passing None removes this owner.
        """
        current = PRELOAD.read_json(duthost, CONTROL_FILE) or {}
        owners = current.get("owners") or {}
        if contribution is None:
            owners.pop(self._owner(), None)
        else:
            owners[self._owner()] = contribution

        hook, rules = [], {}
        for slice_ in owners.values():
            for object_type in slice_.get("hook", []):
                if object_type not in hook:
                    hook.append(object_type)
            for object_type, ops in (slice_.get("rules") or {}).items():
                rules.setdefault(object_type, {}).update(ops)

        if not owners:
            # Nothing left armed: remove the file rather than leave an empty one. The shim
            # treats its absence as "disarmed" and says so in syslog.
            run(duthost, PRELOAD.in_container(duthost, "rm -f {}".format(CONTROL_FILE)))
            return {}

        document = {
            "v": 1,
            # Bumped on every write. The shim keys off mtime and size, but this is what makes
            # a change visible to a human reading the file, and it lands in the stats.
            "seq": int(current.get("seq", 0)) + 1,
            "hook": hook,
            "rules": rules,
            "owners": owners,
        }
        rc, _out, err = PRELOAD.write_file(duthost, CONTROL_FILE,
                                           json.dumps(document, indent=1))
        if rc != 0:
            raise RuntimeError("[sai] could not write {} on {}: {}".format(
                CONTROL_FILE, duthost.hostname, err.strip()))
        return document

    # ----------------------------------------------------------------- deployment

    def _restart_syncd(self, duthost):
        """Restart syncd so the shim is present when it queries the SAI APIs.

        This is the expensive half of the lane, and apply() only gets here when the object
        type is genuinely not hooked yet.

        It restarts *swss*, not syncd. Measured on a lab switch: `systemctl restart syncd` stops
        syncd, orchagent hits its sairedis timeout and swss follows it out, and systemd brings
        neither back -- the box sits with no data plane until someone runs `config reload`.
        Restarting swss bounces the pair the way the rest of SONiC does it. Either way the
        ASIC re-initialises, so this is a real dataplane event on hardware.
        """
        logger.warning("[sai] restarting swss/syncd on %s to hook %s (this disrupts the data "
                       "plane and re-initialises the ASIC)",
                       duthost.hostname, self.params["object_type"])
        rc, _out, err = run(duthost, "{}systemctl restart swss".format(
            sudo_prefix(duthost)))
        if rc != 0:
            raise RuntimeError("[sai] systemctl restart swss failed on {}: {}".format(
                duthost.hostname, err.strip()))

        back, elapsed = poll(
            lambda: PRELOAD.loaded(duthost) and self._stats(duthost) is not None,
            timeout=SYNCD_READY_TIMEOUT, interval=5)
        if not back:
            raise RuntimeError(
                "[sai] syncd did not come back with the shim loaded on {} within {}s. Recover "
                "with `config reload -y` before trying again.".format(
                    duthost.hostname, SYNCD_READY_TIMEOUT))
        logger.info("[sai] syncd is back on %s with the shim loaded after %ss",
                    duthost.hostname, elapsed)

    @staticmethod
    def _stats(duthost):
        return PRELOAD.read_json(duthost, STATS_FILE)

    def _hooked(self, duthost):
        stats = self._stats(duthost)
        return set(stats.get("hooked") or []) if stats else set()

    # ----------------------------------------------------------------- the three methods

    def apply(self, duthost, **params):
        if self.params["mode"] == "freeze":
            return self._freeze(duthost)

        object_type = self.params["object_type"]
        PRELOAD.deploy(duthost, FREEZE_HINT)
        self._merge_control(duthost, self.control())

        if not PRELOAD.loaded(duthost) or object_type not in self._hooked(duthost):
            self._restart_syncd(duthost)
            if object_type not in self._hooked(duthost):
                raise RuntimeError(
                    "[sai] syncd restarted but never hooked {} on {}. Either the vendor SAI "
                    "does not implement it, or its slots moved; check "
                    "`journalctl -t syncd | grep sonic-chaos` on the box.".format(
                        object_type, duthost.hostname))
        else:
            # Already patched, so arming is just the file write -- give the shim its poll
            # interval to notice before the test starts leaning on the fault.
            time.sleep(RELOAD_SETTLE)

        arm_deadman(duthost, self._deadman_tag(), int(self.params["ttl"]),
                    PRELOAD.in_container(duthost, "rm -f {}".format(CONTROL_FILE)))
        logger.info("[sai] armed %s on %s", self.describe(), duthost.hostname)

    def release(self, duthost):
        """Disarm. Safe to call twice.

        The .so and the supervisord line stay: an unarmed shim is a direct call through, and
        removing it would cost another syncd restart on a box we are handing back. Use
        `SaiInjector.uninstall(duthost)` at the end of a session to take it off entirely.
        """
        if self.params["mode"] == "freeze":
            return self._thaw(duthost)

        disarm_deadman(duthost, self._deadman_tag())
        self._merge_control(duthost, None)
        logger.info("[sai] disarmed %s on %s", self.describe(), duthost.hostname)

    def status(self, duthost):
        if self.params["mode"] == "freeze":
            _rc, state, _err = run(duthost, PRELOAD.in_container(
                duthost, "cat /proc/$(pgrep -x syncd | head -1)/stat 2>/dev/null | awk '{print $3}'"))
            state = state.strip()
            return {"active": state == "T", "mode": "freeze", "syncd_state": state or None}

        stats = self._stats(duthost)
        if stats is None:
            return {"active": False, "mode": "intercept", "loaded": PRELOAD.loaded(duthost),
                    "reason": "no stats file; the shim has not hooked anything"}

        op = self.params["op"]
        mine = [row for row in stats.get("rules", [])
                if row.get("object_type") == self.params["object_type"]
                and (op == "all" or row.get("op") == op)]
        return {
            "active": any(row.get("armed") for row in mine),
            "mode": "intercept",
            "loaded": True,
            "seq": stats.get("seq"),
            "hooked": sorted(stats.get("hooked") or []),
            "achieved": {
                "calls": sum(row.get("calls", 0) for row in mine),
                "matched": sum(row.get("matched", 0) for row in mine),
                "injected": sum(row.get("injected", 0) for row in mine),
            },
        }

    def fired(self, status):
        # freeze carries no achieved counter: it engaged iff syncd is actually SIGSTOPped.
        # intercept engaged iff at least one matching call was injected (base reads the counter).
        if self.params["mode"] == "freeze":
            return bool(status.get("active"))
        return super(SaiInjector, self).fired(status)

    def will_restart(self, duthost):
        # Mirrors apply(): freeze SIGSTOPs syncd (no restart); intercept restarts only when the
        # shim is not loaded, or this object type is not hooked yet.
        if self.params["mode"] == "freeze":
            return False
        return not PRELOAD.loaded(duthost) or self.params["object_type"] not in self._hooked(duthost)

    # A delay smaller than the latency of the operation it lands on fires but leaves no visible
    # data-plane change: measured on a lab switch, delay=5000 on a VLAN create was invisible against
    # ~13 s of config-plane overhead; delay=30000 showed. The interposer counter is the ground
    # truth either way.
    DELAY_FLOOR_MS = 15000

    def warnings(self):
        delay = int(self.params.get("delay") or 0)
        if self.params["mode"] == "intercept" and delay and delay < self.DELAY_FLOOR_MS:
            return ["sai delay={} ms may fire without a visible effect: a config-plane operation "
                    "(config vlan/route add) carries seconds of its own latency that can swamp it. "
                    "Confirm it fired with the interposer counter (docker exec syncd cat "
                    "/sonic-chaos/sai_stats.json), or raise the delay to see it on the wall "
                    "clock.".format(delay)]
        return []

    def expected_syslog(self):
        """The two error lines a ``status=`` fault makes the box print, for its op and status only.

        syncd reports the failure it was told to return, and orchagent logs the status it got back.
        Both are the fault itself. What orchagent does *next* -- ``Encountered failure in create
        operation`` and whatever follows -- is deliberately not listed: that reaction is what the
        fault exists to expose. ``delay`` and ``drop`` make no error lines, so they list nothing.
        """
        p = self.params
        status = p.get("status")
        if not status or p.get("mode") == "freeze":
            return ()
        ops = OPS if p["op"] == "all" else (p["op"],)
        apis = "|".join(op.upper() for op in ops)
        names = "|".join(ops)
        code = re.escape(status)
        return (
            r".*ERR syncd#syncd: :- sendApiResponse: api SAI_COMMON_API_(?:{}) failed in syncd mode:{}\b.*".format(
                apis, code),
            r".*ERR swss#orchagent: :- (?:{0}): (?:{0}) status: {1}\b.*".format(names, code),
        )

    # ----------------------------------------------------------------- freeze fallback

    def _freeze(self, duthost):
        rc, _out, err = run(duthost, PRELOAD.in_container(duthost, "pkill -STOP -x syncd"))
        if rc != 0:
            raise RuntimeError("[sai] could not SIGSTOP syncd on {}: {}".format(
                duthost.hostname, err.strip()))
        arm_deadman(duthost, self._deadman_tag(), int(self.params["ttl"]),
                    PRELOAD.in_container(duthost, "pkill -CONT -x syncd"))
        logger.info("[sai] froze syncd on %s; every SAI call now blocks (thaw within %ss)",
                    duthost.hostname, self.params["ttl"])

    def _thaw(self, duthost):
        disarm_deadman(duthost, self._deadman_tag())
        run(duthost, PRELOAD.in_container(duthost, "pkill -CONT -x syncd"))
        logger.info("[sai] thawed syncd on %s", duthost.hostname)

    # ----------------------------------------------------------------- teardown

    @classmethod
    def uninstall(cls, duthost):
        """Take the shim off the box entirely. Needs a syncd restart to take effect.

        Not part of release(): re-arming during a session must stay cheap. Call this when you
        are done with a testbed and want it handed back exactly as found.
        """
        for mode in cls.MODES:
            disarm_deadman(duthost, deadman_tag("sai", mode))
        run(duthost, PRELOAD.in_container(duthost, "pkill -CONT -x syncd"))
        PRELOAD.uninstall(duthost)
        # Only this lane's files. /sonic-chaos is shared with spin now, and `rm -rf` on the
        # directory would take a live spin fault's control file out from under it.
        run(duthost, PRELOAD.in_container(duthost, "rm -f {} {}".format(CONTROL_FILE, STATS_FILE)))
        logger.info("[sai] removed the shim from %s; restart syncd to unload it",
                    duthost.hostname)
