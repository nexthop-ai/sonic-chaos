"""Spine lane -- corrupt one database entry, restore it on release.

    --chaos corrupt=APPL_DB:[LAG_MEMBER_TABLE:PortChannel12:Ethernet48]:status=garbage
    --chaos corrupt=CONFIG_DB:[PORTCHANNEL_MEMBER|PortChannel12|Ethernet48]:mtu=abc

Positional: the DB, then the key (in [...] because APPL_DB keys contain colons). Every keyword
param is a field to overwrite. ``apply`` snapshots the original hash first; ``release`` restores it
exactly (deleting fields we added).

ASIC_DB and COUNTERS_DB need ``force=true``. Writing to ASIC_DB goes behind orchagent's back --
orchagent believes it is the only writer of intent there -- so a corruption can wedge syncd and
will not self-heal. That is a real and interesting fault (it is how you prove syncd's view
reconciliation is or is not defensive), but it should never be something a random scheduler
picks by accident::

    --chaos corrupt=ASIC_DB:[ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:oid:0x1b...]:force=true\
                            :SAI_LAG_MEMBER_ATTR_PORT_ID=oid:0xdead

Deleting a key is ``delete=true`` -- the "corrupted keys" case, where the entry vanishes from one
database while every other database still believes it exists.

Restore is exact, not approximate: the original hash is read back before the first write, so
``release`` puts every original field back and ``HDEL``s the ones we invented. A key that did not
exist before is deleted on release rather than left behind as a half-real entry.
"""
import logging

from ..injector import (
    Injector, ChaosUsageError, register, as_bool, hgetall, hset, hdel, delete_key,
)

logger = logging.getLogger(__name__)


@register
class CorruptInjector(Injector):
    name = "corrupt"
    lane = "spine"
    positional = ("db", "key")
    defaults = {}

    DBS = ("APPL_DB", "CONFIG_DB", "STATE_DB", "ASIC_DB", "COUNTERS_DB")
    # Writing here bypasses the daemon that owns the database; no self-healing path.
    FORCED_DBS = ("ASIC_DB", "COUNTERS_DB")

    def validate(self):
        p = self.params
        if "db" not in p or "key" not in p:
            raise ChaosUsageError("corrupt: needs DB and [key], e.g. "
                                  "corrupt=APPL_DB:[LAG_MEMBER_TABLE:PortChannel12:Ethernet48]:status=x")
        if p["db"] not in self.DBS:
            raise ChaosUsageError("corrupt: db must be one of {}, got {!r}".format(
                "/".join(self.DBS), p["db"]))
        force = as_bool(p.get("force", False), "corrupt: force")
        if p["db"] in self.FORCED_DBS and not force:
            raise ChaosUsageError(
                "corrupt: writing {} bypasses the daemon that owns it and will not self-heal. "
                "Pass force=true if you mean it, and tag the fault unsupported-op.".format(p["db"]))
        self.delete = as_bool(p.get("delete", False), "corrupt: delete")
        self.fields = {k: v for k, v in p.items()
                       if k not in ("db", "key", "force", "delete")}
        if not self.fields and not self.delete:
            raise ChaosUsageError(
                "corrupt: give at least one field=value to overwrite, or delete=true to remove the key")
        self._saved = {}   # hostname -> {"existed": bool, "hash": {field: value}}

    # -- lifecycle ---------------------------------------------------------------------------

    def apply(self, duthost, **params):
        db, key = self.params["db"], self.params["key"]

        original = hgetall(duthost, db, key)
        existed = bool(original)
        if not existed and not self.fields:
            raise RuntimeError(
                "corrupt: {} {!r} does not exist on {}, so there is nothing to delete. A fault that "
                "silently did nothing would be reported as 'no divergence found'.".format(
                    db, key, duthost.hostname))
        # Idempotent apply: only the FIRST apply records the pristine hash, so applying twice and
        # releasing once still restores the original rather than our own corruption.
        self._saved.setdefault(duthost.hostname, {"existed": existed, "hash": dict(original)})

        if self.delete:
            cmd = delete_key(duthost, db, key)
            logger.info("[corrupt] %s on %s: deleted %s %s (%d field(s) saved)",
                        self.describe(), duthost.hostname, db, key, len(original))
        else:
            cmd = hset(duthost, db, key, self.fields)
            logger.info("[corrupt] %s on %s: set %s on %s %s", self.describe(), duthost.hostname,
                        sorted(self.fields), db, key)

        after = hgetall(duthost, db, key)
        applied = self._verify(after)
        if not applied:
            raise RuntimeError(
                "corrupt: write to {} {!r} on {} did not take effect (read back {!r}). The DB may "
                "have rejected it, or the owning daemon overwrote it instantly.".format(
                    db, key, duthost.hostname, after))

        return self.record(duthost, action="corrupt", command=cmd, db=db, key=key,
                           deleted=self.delete, fields=dict(self.fields),
                           existed_before=existed, original=dict(original))

    def release(self, duthost):
        """Put the entry back exactly as it was. Safe to call twice and safe if apply never ran."""
        saved = self._saved.pop(duthost.hostname, None)
        if saved is None:
            return   # never applied here, or already released
        db, key = self.params["db"], self.params["key"]
        original, existed = saved["hash"], saved["existed"]

        if not existed:
            # We invented this key. Leaving it behind would be a corruption that outlives the run.
            delete_key(duthost, db, key)
            logger.info("[corrupt] release on %s: deleted %s %s (it did not exist before)",
                        duthost.hostname, db, key)
            return

        if original:
            hset(duthost, db, key, original)
        # Fields we added that were never in the original hash have to go, or the restore is a
        # superset of the truth rather than the truth.
        invented = set(self.fields) - set(original)
        if invented:
            hdel(duthost, db, key, invented)
        logger.info("[corrupt] release on %s: restored %s %s (%d field(s), dropped %s)",
                    duthost.hostname, db, key, len(original), sorted(invented) or "nothing")

    def status(self, duthost):
        db, key = self.params["db"], self.params["key"]
        current = hgetall(duthost, db, key)
        return {
            "active": self._verify(current),
            "fields": sorted(self.fields),
            "delete": self.delete,
            "present": bool(current),
            "achieved": {f: current.get(f) for f in sorted(self.fields)} if not self.delete else None,
        }

    # -- helpers -----------------------------------------------------------------------------

    def _verify(self, current):
        """Is the corruption actually in place right now?"""
        if self.delete:
            return not current
        return all(current.get(f) == v for f, v in self.fields.items())

    def expected_syslog(self):
        """A daemon reading a field we deliberately made invalid will complain, and should.

        Nothing is listed here on purpose. The complaint *is* the finding -- specifically whether
        the daemon rejects the bad value cleanly or crashes on it -- so it must reach loganalyzer.
        """
        return ()
