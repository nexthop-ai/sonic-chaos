"""Spine lane -- flood syslog.

    --chaos syslog=5000:seconds=30          5000 messages/second for 30 s
    --chaos syslog=20000:seconds=10:size=512

Cheap, and it attacks something nothing else does: the logging path is shared by every daemon
and by the health checks that decide whether the box is alive. A flood competes for disk I/O,
can fill /var/log, and -- the interesting part -- can make rate-limited loggers *drop* the one
message that explains a real failure. A bug that only shows up as "we have no logs from the
window that matters" is a bug.

It also pairs well: run it underneath another fault and see whether the evidence for that fault
survives. If our own repro bundle loses the syslog window under load, the bundle is not evidence.

Mechanism is a `logger` loop inside a container, so nothing is installed. Bounded by `seconds`
and by a disk-usage guard, because filling /var/log on a shared box degrades it for the next user.
The guard is checked *before* the first message: refusing to start on a box that is already
short of disk is the whole point, and checking afterwards would be too late.
"""
import logging

from ..injector import (
    Injector, ChaosUsageError, register, resolve_container, require_target, as_bool,
    run, quote, arm_deadman, disarm_deadman, deadman_tag, poll,
)

logger = logging.getLogger(__name__)


@register
class SyslogInjector(Injector):
    name = "syslog"
    lane = "spine"
    positional = ("rate", "seconds")
    # `ident` is what `logger -t` calls the tag. It is deliberately NOT named `tag`: an
    # experiment file's fault entry uses `tag` for supported-op/unsupported-op scheduling
    # metadata, both land in the same YAML mapping, and PyYAML keeps the last one -- so a
    # `tag:` here would silently become scheduling metadata and the flood would fall back to
    # the default ident. experiment.py now rejects that collision outright; the rename means
    # there is nothing to collide.
    # `process` and `container` are both optional and either may be given. `container` is
    # deliberately NOT defaulted here: with a default there is no way to tell "the user asked
    # for swss" from "nobody said", which is what makes contradicting a process's own container
    # detectable rather than silently overridden. DEFAULT_CONTAINER applies when neither is set.
    defaults = {"rate": "1000", "seconds": "30", "size": "200",
                "ident": "sonic-chaos", "facility": "user", "severity": "notice",
                "max_disk_pct": "85"}

    DEFAULT_CONTAINER = "swss"

    # A flood at `debug` exercises the filtered path -- whether a severity rsyslog is configured
    # to drop still costs the box the I/O to decide that. `err` and above reach the console.
    FACILITIES = ("user", "daemon", "local0", "local1", "local2", "local3", "local4",
                  "local5", "local6", "local7", "syslog", "kern")
    SEVERITIES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")

    def validate(self):
        p = self.params
        for key, lo, hi in (("rate", 1, 100000), ("seconds", 1, 600), ("size", 16, 8192),
                            ("max_disk_pct", 50, 95)):
            try:
                value = int(p[key])
            except ValueError:
                raise ChaosUsageError("syslog: {} must be an integer, got {!r}".format(key, p[key]))
            if not lo <= value <= hi:
                raise ChaosUsageError("syslog: {} must be {}..{}, got {}".format(key, lo, hi, value))
        if not p["ident"].replace("_", "").replace("-", "").isalnum():
            raise ChaosUsageError(
                "syslog: ident must be alphanumeric (plus - and _), got {!r}".format(p["ident"]))
        for key, allowed in (("facility", self.FACILITIES), ("severity", self.SEVERITIES)):
            if p[key] not in allowed:
                raise ChaosUsageError("syslog: {} must be one of {}, got {!r}".format(
                    key, "/".join(allowed), p[key]))
        # Targeting: a process, a container, or neither.
        #
        #   syslog=5000:process=orchagent   flood from wherever orchagent lives (swss)
        #   syslog=5000:container=bgp       flood from a container directly
        #   syslog=5000                     flood from swss
        #
        # Naming a process is the useful form when the flood is meant to compete with a
        # particular daemon's own logging -- which is the whole point of this fault, since the
        # question it asks is whether the evidence for another fault survives under load. It
        # also means syslog targets the same way kill, pause and redis do, rather than being
        # the one injector that needs a container name on the CLI.
        process, container = p.get("process"), p.get("container")
        if process:
            owning = require_target(process, as_bool(p.get("force", False), "syslog: force"), "syslog")
            if container and resolve_container(container) != owning:
                raise ChaosUsageError(
                    "syslog: process {!r} runs in container {!r}, not {!r}. Drop the container "
                    "parameter, or name a process that lives in it.".format(
                        process, owning, container))
            p["container"] = owning
        else:
            # Resolve so a typo in the container fails here, not on the box.
            p["container"] = resolve_container(container or self.DEFAULT_CONTAINER)

    def estimated_bytes(self):
        p = self.params
        return int(p["rate"]) * int(p["seconds"]) * int(p["size"])

    def priority(self):
        """``user.notice`` -- what ``logger -p`` wants."""
        return "{}.{}".format(self.params["facility"], self.params["severity"])

    def deadman_name(self):
        return deadman_tag("syslog", self.params["container"], self.params["ident"])

    def marker(self):
        """A string unique to this flood, used to find and kill the generator inside the container."""
        return "chaosflood-{}".format(self.params["ident"])

    def generator_script(self):
        """The flood loop, as a shell program run inside the container.

        Two things here were learned from a real box, and both are load-bearing:

        * **Every line must be unique.** rsyslog collapses repeated identical messages into
          "last message repeated N times", so a constant payload floods nothing: a 3 s run at
          2000/s delivered *one* line. Stamping each line with the batch and line counter took
          the same run to 4600 delivered.
        * ``logger`` is spawned once per batch, not once per message. A process spawn per
          message caps out in the low hundreds per second and would make ``rate`` a fiction.

        The leading marker comment is what ``pgrep -f`` matches inside the container, since the
        whole script arrives as the shell's argv rather than as a file.
        """
        p = self.params
        payload = "x" * max(1, int(p["size"]) - len(p["ident"]) - 32)
        return (
            "# {marker}\n"
            "n=0; end=$(( $(date +%s) + {seconds} )); "
            "while [ $(date +%s) -lt $end ]; do "
            "  n=$((n+1)); "
            "  for i in $(seq 1 {batch}); do echo \"$n-$i {payload}\"; done "
            "    | logger -t {ident} -p {pri}; "
            "  sleep 0.1; "
            "done"
        ).format(marker=self.marker(), seconds=int(p["seconds"]),
                 batch=max(1, int(p["rate"]) // 10), payload=payload,
                 ident=p["ident"], pri=self.priority())

    # -- lifecycle ---------------------------------------------------------------------------

    def apply(self, duthost, **params):
        p = dict(self.params, **params)
        seconds, container = int(p["seconds"]), p["container"]

        free_pct = self._disk_pct(duthost)
        if free_pct is not None and free_pct >= int(p["max_disk_pct"]):
            raise RuntimeError(
                "syslog: /var/log on {} is already {}% full (limit {}%). Refusing to flood it -- "
                "filling a shared box's disk degrades it for whoever books it next.".format(
                    duthost.hostname, free_pct, p["max_disk_pct"]))

        before = self._delivered(duthost)

        # The script is passed as an argument, not copied in as a file. `docker cp` cannot write
        # into the container's /tmp at all: it is a tmpfs mount (and noexec), and cp works
        # against the container's filesystem layer, so it fails with "Could not find the file".
        # That failure used to be invisible -- its rc went unchecked, and the `docker exec -d`
        # after it returns 0 whether or not the script exists, because a detached exec never
        # waits. The injector reported a flood it had never started. Passing the body inline
        # removes the file, the directory, and both failure modes.
        cmd = "docker exec -d {} sh -c {}".format(container, quote(self.generator_script()))
        run(duthost, cmd)

        # `docker exec -d` always returns 0, so the only honest check is whether the generator
        # is actually in the container's process table afterwards.
        alive, waited = poll(lambda: self._running(duthost), timeout=10, interval=1)
        if not alive:
            rc, out, err = run(duthost, "docker exec {} sh -c {} 2>&1 | head -3".format(
                container, quote(self.generator_script())))
            raise RuntimeError(
                "syslog: the generator was not running {}s after launch on {}. Running it in the "
                "foreground said: {!r}".format(waited, duthost.hostname,
                                               (out or err).strip()[:300] or "nothing"))

        # Bounded twice: the loop has its own deadline, and the dead-man kills it if the loop
        # itself wedges. Neither path leaves a box writing logs forever.
        arm_deadman(duthost, self.deadman_name(), seconds + 30,
                    ["docker exec {} pkill -f {} 2>/dev/null".format(container, quote(self.marker()))])

        logger.info("[syslog] %s on %s: %s msg/s for %ss (~%d bytes, /var/log at %s%%)",
                    self.describe(), duthost.hostname, p["rate"], seconds,
                    self.estimated_bytes(), free_pct)
        return self.record(duthost, action="syslog_flood", command=cmd, rate=int(p["rate"]),
                           seconds=seconds, ident=p["ident"], priority=self.priority(),
                           process=p.get("process"), container=container,
                           disk_pct_before=free_pct, delivered_before=before,
                           verified_running=True, estimated_bytes=self.estimated_bytes())

    def release(self, duthost):
        """Stop the generator. Deliberately does NOT truncate logs -- the window is the evidence."""
        run(duthost, "docker exec {} pkill -f {} 2>/dev/null; true".format(
            self.params["container"], quote(self.marker())))
        disarm_deadman(duthost, self.deadman_name())
        logger.info("[syslog] release on %s: generator stopped, logs left intact", duthost.hostname)

    def status(self, duthost):
        p = self.params
        last = (self.events() or [{}])[-1]
        now, before = self._delivered(duthost), last.get("delivered_before")
        # Unreadable at either end means we do not know, and must not pretend otherwise.
        delivered = None if now is None or before is None else now - before
        attempted = int(p["rate"]) * int(p["seconds"])
        drop_pct = None
        if delivered is not None and attempted and 0 <= delivered <= attempted:
            drop_pct = round(100.0 * (attempted - delivered) / attempted, 1)
        return {
            "active": self._running(duthost),
            "delivered": delivered,
            "attempted": attempted,
            # A large gap is itself the finding: the logging path dropped what it was handed.
            # A None drop_pct means the log could not be read, NOT that nothing arrived.
            "achieved": {"delivered": delivered, "attempted": attempted,
                         "drop_pct": drop_pct, "disk_pct": self._disk_pct(duthost)},
        }

    # -- helpers -----------------------------------------------------------------------------

    def _disk_pct(self, duthost):
        """/var/log usage as an integer percent, or None when it cannot be read."""
        rc, out, _ = run(duthost, "df --output=pcent /var/log | tail -1")
        text = (out or "").strip().rstrip("%").strip()
        return int(text) if rc == 0 and text.isdigit() else None

    def _delivered(self, duthost):
        """How many of our tagged lines reached the log, or ``None`` if we could not read it.

        ``sudo`` is not optional: /var/log/syslog is ``root:adm 0640``, so the admin account a
        plain SSH session uses cannot read it. Without this the count came back empty and was
        being reported as *zero delivered* -- which then showed up as a 100% drop rate, a
        fabricated finding far worse than admitting we could not measure.

        ``None`` rather than 0 for the same reason: a measurement we failed to take must not be
        indistinguishable from a measurement of nothing.
        """
        rc, out, _ = run(duthost, "sudo grep -c {} /var/log/syslog".format(
            quote(self.params["ident"])))
        text = (out or "").strip()
        if text.isdigit():
            return int(text)
        # grep exits 1 with empty output when the pattern is simply absent; that is a real zero.
        return 0 if rc == 1 and not text else None

    def _running(self, duthost):
        """Is the generator alive inside the container? Matched on the marker the script carries."""
        rc, out, _ = run(duthost, "docker exec {} pgrep -f {} >/dev/null 2>&1 && echo yes || echo no".format(
            self.params["container"], quote(self.marker())))
        return out.strip() == "yes"

    def expected_syslog(self):
        """Our own flood, and rsyslog complaining about it. Both are noise we created."""
        return (
            r".*{}.*".format(self.params["ident"]),
            r".* rsyslogd.*imuxsock.*begin to drop messages.*",
            r".* rsyslogd.*rate-limiting.*",
        )
