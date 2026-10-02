"""Put an interposer .so in front of one program in one container, and take it away again.

Both shim-lane injectors need the same six steps -- build it, copy it, prove it loads, wire it
into that program's supervisord entry, read its control/stats files, restore the box -- against
different targets:

    sai   -> sonic_chaos_sai.so   in front of ``syncd``     in the ``syncd`` container
    spin  -> sonic_chaos_spin.so  in front of ``orchagent`` in the ``swss`` container

Two ways to wire it, and which one is right is a property of the container, not a preference
-------------------------------------------------------------------------------------------
**supervisord** (syncd): an ``environment=LD_PRELOAD=`` line in the program's stanza.

**launcher** (swss): the same export, added to the daemon's own ``/usr/bin/<daemon>.sh``, which
ends in ``exec``. The swss container's ``docker-init.sh`` re-renders
``/etc/supervisor/conf.d/supervisord.conf`` from a j2 template on *every* container start, so an
edit to the rendered file is wiped by the very restart that was supposed to activate it -- it
looks installed, comes back absent, and the run silently proves nothing. Measured on a lab switch.
The launcher script is not in that render list, so an edit to it survives.

The launcher route is also far cheaper to activate: ``supervisorctl restart <program>`` re-execs
the script and picks up the export without bouncing the container, so no ASIC re-initialisation
and no systemd involvement. Confirmed on a lab switch -- orchagent came back with the interposer
mapped and the container never stopped.

This was ``injectors/sai.py``'s private code until ``spin`` needed the same thing. It is
unchanged in behaviour -- every hard-won detail below was paid for on hardware once already:

* **``environment=`` on one program, never ``/etc/ld.so.preload``.** The latter maps the .so
  into every process in the container -- every ``docker exec``, every supervisord child -- for
  no benefit, since only the one program calls the symbol we interpose.
* **Prove it loads before wiring it in.** A .so built against a newer glibc than the container
  has does not fail loudly: the loader prints a warning nobody reads, the daemon comes up with
  no interposer, and the run silently proves nothing. ``LD_PRELOAD=... /bin/true`` turns that
  into an error at the only moment we can still act on it.
* **``grep -c`` prints "0" *and* exits 1.** Read its output, never its exit status. Chaining
  ``|| echo 0`` yields "0\\n0", and the supervisord edit silently never happened.
* **Keep a backup of supervisord.conf**, so uninstall restores rather than reconstructs.
* **Every command goes through ``sudo_prefix``.** ``docker``, ``systemctl`` and writes under
  /usr/lib all need root. Under pytest ``duthost.shell`` already is root and the prefix is
  redundant; a standalone run over ssh lands as admin (uid 1000) and every one of them
  fails with "Access denied" -- which is how the whole sai lane was unusable from the console's
  default ssh runner while passing under pytest. Same trap injector.py's ``sudo_prefix`` docstring
  cites from a lab switch, and it has now caught three lanes.
"""
import base64
import hashlib
import json
import logging
import os
import shutil
import subprocess

from .injector import ChaosUsageError, run, quote, sudo_prefix

logger = logging.getLogger(__name__)

INSTALL_DIR = "/sonic-chaos"
SUPERVISOR_CONF = "/etc/supervisor/conf.d/supervisord.conf"
SUPERVISOR_BACKUP = SUPERVISOR_CONF + ".sonic-chaos-bak"
BUILD_TIMEOUT = 300


PACKAGE_SHIM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shim")


def shim_dir():
    """Where the interposers are built: the package's shim/ if writable, else a user cache copy."""
    if os.access(PACKAGE_SHIM_DIR, os.W_OK):
        return PACKAGE_SHIM_DIR
    cache = os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"),
                         "sonic-chaos", "shim")
    if not os.path.isdir(cache):
        shutil.copytree(PACKAGE_SHIM_DIR, cache, ignore=shutil.ignore_patterns("build"))
    return cache


class Preload(object):
    """One interposer, one program, one container."""

    def __init__(self, lane, container, program, so_name, local_binary, process=None,
                 launcher=None):
        self.lane = lane
        self.container = container
        self.program = program                    # the [program:X] stanza in supervisord.conf
        self.process = process or program         # what pgrep -x finds, if it differs
        self.launcher = launcher                  # set -> wire via this script, not supervisord
        self._binpath = {}                        # host -> real binary path from supervisord
        self.so = "{}/{}".format(INSTALL_DIR, so_name)
        self.local_binary = local_binary
        self.build_dir = os.path.dirname(os.path.dirname(local_binary))

    # -- talking to the container -------------------------------------------------------------

    def in_container(self, duthost, command):
        """``docker exec`` into this container, as root on the host whatever we are running as."""
        return "{}docker exec {} sh -c {}".format(
            sudo_prefix(duthost), self.container, quote(command))

    def write_file(self, duthost, path, content):
        """Put `content` at `path` inside the container, atomically.

        base64 over stdin rather than ``docker cp``: /tmp in these containers is a tmpfs that
        ``docker cp`` refuses, and the encoding survives any quoting the content might contain.
        """
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        script = "mkdir -p {dir} && base64 -d > {path}.tmp && mv {path}.tmp {path}".format(
            dir=INSTALL_DIR, path=path)
        return run(duthost, "echo {} | {}docker exec -i {} sh -c {}".format(
            encoded, sudo_prefix(duthost), self.container, quote(script)))

    def read_file(self, duthost, path):
        rc, out, _err = run(duthost, self.in_container(duthost, "cat {} 2>/dev/null".format(path)))
        return None if rc != 0 else out.strip()

    def read_json(self, duthost, path):
        text = self.read_file(duthost, path)
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            logger.warning("[%s] %s on %s is not valid JSON", self.lane, path, duthost.hostname)
            return None

    def remove_file(self, duthost, path):
        return run(duthost, self.in_container(duthost, "rm -f {}".format(path)))

    # -- getting the .so onto the box ---------------------------------------------------------

    def ensure_built(self, fallback_hint=""):
        """Build the interposer if this checkout has not got one yet.

        ``shim/build/`` is not committed, so a fresh clone has no binary and the first person to
        run the lane would otherwise hit a build step mid-test. It is a ten-second C build with
        no dependencies beyond a compiler, so just do it.

        Plain ``make``, not ``build.sh``: the script also runs the container test, which needs
        docker. The glibc gate it would have applied is not lost -- ``probe`` checks the real
        container, which is stricter than guessing at the floor from here.
        """
        if os.path.isfile(self.local_binary):
            return
        writable = shim_dir()
        if writable != self.build_dir:
            # An installed package is read-only; build in the user cache copy instead.
            self.local_binary = os.path.join(writable, "build", os.path.basename(self.local_binary))
            self.build_dir = writable
            if os.path.isfile(self.local_binary):
                return
        logger.info("[%s] no interposer in this checkout; building it once (~10s) in %s",
                    self.lane, self.build_dir)
        try:
            done = subprocess.run(["make", "-s"], cwd=self.build_dir, timeout=BUILD_TIMEOUT,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except (OSError, subprocess.SubprocessError) as err:
            raise ChaosUsageError("{}: no interposer at {} and building it failed ({}). Build it "
                                  "by hand:\n    {}/build.sh{}".format(
                                      self.lane, self.local_binary, err, self.build_dir,
                                      fallback_hint))
        if done.returncode != 0 or not os.path.isfile(self.local_binary):
            raise ChaosUsageError("{}: could not build the interposer in {}:\n{}\nIt needs only a "
                                  "C compiler.{}".format(
                                      self.lane, self.build_dir,
                                      (done.stdout or b"").decode("utf-8", "replace")[-800:],
                                      fallback_hint))
        logger.info("[%s] built %s", self.lane, self.local_binary)

    def _push_binary(self, duthost):
        """Copy the .so in, if what is already there is not byte-identical.

        ``duthost.copy`` exists on both the ansible duthost and the standalone ``SshDut``, which
        grew one so the sai lane could run over ssh at all. It crosses in a single round trip on
        stdin and verifies the landed size -- worth more than a chunked base64 fallback here,
        because a truncated .so is only a loader warning on the box and would silently prove
        nothing.
        """
        with open(self.local_binary, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()

        _rc, present, _err = run(duthost, self.in_container(
            duthost, "sha256sum {} 2>/dev/null".format(self.so)))
        if present.strip().startswith(digest):
            return

        logger.info("[%s] copying the interposer to %s:%s", self.lane, duthost.hostname, self.so)
        staging = "/tmp/{}".format(os.path.basename(self.local_binary))
        duthost.copy(src=self.local_binary, dest=staging)
        rc, _out, err = run(duthost, "{}docker exec -i {} sh -c {} < {}".format(
            sudo_prefix(duthost), self.container,
            quote("mkdir -p {d} && cat > {so}.tmp && chmod 0755 {so}.tmp && mv {so}.tmp {so}".format(
                d=INSTALL_DIR, so=self.so)),
            staging))
        if rc != 0:
            raise RuntimeError("[{}] could not install the interposer in the {} container on "
                               "{}: {}".format(self.lane, self.container, duthost.hostname,
                                               err.strip()))
        run(duthost, "{}rm -f {}".format(sudo_prefix(duthost), staging))

    def probe(self, duthost):
        """Refuse to go further unless the .so actually loads on this container's glibc."""
        rc, out, _err = run(duthost, self.in_container(duthost,
                                                       "LD_PRELOAD={} /bin/true 2>&1".format(self.so)))
        out = out.strip()
        if rc != 0 or "cannot" in out.lower() or "error" in out.lower():
            raise RuntimeError(
                "[{}] the interposer will not load in the {} container on {}: {}\nMost likely it "
                "was built against a newer glibc than the container has; rebuild with "
                "SONIC_CHAOS_BUILD_IMAGE=debian:bookworm shim/build.sh".format(
                    self.lane, self.container, duthost.hostname, out or "no output"))

    def wire(self, duthost):
        """Make the next start of this program load the interposer."""
        if self.launcher:
            self._wire_launcher(duthost)
        else:
            self._wire_supervisord(duthost)

    def _marker(self):
        # Matches both the environment= LD_PRELOAD line (edited launcher) and the wrap/ path we
        # write into a synthesised command=. Both contain "sonic-chaos" (the install directory).
        return "sonic-chaos"

    def _already_wired(self, duthost, path):
        # `grep -c` prints "0" AND exits 1 when it matches nothing. Read the output, never the
        # exit status: `|| echo 0` yields "0\n0" and the edit silently never happens.
        _rc, count, _err = run(duthost, self.in_container(duthost,
                                                          "grep -c {} {}".format(self._marker(), path)))
        return count.strip() not in ("", "0")

    def _wire_supervisord(self, duthost):
        run(duthost, self.in_container(duthost, "[ -f {bak} ] || cp {conf} {bak}".format(
            bak=SUPERVISOR_BACKUP, conf=SUPERVISOR_CONF)))
        if self._already_wired(duthost, SUPERVISOR_CONF):
            return
        line = 'environment=LD_PRELOAD="{}"'.format(self.so)
        rc, _out, err = run(duthost, self.in_container(
            duthost, r"sed -i '/^\[program:{}\]$/a {}' {}".format(self.program, line, SUPERVISOR_CONF)))
        if rc != 0:
            raise RuntimeError("[{}] could not add the preload line to {} on {}: {}".format(
                self.lane, SUPERVISOR_CONF, duthost.hostname, err.strip()))

    def _binary(self, duthost=None):
        """The absolute path supervisord actually execs, cached per host.

        Guessing /usr/bin/<name> was wrong for FRR: zebra lives at /usr/lib/frr/zebra and its
        stanza carries arguments. The supervisord ``command=`` line is the authoritative source,
        so parse the binary out of it (first token, arguments dropped) rather than assume a path.
        """
        host = getattr(duthost, "hostname", str(duthost)) if duthost is not None else None
        if host is not None and host not in self._binpath:
            rc, out, _err = run(duthost, self.in_container(
                duthost,
                "awk '/^\\[program:{}\\]/{{f=1}} f&&/^command=/{{sub(/^command=/,\"\");print $1;exit}}'"
                " {}".format(self.process, SUPERVISOR_CONF)))
            path = (out or "").strip()
            self._binpath[host] = path if (rc == 0 and path.startswith("/")) else None
        return self._binpath.get(host) if host is not None else None

    def _stashed(self):
        """Where the real binary goes when we swap in a wrapper. Same basename on purpose:
        ``pgrep -x <name>`` is used all over this lane, and a process exec'd from
        ``<name>.real`` would report comm=``<name>.real`` and match none of it. Keeping the
        name and changing only the directory keeps every lookup working."""
        return "{}/real/{}".format(INSTALL_DIR, self.process)

    def _wire_launcher(self, duthost):
        """Make the next start of this daemon load the interposer.

        Most SONiC daemons are started bare -- supervisord runs ``command=/usr/bin/vlanmgrd``
        with no wrapper -- so there is nothing to add an export to. Only orchagent, buffermgrd
        and swssconfig ship a ``.sh`` in swss. When the launcher exists we edit it; when it does
        not we synthesise one, which is what makes this work for any daemon rather than for the
        three that happen to have a script.
        """
        rc, _out, _err = run(duthost, self.in_container(
            duthost, "test -f {}".format(self.launcher)))
        if rc == 0:
            return self._wire_existing(duthost)
        return self._wire_wrapped(duthost)

    def _wire_wrapped(self, duthost):
        """Swap the daemon's binary for a wrapper that preloads the interposer, then execs it.

        The real binary moves to ``INSTALL_DIR/real/<name>`` and a wrapper takes its place at
        the path supervisord's ``command=`` names. This is the regeneration-proof part: swss and
        bgp both re-render supervisord.conf from a j2 on every container start, so anything
        written INTO that file is wiped by the very restart meant to load it -- but ``command=``
        regenerates to the same path, which is now the wrapper. supervisord.conf is never touched.
        Measured the hard way: a ``command=`` rewrite here survived neither container.
        """
        binary = self._binary(duthost)
        if not binary:
            raise RuntimeError(
                "[{}] cannot resolve {}'s binary from supervisord on {}, nothing to wire".format(
                    self.lane, self.process, duthost.hostname))
        rc, _out, _err = run(duthost, self.in_container(duthost, "test -x {}".format(binary)))
        if rc != 0:
            raise RuntimeError("[{}] {}'s binary {} is not executable on {}".format(
                self.lane, self.process, binary, duthost.hostname))
        if self._already_wired(duthost, binary):
            return
        # The wrapper execs the STASHED binary, not its own path -- execing the path it sits at
        # would loop. supervisord's command= arguments are still appended by supervisord.
        script = "#!/bin/sh\nexport LD_PRELOAD=\"{so}\"\nexec {real} \"$@\"\n".format(
            so=self.so, real=self._stashed())
        encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
        # cp the real binary aside first (cp -n: never clobber a good stash on a re-arm), then
        # overwrite its path with the wrapper via temp+mv, so the path is never absent mid-step.
        steps = ("mkdir -p {d}/real && cp -n {b} {r} && chmod 0755 {r} && "
                 "base64 -d > {b}.hs && chmod 0755 {b}.hs && mv {b}.hs {b}").format(
                     d=INSTALL_DIR, b=binary, r=self._stashed())
        rc, _out, err = run(duthost, "echo {} | {}docker exec -i {} sh -c {}".format(
            encoded, sudo_prefix(duthost), self.container, quote(steps)))
        if rc != 0:
            raise RuntimeError("[{}] could not wrap {} on {}: {}".format(
                self.lane, binary, duthost.hostname, err.strip()))
        if not self._already_wired(duthost, binary):
            raise RuntimeError("[{}] wrapper for {} did not land on {}".format(
                self.lane, binary, duthost.hostname))

    def _wire_existing(self, duthost):
        """Export LD_PRELOAD just above the launcher's ``exec``.

        ``cp -n`` so a second apply does not overwrite the pristine backup with an already-wired
        copy, which would leave uninstall restoring the fault instead of removing it.
        """
        backup = self.launcher + ".sonic-chaos-bak"
        run(duthost, self.in_container(duthost, "cp -n {} {}".format(self.launcher, backup)))
        if self._already_wired(duthost, self.launcher):
            return
        cmd = 'sed -i \'/^exec /i export LD_PRELOAD="{}"\' {}'.format(
            self.so, self.launcher)
        rc, _out, err = run(duthost, self.in_container(duthost, cmd))
        if rc != 0:
            raise RuntimeError("[{}] could not wire {} on {}: {}".format(
                self.lane, self.launcher, duthost.hostname, err.strip()))
        if not self._already_wired(duthost, self.launcher):
            raise RuntimeError(
                "[{}] {} has no `exec` line to wire on {} -- the daemon is not started the way "
                "this expects".format(self.lane, self.launcher, duthost.hostname))

    def deploy(self, duthost, fallback_hint=""):
        self.ensure_built(fallback_hint)
        self._push_binary(duthost)
        self.probe(duthost)
        self.wire(duthost)

    def loaded(self, duthost):
        """Is the .so mapped into the running program?

        Out of /proc rather than anything the interposer writes, so the answer is the kernel's
        even if it never got far enough to leave a stats file.

        A mapping that ends in "(deleted)" is *not* loaded, for our purposes. ``_push_binary``
        swaps a new build in with an atomic rename, and a running program keeps the old inode
        mapped, so /proc still lists the path -- with "(deleted)" after it. Counting that as
        loaded meant a fixed interposer never reached a box that already ran an older one: the
        new file landed on disk, the restart was skipped, and the old code kept running. Found
        with the per-period spin fix, which would otherwise have shipped and done nothing.

        Reads the output rather than grep's exit status, for the reason the module docstring
        gives.
        """
        _rc, out, _err = run(duthost, self.in_container(
            duthost, "grep {} /proc/$(pgrep -x {} | head -1)/maps 2>/dev/null".format(
                os.path.basename(self.so), self.process)))
        maps = [line for line in out.splitlines() if line.strip()]
        if not maps:
            return False
        return not any(line.rstrip().endswith("(deleted)") for line in maps)

    def uninstall(self, duthost):
        """Take the wiring back out. The caller restarts the program to make it take.

        Two shapes, both attempted (each a no-op if it does not apply): a swapped binary (move
        the stash back over the wrapper) and an edited launcher .sh (restore its backup, else
        strip our line). The sai case (no launcher) restores supervisord.conf's backup instead.
        """
        if self.launcher:
            binary = self._binary(duthost)
            if binary:
                run(duthost, self.in_container(duthost,
                    "[ -f {r} ] && mv -f {r} {b} || true".format(r=self._stashed(), b=binary)))
            run(duthost, self.in_container(
                duthost,
                "if [ -f {bak} ]; then mv -f {bak} {sh}; "
                "elif [ -f {sh} ] && grep -q {m} {sh}; then sed -i '/{m}/d' {sh}; fi".format(
                    bak=self.launcher + ".sonic-chaos-bak", sh=self.launcher, m=self._marker())))
        else:
            run(duthost, self.in_container(duthost,
                "[ -f {bak} ] && mv -f {bak} {t} || sed -i '/{m}/d' {t}".format(
                    bak=SUPERVISOR_BACKUP, t=SUPERVISOR_CONF, m=self._marker())))
        run(duthost, self.in_container(duthost,
            "rm -rf {d}/real {d}/wrap {so}".format(d=INSTALL_DIR, so=self.so)))
