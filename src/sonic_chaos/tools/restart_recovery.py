"""Reproduce a known ticket on a live DUT: Spine's real fault, then Oracle's real contract.

    sonic-chaos tool restart-recovery --dut ssh://admin@<switch>
    sonic-chaos tool restart-recovery --dut ssh://admin@<switch>

The fault is a cold orchagent-only restart. The cold-restart route-loss failure: the new orchagent
rebuilds its temp view without replaying ProducerStateTable-fed APPL_DB state (fpmsyncd's
routes, SRv6 SIDs), so
APPLY_VIEW removes from the ASIC things APPL_DB still holds. Pure orchagent logic, no vendor
SAI in the path. On DNX hardware the same restart is also the DNX cold-restart path -- syncd may
declare the view inconsistent and orchagent SIGABRT -- which is why this refuses to run on a
box that is not already clean, checks health afterwards, and prints the recovery plan.

Sequence: steady-state gate -> route census -> kill (polls until orchagent is back) ->
wait_consistent(parity, RECOVER) -> route census -> health. Evidence goes to a ReproBundle.
"""
import os
import sys
import time

from .. import injectors  # noqa: F401,E402
from .. import oracle  # noqa: E402
from ..bundle import ReproBundle  # noqa: E402
from ..injector import get  # noqa: E402
from . import target_dut  # noqa: E402

TICKET = os.environ.get("TICKET", "")
SPEC = os.environ.get("SPEC", "orchagent:how=restart:settle=300")
RECOVER = int(os.environ.get("RECOVER", "300"))
OUT = os.environ.get("OUT", "out/chaos")

ROUTES = {"APPL_DB": ["ROUTE_TABLE:"], "ASIC_DB": ["ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:"]}


def census(dut):
    """Route counts on both sides -- the cold-restart route-loss symptom is ASIC routes vanishing."""
    snap = oracle.snapshot(dut, dbs=("APPL_DB", "ASIC_DB"), prefixes=ROUTES, name_maps=False)
    appl = len(snap.keys("APPL_DB", "ROUTE_TABLE:"))
    asic = len(snap.keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:"))
    return snap, appl, asic


CONTAINERS = ("swss", "syncd", "bgp", "teamd", "lldp", "pmon", "database")


def container_started(dut):
    """``{container: "running StartedAt" | "stopped StartedAt"}`` -- compared before/after.

    Both halves matter. A container that restarted has a new StartedAt. A container that stopped
    and never came back keeps its OLD StartedAt -- run 2 on a lab switch reported "restarted: none"
    while swss, syncd, bgp and teamd were all dead, because this only compared timestamps.
    """
    res = dut.shell_raw("docker inspect --format '{{.Name}} {{.State.Running}} {{.State.StartedAt}}' "
                        + " ".join(CONTAINERS))
    out = {}
    for line in (res.get("stdout") or "").splitlines():
        parts = line.strip().lstrip("/").split()
        if len(parts) == 3:
            out[parts[0]] = ("running " if parts[1] == "true" else "stopped ") + parts[2]
    return out


def show(divs, indent="    "):
    for d in divs[:12]:
        print("{}[{}] {:<10} {}".format(indent, d.kind, d.db, d.key[:70]))
        print("{}    {}".format(indent, str(d.detail)[:120]))
    if len(divs) > 12:
        print("{}... and {} more".format(indent, len(divs) - 12))


def main():
    dut = target_dut()
    bundle = ReproBundle("repro/{}".format(TICKET), root=OUT)
    print("ticket {}  box {}  fault kill={}  recover_within {}s\n".format(TICKET, dut.hostname, SPEC, RECOVER))

    # -- steady state -----------------------------------------------------------------------
    print("gate    parity + health must hold before we touch anything")
    real, notices, before = oracle.gate(dut, only=["parity", "health"])
    for n in notices:
        print("    not checked: {} -- {}".format(n.kind, n.detail[:90]))
    if real:
        print("  INVALID: the box is already divergent; a fault injected now proves nothing")
        show(real)
        return 2
    print("  clean")
    bundle.add("oracle_before.json",
               {"hostname": before.hostname, "taken_at": before.taken_at, "tables": before.tables})

    print("\ncensus  routes before")
    routes_before, a0, s0 = census(dut)
    print("  APPL_DB ROUTE_TABLE {}   ASIC_DB ROUTE_ENTRY {}".format(a0, s0))
    started_before = container_started(dut)

    # -- the fault --------------------------------------------------------------------------
    injector = get("kill").from_spec(SPEC)
    print("\ninject  {}".format(injector.describe()))
    t0 = time.time()
    event = injector.apply(dut)
    took = round(time.time() - t0, 1)
    recovered = (event or {}).get("recovered")
    print("  orchagent back: {}  (pid {} -> {}, {}s)".format(
        recovered, (event or {}).get("pid_before"), (event or {}).get("pid_after"), took))
    bundle.add("fault.json", {"ticket": TICKET, "spec": SPEC, "event": event})
    if not recovered:
        print("  !! orchagent did not come back inside the settle budget. On DNX this is the cold-restart path.")
    started_after = container_started(dut)
    restarted = sorted(c for c in started_after
                       if started_after[c].startswith("running") and started_after[c] != started_before.get(c))
    stopped = sorted(c for c in started_after if started_after[c].startswith("stopped"))
    print("  blast radius: restarted = {}   STOPPED and not back = {}".format(
        ", ".join(restarted) or "none", ", ".join(stopped) or "none"))
    if stopped:
        print("  !! {} down after the fault. Check `systemctl show <unit> -p Result` for "
              "start-limit-hit before assuming a crash.".format(", ".join(stopped)))
        restarted = sorted(set(restarted) | set(stopped))
    if restarted:
        print("  !! a process restart that takes {} with it is a cold container start, not an "
              "orchagent-only restart -- it is not the {} shape".format(", ".join(restarted), TICKET))
    bundle.add("blast_radius.json", {"before": started_before, "after": started_after, "restarted": restarted})

    # -- the contract -----------------------------------------------------------------------
    print("\noracle  parity must hold again within {}s".format(RECOVER))
    baseline = oracle.finding_keys(real)
    findings, notices, elapsed, after = oracle.wait_consistent(
        dut, only="parity", timeout=RECOVER, interval=15, baseline=baseline)
    bundle.add("oracle_after.json",
               {"hostname": after.hostname, "taken_at": after.taken_at, "tables": after.tables})
    if findings:
        print("  {} divergence(s) still present {}s after the restart:".format(len(findings), elapsed))
        show(findings)
        bundle.add("oracle_findings.txt", oracle.format_divergences(
            findings, header="{}: {} divergence(s) {}s after orchagent restart".format(TICKET, len(findings), elapsed)))
    else:
        print("  consistent after {}s".format(elapsed))

    print("\ncensus  routes after")
    routes_after, a1, s1 = census(dut)
    print("  APPL_DB ROUTE_TABLE {} ({:+d})   ASIC_DB ROUTE_ENTRY {} ({:+d})".format(a1, a1 - a0, s1, s1 - s0))
    route_diff = oracle.diff(routes_before, routes_after)
    if route_diff:
        print("  {} route-level change(s); first few:".format(len(route_diff)))
        show(route_diff, indent="    ")
        bundle.add("route_diff.txt", oracle.format_divergences(
            route_diff, header="ROUTE_TABLE / ROUTE_ENTRY before vs after"))

    # -- health, and the way home ----------------------------------------------------------
    print("\nhealth  must hold again within {}s".format(RECOVER))
    hreal, hnotices, helapsed, _ = oracle.wait_consistent(dut, only="health", timeout=RECOVER, interval=15)
    for n in hnotices:
        print("    not checked: {}".format(n.kind))
    if hreal:
        print("  {} health violation(s) still present after {}s:".format(len(hreal), helapsed))
        show(hreal)
        # What actually worked on a lab switch after a start-limit-hit, in this order. `config reload -y`
        # alone did NOT bring swss back there; `systemctl start swss` did, in 45 s.
        print("\n  RECOVERY, in order:")
        print("    1. sudo systemctl reset-failed swss syncd bgp teamd   # clears start-limit-hit")
        print("    2. sudo systemctl start swss                          # brought all four back in 45s")
        print("    3. if still down: re-provision {} with your lab's tooling".format(dut.hostname))
    else:
        print("  clean after {}s".format(helapsed))

    # -- did the routes come back? -----------------------------------------------------------
    # Parity holding on two empty databases is consistent but not recovered. The contract also
    # says the box must be back to what it was: give the routes the same budget.
    print("\nroutes  must return to >= 90% of {} within {}s".format(a0, RECOVER))
    t0, floor = time.time(), int(a0 * 0.9)
    while True:
        _, a2, s2 = census(dut)
        relapsed = round(time.time() - t0, 1)
        if a2 >= floor or relapsed >= RECOVER:
            break
        print("  {}s: APPL {} ASIC {} ...".format(relapsed, a2, s2))
        time.sleep(30)
    routes_back = a2 >= floor
    print("  {}: APPL_DB {} ASIC_DB {} after {}s".format(
        "recovered" if routes_back else "NOT recovered", a2, s2, relapsed))

    # -- verdict ------------------------------------------------------------------------------
    # The cold-restart route-loss signature is ONE-SIDED: APPL_DB keeps the routes while the ASIC loses them, so
    # route_check fails. Routes vanishing from BOTH sides is a consistent teardown (BGP withdrew,
    # or swss flushed APPL_DB on a cold start) -- parity holds, and calling that "reproduced"
    # would be the tool lying. Report what the evidence supports and nothing more.
    print("\n" + "=" * 78)
    one_sided = bool(findings) or (a1 >= max(a0 // 2, 1) and s1 < a1 // 2)
    if one_sided:
        verdict = "REPRODUCED -- APPL_DB kept its routes while the ASIC lost them (one-sided)"
        code = 1
    elif s1 < s0 // 2 and a1 < a0 // 2:
        verdict = ("NOT the {} shape: routes left BOTH databases ({} -> {} APPL, {} -> {} ASIC), so parity "
                   "holds. That is a consistent teardown, not APPLY_VIEW dropping ASIC state.").format(
                       TICKET, a0, a1, s0, s1)
        code = 0
    else:
        verdict = "did not reproduce on this image"
        code = 0
    if hreal:
        verdict += "\nHEALTH REGRESSION: {} violation(s) outlived the {}s budget -- a finding in its own right.".format(
            len(hreal), RECOVER)
        code = max(code, 1)
    if not routes_back:
        verdict += "\nROUTES NOT RECOVERED: {} -> {} APPL_DB routes {}s after the fault, BGP {}.".format(
            a0, a2, RECOVER, "Established" if not hreal else "not Established")
        code = max(code, 1)
    if restarted:
        verdict += "\nBLAST RADIUS: the fault restarted {} -- cold container start, APPL_DB flushed.".format(
            ", ".join(restarted))
    print("{}: {}".format(TICKET, verdict))
    print("evidence: {}".format(bundle.dir))
    bundle.add("verdict.txt", "{}\n{}\n".format(TICKET, verdict))
    return code


if __name__ == "__main__":
    sys.exit(main())
