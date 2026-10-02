"""The ``sonic-chaos`` command.

    sonic-chaos run --dut ssh://admin@10.0.0.5 --chaos kill=orchagent       one fault, graded
    sonic-chaos run --dut ... --chaos-file orchagent-restart                 a seeded experiment
    sonic-chaos list [injectors|invariants|experiments|transports]           what is available
    sonic-chaos validate 'sai=route_entry:create:delay=2000'                 check a spec, touch nothing
    sonic-chaos schema                                                       experiment JSON Schema
    sonic-chaos selftest                                                     the contract check, no switch
    sonic-chaos tool <name> --dut ... [args]                                 harness self-checks on a box
    sonic-chaos shim build                                                   build the C interposers
    sonic-chaos console [--host 127.0.0.1] [--port 8811]                     the web console
"""
import argparse
import json
import os
import subprocess
import sys

from . import __version__


def _run(argv):
    from .engine import runner
    return runner.main(argv)


def _list(args):
    from . import injectors  # noqa: F401  registers them
    from . import oracle
    from .engine.runner import SHIPPED_EXPERIMENTS
    from .injector import REGISTRY
    what = args.what
    if what == "injectors":
        for name in sorted(REGISTRY):
            cls = REGISTRY[name]
            positional = ":".join(cls.positional) if cls.positional else ""
            print("{:9s} {:8s} {}={}".format(name, cls.lane or "", name, positional))
    elif what == "invariants":
        for name in sorted(oracle.INVARIANTS):
            print("{:20s} {}".format(name, oracle.INVARIANT_GROUP.get(name, "")))
    elif what == "experiments":
        for fname in sorted(os.listdir(SHIPPED_EXPERIMENTS)):
            if fname.endswith(".yml"):
                print(fname[:-4])
    elif what == "transports":
        from . import transport
        transport._site_schemes()
        print("ssh://user@host[:port]\nlocal://\ncmd:<command prefix>")
        for scheme in sorted(set(transport._SCHEMES) - {"ssh", "local"}):
            print("{}://...".format(scheme))
    return 0


def _validate(args):
    from . import injectors  # noqa: F401
    from .injector import ChaosPlan, ChaosUsageError
    try:
        plan = ChaosPlan.from_args(args.specs)
        for inj in plan.injectors:
            inj.validate()
            for warning in inj.warnings():
                print("warning: {}: {}".format(inj.name, warning))
    except ChaosUsageError as err:
        print("invalid: {}".format(err))
        return 2
    print(plan.describe())
    return 0


def _schema(_args):
    from .experiment import json_schema
    print(json.dumps(json_schema(), indent=2, sort_keys=True))
    return 0


def _selftest(_args):
    from . import selftest
    return selftest.main()


def _tool(args, rest):
    import importlib
    from .tools import TOOLS
    if args.name not in TOOLS:
        print("unknown tool {!r}; one of: {}".format(args.name, ", ".join(sorted(TOOLS))))
        return 2
    if args.dut:
        os.environ["SONIC_CHAOS_DUT"] = args.dut
    module = importlib.import_module("sonic_chaos.tools." + TOOLS[args.name])
    sys.argv = ["sonic-chaos tool " + args.name] + rest
    return module.main() or 0


def _shim(args):
    from .preload import shim_dir
    if args.action == "build":
        return subprocess.call(["bash", os.path.join(shim_dir(), "build.sh")])
    print(shim_dir())
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(prog="sonic-chaos", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version="sonic-chaos " + __version__)
    sub = ap.add_subparsers(dest="command", metavar="COMMAND")
    sub.add_parser("run", help="run faults against a switch and grade the result", add_help=False)
    p = sub.add_parser("list", help="list injectors, invariants, shipped experiments or transports")
    p.add_argument("what", nargs="?", default="injectors",
                   choices=("injectors", "invariants", "experiments", "transports"))
    p = sub.add_parser("validate", help="check fault specs without touching a switch")
    p.add_argument("specs", nargs="+", metavar="INJECTOR=SPEC")
    sub.add_parser("schema", help="print the experiment file JSON Schema")
    sub.add_parser("selftest", help="the contract self-check; needs no switch")
    p = sub.add_parser("tool", help="harness self-checks against a real switch")
    p.add_argument("name")
    p.add_argument("--dut", help="the switch URL (default: $SONIC_CHAOS_DUT)")
    p = sub.add_parser("shim", help="build the C interposers the sai and spin lanes load")
    p.add_argument("action", nargs="?", default="build", choices=("build", "path"))
    sub.add_parser("console", help="serve the web console (sonic-chaos console --help)", add_help=False)

    if argv and argv[0] == "run":
        return _run(argv[1:])
    if argv and argv[0] == "console":
        from .console import server
        return server.main(argv[1:])
    args, rest = ap.parse_known_args(argv)
    if args.command == "tool":
        return _tool(args, rest)
    if rest:
        ap.error("unrecognized arguments: {}".format(" ".join(rest)))
    handlers = {"list": _list, "validate": _validate, "schema": _schema, "selftest": _selftest,
                "shim": _shim}
    if args.command not in handlers:
        ap.print_help()
        return 2
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
