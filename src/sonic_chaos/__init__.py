"""sonic-chaos: fault injection for a running SONiC switch (formerly hyperSONiC).

You point it at a switch, it breaks something on purpose, and it tells you whether the switch
noticed -- and, just as important, whether the fault ever landed. The distribution and the
command are ``sonic-chaos``; the import is ``sonic_chaos``.

    from sonic_chaos import Chaos, SshDut, fault

    chaos = Chaos(SshDut("10.0.0.5"))
    with chaos.kill("orchagent:how=restart"):
        pass
    chaos.assert_recovers(within=180)

Everything here is imported lazily: ``import sonic_chaos`` pulls in neither pytest nor any
injector until one is used.
"""
__version__ = "0.1.0"

_EXPORTS = {
    "Chaos": "api", "ChaosFinding": "api", "fault": "api", "register_injector": "api", "invariant": "api",
    "Injector": "injector", "ChaosPlan": "injector", "ChaosSession": "injector",
    "ChaosUsageError": "injector",
    "Experiment": "experiment",
    "CommandDut": "transport", "SshDut": "transport", "LocalDut": "transport", "open_dut": "transport",
}

__all__ = [
    "Chaos", "ChaosFinding", "ChaosPlan", "ChaosSession", "ChaosUsageError", "CommandDut", "Experiment",
    "Injector", "LocalDut", "SshDut", "__version__", "fault", "invariant", "open_dut", "register_injector",
]


def __getattr__(name):
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError("module 'sonic_chaos' has no attribute {!r}".format(name))
    import importlib
    if module in ("api", "injector"):
        importlib.import_module("sonic_chaos.injectors")        # registers the built-ins
    return getattr(importlib.import_module("sonic_chaos." + module), name)
