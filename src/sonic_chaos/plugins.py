"""Third-party injectors and invariants, found through entry points.

A package adds a fault or a check without forking sonic-chaos:

    [project.entry-points."sonic_chaos.injectors"]
    netem = "my_faults.netem:Netem"            # an Injector subclass, or a module that registers some

    [project.entry-points."sonic_chaos.invariants"]
    zebra_memory = "my_checks.memory"          # a module whose @invariant functions register on import

Loaded once, lazily: the first time an unknown injector or invariant name is looked up, and
whenever the catalogue is listed. A plugin that fails to import is logged and skipped, so one
broken package cannot take the built-ins down with it.
"""
import logging
from importlib import metadata

logger = logging.getLogger(__name__)

GROUPS = ("sonic_chaos.injectors", "sonic_chaos.invariants")
_loaded = [False]


def load_entry_points():
    if _loaded[0]:
        return
    _loaded[0] = True
    from .injector import REGISTRY, Injector, register
    for group in GROUPS:
        for ep in metadata.entry_points(group=group):
            try:
                obj = ep.load()
            except Exception as err:
                logger.warning("[chaos] could not load %s plugin %s (%s): %r", group, ep.name, ep.value, err)
                continue
            if isinstance(obj, type) and issubclass(obj, Injector) and obj.name and obj.name not in REGISTRY:
                register(obj)
