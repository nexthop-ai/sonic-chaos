"""Built-in injectors. Importing this package registers them. To add one: new module here, import it below."""
from . import (  # noqa: F401
    cpu, kill, corrupt, sai, spin, pause, redis, mem, syslog, exhaust, storm, hog,
)
