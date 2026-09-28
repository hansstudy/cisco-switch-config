"""Rule implementations. The ONLY module that knows the rule modules.

Importing this package registers every check function with `ciscocheck.registry`. The list
below is explicit and frozen -- never `pkgutil` -- so a build with a missing or broken family
module fails loudly at import time instead of silently shipping an incomplete ruleset.
"""
from __future__ import annotations

from . import mgt, aaa, vty, snmp, log, ntp, ssh, stp, l2, dhcp, ifc, res  # noqa: F401
