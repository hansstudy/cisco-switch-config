"""ciscocheck - the audit engine of the cisco-switch-config skill.

Standard library only. `mask.py` is the only module that inspects raw configuration
content; every other module sees masked text. `report.py` is the only module that writes.
"""
from __future__ import annotations

__version__ = "1.0.0"
SKILL_VERSION = __version__
