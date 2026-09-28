"""ciscobaseline - the hardened baseline generator of the cisco-switch-config skill.

Standard library only. A JSON spec is validated by `spec.py`, which rejects every
secret-named field; `render.py` turns the validated spec into ordered configuration lines
from the `string.Template` files under `data/baseline/`. Nothing here writes: every byte
leaves through `ciscocheck.report`, called by `gen_baseline.py`. Secret slots are only ever
`<REPLACE-ME:name>` placeholders.
"""
from __future__ import annotations
