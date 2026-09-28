"""Control file for the AC8 planted-shape fixture tree: the safe equivalent of every category in
planted.py. Must always give 0 unsafe-calls findings."""
from __future__ import annotations

import codecs
import io
import json
import os
import re
from pathlib import Path

p = "x"

# Reading, not writing - default mode, explicit "r", and the read-mode io/codecs siblings.
with open(p) as fh:
    fh.read()
with open(p, "r") as fh:
    fh.read()
io.open(p, "r").read()
codecs.open(p, "r", "utf-8").read()

# Path reads, existence checks - never denied.
text = Path(p).read_text()
data = Path(p).read_bytes()
exists = Path(p).exists()
is_dir = Path(p).is_dir()

# Harmless os/re usage that must never collide with a denied bare or attribute name.
joined = os.path.join(p, "y")
value = os.environ.get("HOME")
compiled = re.compile(r"abc")               # bare 'compile' collides only as a builtin Name
parsed = json.loads("{}")

# A resolved alias to a SAFE function must not misfire just because alias resolution exists.
myopen = open
with myopen(p, "r") as fh:
    fh.read()


def system(cmd: str) -> str:
    """A local function that happens to be named 'system' - not the os one."""
    return cmd


system("not os.system, just a local function")
