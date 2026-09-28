"""AC8 planted-shape fixture tree. All 27 code shapes this scanner self-test tree exercises,
seven that were already caught by the baseline scanner and twenty that close gaps in its
coverage - see packaging/tests/ac8-planted/PLANTED.md for the caught/total counts, and
packaging/tests/ac8-planted/run_check.py for the runner that proves every `# SHAPE:` line below
still gets >= 1 finding.

This file is a fixture, never imported and never shipped: it is not under skills/cisco-switch-
config/ and is excluded from build_skill_zip.py's tree by construction (a different skill name,
"testskill", under packaging/tests/, not under the real skills/ root). Each shape's finding fires
on the line tagged `# SHAPE: <n>` - for an import-level denial that is the `import`/`from`
statement itself, not the later line that uses what it imported."""
from __future__ import annotations

import builtins
import codecs
import importlib.util
import io
import sys
import tempfile
from pathlib import Path

import ftplib
import http.client
import multiprocessing                          # SHAPE: 15 multiprocessing.* (import-level)
import os
import runpy                                     # SHAPE: 12 runpy.* (import-level)
import shutil
import smtplib
import socket
import traceback                                 # SHAPE: 10 traceback.* (import-level)
import webbrowser                                # SHAPE: 14 webbrowser.* (import-level)
from urllib import request                       # SHAPE: 11 module root "urllib", not urllib.request

p = "x"
m = "w"                  # a mode decided at runtime, not a literal
kw = {"mode": "w"}       # a **kwargs spread that could smuggle a write mode
myprint = print          # a plain alias, resolved transitively like an import alias

# --- previously caught (7): must remain caught ------------------------------
os.open(p, os.O_WRONLY)                          # os.open, exact
shutil.copy("a", "b")                            # shutil.*, prefix
tempfile.mkstemp()                               # tempfile.*, prefix
socket.socket()                                  # socket (import-level, above)
smtplib.SMTP()                                   # smtplib (import-level, above)
ftplib.FTP()                                      # ftplib (import-level, above)
http.client.HTTPConnection("example.invalid")    # http.client (http import-level, above)

# --- previously missed (20): must be caught by the current scanner ---------
open(p, m)                                       # SHAPE: 1 non-constant open() mode (variable)
open(p, **kw)                                    # SHAPE: 2 open() with **kwargs - mode unverifiable
io.open(p, "w")                                  # SHAPE: 3 io.open, mode at index 1 like builtin open
codecs.open(p, "w")                              # SHAPE: 4 codecs.open, same signature family
sys.__stdout__.write("x")                        # SHAPE: 5 the un-redirected stdout alias
sys.__stderr__.write("x")                        # SHAPE: 6 the un-redirected stderr alias
sys.stdout.writelines(["x"])                     # SHAPE: 7 .writelines, same row as .write
builtins.print("x")                              # SHAPE: 8 the attribute form of print
myprint("x")                                     # SHAPE: 9 a plain reassignment alias of print
traceback.print_exc()                            # (uses the SHAPE 10 import above; no separate finding needed here)
request.urlopen("http://example.invalid")        # (uses the SHAPE 11 import above; no separate finding needed here)
runpy.run_module("os")                           # (uses the SHAPE 12 import above; no separate finding needed here)
importlib.util.spec_from_file_location("x", p)   # SHAPE: 13 importlib.util loader construction
webbrowser.open("http://example.invalid")        # (uses the SHAPE 14 import above; no separate finding needed here)
multiprocessing.Process()                        # (uses the SHAPE 15 import above; no separate finding needed here)
os.startfile(p)                                  # SHAPE: 16 os.startfile (Windows launcher)
os.replace(p, "y")                               # SHAPE: 17 os.replace
os.makedirs(p)                                   # SHAPE: 18 os.makedirs
Path(p).touch()                                  # SHAPE: 19 Path.touch - attribute call on a call result
Path(p).mkdir()                                  # SHAPE: 20 Path.mkdir - attribute call on a call result
