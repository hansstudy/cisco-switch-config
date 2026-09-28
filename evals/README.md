# Evals — cisco-switch-config

Ten cases: six positive, four negative. Every case grants only
`["Read", "Glob", "Grep", "Skill"]` — **no case grants `Bash`**, because native Windows has no
sandbox backend and a `Bash`-granting case is refused there.

Prompts that embed configuration text use the same synthetic canary vocabulary as the test fixtures
(`CANARY-COMMUNITY-01`, `CANARY-TACACS-KEY-01`, ...), never a real-looking secret.
`.gitleaks.toml` and `.github/secret_scanning.yml` exclude this directory for exactly that
reason — see `docs/threat-model.md`.

## Running the suite

```
claude plugin eval . --ablation with-without --threshold 0.8 \
    --trust-plugin --no-publish \
    --model claude-sonnet-5 \
    --judge-model claude-opus-5 \
    --json dist/eval.json
```

The target (`.`) comes **first** — a target given after `--json` is read as the output path, not
the plugin to evaluate. `--trust-plugin` is mandatory: under `--json` the interactive trust prompt
cannot be asked, and the run is refused with exit 1 without it. `--no-publish` is mandatory: the
HTML report is otherwise published to a claude.ai URL by default, which for an artifact whose
prompts embed fixture configuration text is unreviewed egress (see `docs/threat-model.md`).
Prerequisite: Claude Code v2.1.269 or later — an "early access" message means a stale build;
run `claude update`.

**`claude-sonnet-5` and `claude-opus-5` are current-generation aliases, not dated pins.** An alias
cannot deliver the "a model rollout is not mistaken for a plugin regression" property a dated
snapshot gives. The control here is *recording*, not *pinning*: after every run, copy
`claudeVersion` and the resolved model ids out of `dist/eval.json` into the run record below, so a
delta shift can be attributed after the fact. If the installed build rejects either alias,
substitute the current-generation alias it offers instead and record why — that is a deviation to
note, not a FAIL. Do not reintroduce a dated id; `claude-opus-4-1-20250805` was retired on
2026-08-05.

## Run record

| Date | `claudeVersion` | Resolved model | Resolved judge model | Result (`--threshold 0.8`) | Notes |
|---|---|---|---|---|---|
| _(none yet — this suite has not been run against a live Claude Code build from this environment)_ | | | | | |

## What the ten cases measure, and what they do not

Every positive case's *indicator* grader is `tool_used` on `Skill` with `input_match` matching
`cisco-switch-config` — unscored by design in a two-arm run, because it only shows the plugin
fired, not that it helped. The *scored* grader is either a `regex` over `last_message` for the
catalogue check-id pattern `CSC-[A-Z]{2,5}-\d{4}` (which the no-plugin arm has no catalogue to
produce), a `regex` for this skill's own `<REPLACE-ME:` placeholder vocabulary, or an `llm` rubric
for the two cases (`generate-explicit`, `explain-oblique`) that cannot naturally emit a check id.
Every negative case is scored `tool_used` on `Skill`, `min: 0, max: 0`, `arm: both`.

**These cases measure that the skill triggers and that its catalogue vocabulary reaches the
answer.** They do **not** measure that the engine actually ran — no case grants `Bash`, by the
native-Windows sandbox constraint stated above. Execution correctness is covered by the test
suite (`tests/test_corpus.py`, `tests/test_baseline.py`, `tests/test_runtime_invariant.py`), not
by this eval suite.

## Cases

| Case | Kind | Phrasing class | Capability |
|---|---|---|---|
| `audit-explicit` | positive | explicit | audit |
| `audit-oblique` | positive | oblique | audit |
| `audit-artefact` | positive | artefact-led | audit |
| `generate-explicit` | positive | explicit | generate |
| `explain-oblique` | positive | oblique | explain |
| `diff-artefact` | positive | artefact-led | diff |
| `neg-juniper` | negative | — | — |
| `neg-windows-fw` | negative | — | — |
| `neg-asa` | negative | — | — |
| `neg-coding` | negative | — | — |
