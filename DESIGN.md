# Architecture Review — host_intrusion_detector

*For people reading, extending, or reviewing the code: the design decisions and
the order things were built. For what the tool does and how to run it, see
[README.md](README.md).*

---

## 1. The governing idea

Same as the companion vuln-scanner project: **a detector is only as good as the
proof that it works.** So the build order was:

1. Define a normalized event shape that hides where the event came from.
2. Write a labeled corpus of malicious/benign **pairs** that share a binary or a
   parent process.
3. Write the scorer (precision/recall/F1) and make it distinguish "a rule fired"
   from "the *right* rule fired."
4. Only then write the six detection rules.
5. Live Sysmon collection is code-complete but intentionally *not* the trusted
   path yet — see §8.

Everything is stdlib. `pyproject.toml` `dependencies = []`. Event reading goes
through `wevtutil` (built into Windows), not `pywin32`, so the only external
requirement is Sysmon itself.

---

## 2. Module map and data flow

```
   collector.py                         events.py
   ┌─────────────────────────────┐      ┌──────────────────────────┐
   │ read_evtx_via_wevtutil()    │      │ Event dataclass          │
   │   live channel / .evtx      │────► │  EventID-1 fields as     │
   │ load_json_fixture()         │      │  first-class attrs +     │
   │   synthetic test events     │      │  `extra` dict bag        │
   │ load_events(source)  ──dispatch    │  image_name / parent_    │
   └─────────────────────────────┘      │  image_name helpers      │
                 │                      └──────────────────────────┘
                 ▼
            list[Event]
                 │
                 ▼
   rules.py:  evaluate(event) -> list[Finding]
     6 rules, each (Event) -> Finding | None
                 │
                 ▼
   scorer.py:
     score_events()   findings grouped by process_guid -> ProcessRisk(score = Σ severity)
     benchmark()      labeled rows -> BenchmarkResult(tp/fp/fn/wrong_rule -> P/R/F1)
                 │
                 ▼
   cli.py:  scan / benchmark / audit-credentials
                                   │
                                   ▼
                     credaudit_bridge.py  ──subprocess──►  `credaudit --json`
                     (companion project; findings re-scored into HIDS format)
```

Dependency direction: `events.py` depends on nothing. `collector.py`, `rules.py`,
`scorer.py` depend on `events.py`. No rule imports another rule.

---

## 3. The `Event` model ([`hids/events.py`](hids/events.py))

```python
@dataclass
class Event:
    event_id: int
    timestamp: datetime
    computer: str
    # EventID-1 (process create) fields, defaulted to "" not None:
    process_guid / process_id / image / command_line
    parent_process_guid / parent_process_id / parent_image / parent_command_line
    user
    extra: dict          # everything else (TaskName for 4698, DestinationIp for 3, ...)

    image_name / parent_image_name   # -> "powershell.exe", lowercased basename
```

Decisions that matter:

- **Empty string, never `None`, for absent fields.** Rules do plain
  `"powershell" in event.image_name` and regex `.search(event.command_line)`
  with no `None`-guard anywhere. A network-connect event just has `image=""`.
- **Process-creation fields are promoted to real attributes** because EventID 1
  is 90% of what matters; everything else goes in `extra`. This avoids both a
  giant flat dataclass and a everything-is-a-dict soup.
- **`image_name` / `parent_image_name` are computed properties.** Rules compare
  against lowercase basenames (`winword.exe`), and Sysmon gives full paths with
  inconsistent casing. Centralizing the `rsplit("\\", 1)[-1].lower()` keeps
  every rule honest.
- **The parent/child relationship is *in the event*.** Sysmon EventID 1 carries
  the parent's image and command line inline, so "Word spawned PowerShell" is a
  single-event check — no cross-event state machine needed. This is why the rule
  engine can be stateless (see §5).

---

## 4. Collector ([`hids/collector.py`](hids/collector.py))

`load_events(source)` dispatches on the string: `.json` → fixture loader,
anything else → `wevtutil`.

### 4.1 `wevtutil` path

`wevtutil qe <channel> /c:500 /rd:true /f:xml` (+ `/lf:true` when the source ends
`.evtx`). Design points:

- **`check=True`, then translate failures.** `FileNotFoundError` (not on Windows)
  and `CalledProcessError` (channel missing / access denied) are both re-raised
  as `CollectorError` with a *hint* ("is Sysmon installed? try an elevated
  terminal"), so the CLI prints a sentence instead of a traceback.
- **Manual XML splitting.** `wevtutil` emits bare `<Event>…</Event>` blocks with
  no root element and no separators, so the code splits on `</Event>` and
  re-appends it per chunk.
- **Per-chunk error tolerance.** `_MALFORMED_EVENT_ERRORS` bundles
  `ET.ParseError, AttributeError, KeyError, ValueError` — a missing node, a
  missing attribute, a bad int. One corrupt event is skipped; the scan
  continues.
- **`_parse_systemtime`.** Sysmon writes 9-digit (nanosecond) fractional
  seconds + `Z`; `datetime.fromisoformat` on 3.10 accepts only 3 or 6 digits.
  The regex truncates the fraction to 6 and swaps `Z`→`+00:00`.

### 4.2 Fixture path

`load_json_fixture` accepts two row shapes: a flat dict matching `Event`'s
fields, or `{"raw": {...}}` with Sysmon-style keys (`ProcessGuid`, `CommandLine`,
`EventID`, `TimeCreated`) — the same keys `_parse_event_xml` extracts. The `raw`
shape lets fixtures read like real Sysmon data, which is what the benchmark
corpus uses.

---

## 5. Rules ([`hids/rules.py`](hids/rules.py))

Each rule is `(Event) -> Finding | None`. `ALL_RULES` is a list; `evaluate()`
runs all of them and collects the non-`None` results. Adding a rule is: write the
function, append it to `ALL_RULES`.

```python
@dataclass
class Finding:
    rule_id: str
    severity: int          # 3 / 6 / 8 / 10 — coarse, so scores can be summed
    technique: str          # MITRE ATT&CK ID, e.g. "T1059.001"
    description: str
    event: Event
```

**Why severity is an int on a 1–10 scale, kept coarse:** the scorer sums
severities across a process (§6). Summing only makes sense if the scale is
consistent and there aren't 40 distinct values, so rules pick from four
constants.

**Why MITRE technique IDs:** same reason the vuln scanner tags CWE — a finding
can be checked against a named external standard instead of an ad-hoc label.

**The rules are deliberately narrow.** This is the core design claim, and each
rule encodes it:

| Rule | Narrowing condition — *not* just a keyword |
|---|---|
| `ENCODED_POWERSHELL` | image is powershell/pwsh **and** command line matches `-enc` / `-nop` / `-w hidden` / base64 blob |
| `OFFICE_SPAWNED_SHELL` | parent in Office set **and child in the shell/script set** (Word spawns `splwow64.exe` constantly — that's not a child shell) |
| `BROWSER_SPAWNED_SHELL` | parent in browser set **and** child in shell set (not a browser's own renderer helper) |
| `LOLBIN_DOWNLOAD` | image in LOLBin set **and** command line has a download indicator (URL / `-urlcache` / `DownloadString`) — not every `certutil` call |
| `SCHEDULED_TASK_CREATED` | EventID 4698, **or** EventID 1 with `schtasks.exe` **and** `/create` (not `/query`) |
| `EXEC_FROM_TEMP` | image path under `\AppData\Local\Temp\` / `\Windows\Temp\` / `\Downloads\` |

The benchmark corpus is built to punish a rule that skips the narrowing
condition: every malicious case has a benign twin using the same binary
(`certutil -urlcache` vs `certutil -verify`) or the same parent
(`WINWORD → powershell` vs `WINWORD → splwow64`).

---

## 6. Scorer ([`hids/scorer.py`](hids/scorer.py))

Two separate jobs:

### 6.1 `score_events` — operational output

Groups findings by `process_guid` into `ProcessRisk`, whose `score` is the sum of
finding severities. Falls back to `image:pid` as the key when the event has no
GUID (e.g. a 4698 scheduled-task event). Results are sorted highest-score-first,
so `hids scan` shows the worst process at the top.

Rationale for summing: a process that trips *three* rules is worse than one that
trips a single higher-severity rule, and analysts triage by "which process
should I look at first."

### 6.2 `benchmark` — grading the rule set

`load_labeled_fixture` parses rows into `(event, is_malicious, expected_rule)`.
It **asserts `len(events) == len(payload)`** — `load_json_fixture` must yield
exactly one event per row, and a silent `zip` truncation would corrupt every
label alignment, so a divergence raises instead.

`BenchmarkResult`:

- **TP** = labeled malicious **and** ≥ 1 rule fired
- **FN** = malicious and nothing fired
- **FP** = labeled benign but a rule fired
- **`wrong_rule`** = malicious, a rule fired, but not the `expected_rule` the
  fixture named. Still counts as a TP, but tallied separately so
  *"something fired"* and *"the intended rule fired"* are never conflated. The
  CLI prints a warning when `wrong_rule > 0`.

precision/recall/F1 are properties with zero-denominator guards.

Current corpus: 16 cases (8 pairs), scoring 1.00/1.00/1.00 — which the README is
explicit is a *sanity check that the rules work as designed*, not evidence of
production accuracy on unseen data.

---

## 7. The credential-auditor bridge ([`hids/credaudit_bridge.py`](hids/credaudit_bridge.py))

`hids audit-credentials` covers a different attack surface (browser extensions,
plaintext secrets, browser settings). Rather than reimplement it, the bridge:

1. `shutil.which("credaudit")` → raise `CredauditNotFound` with an install hint
   if absent. It's a *separate* installable package, not a dependency.
2. `subprocess.run(["credaudit", "--json", ...])`, 120 s timeout. **No
   `check=True`** — credaudit exits 1 when it finds HIGH/CRITICAL issues, which
   is a signal, not a failure.
3. Parse `findings[]`, map each into a `CredentialFinding` whose `score` comes
   from `_SEVERITY_TO_SCORE = {LOW:3, MEDIUM:6, HIGH:8, CRITICAL:10}` — the
   **same 3/6/8/10 scale** the Sysmon rules use, so both surfaces report in one
   currency.

The coupling is a CLI contract (`--json` output shape), not a Python import, so
the two projects version independently.

---

## 8. Why live collection isn't the trusted path yet

`read_evtx_via_wevtutil` is written and its XML parsing + error handling are unit
tested against captured sample output. But Sysmon needs an elevated installer and
a system-wide logging config change, done manually rather than by an agent (see
README "Installing Sysmon"). So the honest status is: **"tested against synthetic
input" ≠ "run against real logs."** The next real milestone is running `hids
scan` against several days of this machine's actual Sysmon channel and tuning
rules against whatever false-positives ordinary daily use produces.

This is a deliberate architectural boundary: the fixture path and the `wevtutil`
path produce the *same* `list[Event]`, so the rules and scorer are already
exercised on realistic data shapes; only the final "read real logs" hop is
unproven.

---

## 9. Testing strategy

`pytest`, stdlib only, CI on Linux + Windows × Python 3.10/3.12/3.13, plus
`hids benchmark` run as its own CI step.

| File | Approach |
|---|---|
| `test_rules.py` | one malicious + one benign event per rule; the benign twin must *not* fire |
| `test_scorer.py` | regression test over the full labeled corpus (locks P/R/F1 and `wrong_rule`) |
| `test_collector.py` | `_parse_event_xml` / `_parse_systemtime` / `wevtutil` error paths against captured sample XML, `subprocess` mocked |
| `test_cli.py` | subcommand exit codes and output |
| `test_credaudit_bridge.py` | bridge parsing + `CredauditNotFound` with `subprocess`/`which` mocked |

Pattern: the deterministic seams (XML parsing, scoring, severity math, dispatch)
are tested hard; the one thing that can't be faked cheaply (a live Sysmon
install) is quarantined behind the collector interface.

---

## 10. Extension points

- **New rule:** `(Event) -> Finding | None`, append to `ALL_RULES`, add a
  malicious/benign pair to `tests/fixtures/labeled_events.json` with an
  `expected_rule`.
- **New event source:** a function returning `Iterable[Event]`; wire it into
  `load_events`'s dispatch.
- **New Sysmon EventID:** add a branch in `_parse_event_xml` (or rely on the
  generic `extra=data` fallthrough) and read fields from `event.extra` in the
  rule.
- **Stateful correlation** (roadmap): rules currently see one event at a time. A
  correlation layer would sit between `load_events` and `evaluate`, emitting
  synthetic "composite" events or feeding a windowed buffer — the `Finding`
  contract wouldn't change.
- **Optional LLM pass** (roadmap): mirror the vuln-scanner's two-detector
  comparison — an LLM reasoning over a process's full command line + ancestry,
  graded against the *same* `benchmark()` on the *same* corpus.

---

## 11. Known limitations

- No cross-event state — a "created a scheduled task *and* came from Temp within
  N seconds" chain is invisible; each rule sees one event.
- The corpus is 16 self-authored cases. 1.00/1.00 means "designed correctly,"
  not "accurate in the wild."
- Live Sysmon read is unproven on a real install (§8).
- `wevtutil` XML splitting on the literal string `</Event>` assumes that string
  never appears inside event data — true for Sysmon EventID 1, but a fragile
  assumption if exotic event types are added.
