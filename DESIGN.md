# Architecture Review: host_intrusion_detector

*For people reading, extending or reviewing the code: the design decisions and
the order I built things in. For what the tool does and how to run it, see
[README.md](README.md).*

---

## 1. Build order

Same approach as my vuln-scanner project: I didn't want to trust a detector
until I had a way to score it. So I built things in this order:

1. Define one event format that doesn't depend on where the event came from.
2. Write a labeled corpus of malicious/benign **pairs** that share a binary or a
   parent process.
3. Write the scorer (precision/recall/F1) and make it tell "a rule fired"
   apart from "the *right* rule fired."
4. Only then write the six detection rules.
5. Read live Sysmon logs last. See §8.

It uses only the standard library (`dependencies = []` in `pyproject.toml`).
Events are read with `wevtutil`, which ships with Windows, instead of
`pywin32`, so Sysmon is the only thing you need to install.

---

## 2. Module map and data flow

```
   collector.py                         events.py
   ┌─────────────────────────────┐      ┌──────────────────────────┐
   │ read_evtx_via_wevtutil()    │      │ Event dataclass          │
   │   live channel / .evtx      │────► │  EventID-1 fields as     │
   │ load_json_fixture()         │      │  first-class attrs +     │
   │   synthetic test events     │      │  `extra` dict bag        │
   │ load_events(source)-dispatch│      │  image_name / parent_    │
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
                     (separate project; findings re-scored into HIDS format)
```

`events.py` depends on nothing. `collector.py`, `rules.py` and `scorer.py`
depend on `events.py`. No rule imports another rule.

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

Choices I made here:

- **Missing fields are empty strings, never `None`.** Rules can do
  `"powershell" in event.image_name` or `.search(event.command_line)` without
  checking for `None`. A network-connect event just has `image=""`.
- **Process-create fields are real attributes; everything else goes in
  `extra`.** EventID 1 is most of what the rules need. This avoids both one
  huge flat dataclass and passing raw dicts everywhere.
- **`image_name` / `parent_image_name` are computed properties.** Rules compare
  lowercase file names (`winword.exe`), but Sysmon gives full paths with mixed
  casing. Doing the `rsplit("\\", 1)[-1].lower()` in one place means no rule
  can get it slightly wrong.
- **The parent process is part of the event.** Sysmon EventID 1 includes the
  parent's image and command line, so "Word started PowerShell" can be checked
  from one event, with no state kept across events. That's why the rules can be
  stateless (see §5).

---

## 4. Collector ([`hids/collector.py`](hids/collector.py))

`load_events(source)` looks at the string: `.json` goes to the fixture loader,
anything else goes to `wevtutil`.

### 4.1 `wevtutil` path

The collector runs a command like:

```
wevtutil qe Microsoft-Windows-Sysmon/Operational /rd:true /f:xml /c:500
```

| Part | Meaning |
|---|---|
| `qe` | "query events": read events from a log |
| `<channel>` | which log to read, e.g. `Microsoft-Windows-Sysmon/Operational` |
| `/rd:true` | "reverse direction": newest events first |
| `/f:xml` | print each event as XML, which is easy to parse |
| `/c:<N>` | only read N events. Added only when `hids scan --max-events N` is given with N > 0; the default 0 reads the whole log. |
| `/lf:true` | "log file": the source is an exported `.evtx` file, not a live log. Added when the source ends in `.evtx`. |

Notes:

- **`check=True`, then turn failures into friendly errors.**
  `FileNotFoundError` (not on Windows) and `CalledProcessError` (channel missing
  or access denied) are re-raised as `CollectorError` with a hint ("is Sysmon
  installed? try an elevated terminal"), so the CLI prints a sentence instead
  of a traceback.
- **Splitting the XML by hand.** `wevtutil` prints bare `<Event>…</Event>`
  blocks with no root element, so the code splits on `</Event>` and adds it
  back to each chunk.
- **One bad event doesn't stop the scan.** `_MALFORMED_EVENT_ERRORS` groups
  `ET.ParseError, AttributeError, KeyError, ValueError` (a missing node, a
  missing attribute, a bad int). A corrupt event is skipped and the scan
  continues.
- **`_parse_systemtime`.** Sysmon writes 9-digit (nanosecond) fractional
  seconds and a `Z`, but `datetime.fromisoformat` on Python 3.10 only accepts 3
  or 6 digits. The regex cuts the fraction to 6 digits and replaces `Z` with
  `+00:00`.

### 4.2 Fixture path

`load_json_fixture` accepts two row formats: a flat dict matching `Event`'s
fields, or `{"raw": {...}}` with Sysmon-style keys (`ProcessGuid`,
`CommandLine`, `EventID`, `TimeCreated`), the same keys `_parse_event_xml`
pulls out. The benchmark corpus uses the `raw` format so the fixtures look like
real Sysmon data.

---

## 5. Rules ([`hids/rules.py`](hids/rules.py))

Each rule is `(Event) -> Finding | None`. `ALL_RULES` is a list, and
`evaluate()` runs all of them and keeps the non-`None` results. To add a rule,
write the function and append it to `ALL_RULES`.

```python
@dataclass
class Finding:
    rule_id: str
    severity: int          # 3 / 6 / 8 / 10, coarse so scores can be summed
    technique: str          # MITRE ATT&CK ID, e.g. "T1059.001"
    description: str
    event: Event
```

**Why severity is a coarse 1–10 integer:** the scorer adds up severities for
each process (§6). That only makes sense if every rule uses the same scale, so
rules pick from four fixed values instead of inventing their own.

**Why MITRE technique IDs:** same reason the vuln scanner uses CWE IDs. A
finding points to a public standard instead of a label I made up.

**The rules are narrow on purpose.** Each one checks a second condition, not
just a keyword:

| Rule | Condition (more than a keyword) |
|---|---|
| `ENCODED_POWERSHELL` | image is powershell/pwsh **and** command line has one of the PowerShell flags below |
| `OFFICE_SPAWNED_SHELL` | parent in Office set **and child in the shell/script set** (Word starts `splwow64.exe` all the time, and that isn't a shell) |
| `BROWSER_SPAWNED_SHELL` | parent in browser set **and** child in the shell/script set (not one of the browser's own helper processes) |
| `LOLBIN_DOWNLOAD` | image in LOLBin set **and** command line has a download indicator (URL / `-urlcache` / `DownloadString`), not every `certutil` call |
| `SCHEDULED_TASK_CREATED` | EventID 4698, **or** EventID 1 with `schtasks.exe` **and** `/create` (not `/query`) |
| `EXEC_FROM_TEMP` | image path under `\AppData\Local\Temp\` / `\Windows\Temp\` / `\Downloads\` |

The sets and patterns the rules use (all matched case-insensitively against
the lowercase file name or the command line):

| Set | Members | Used by |
|---|---|---|
| Office set (`_OFFICE_PARENTS`) | `winword.exe` (Word), `excel.exe`, `powerpnt.exe` (PowerPoint), `outlook.exe`, `mspub.exe` (Publisher), `acrord32.exe` (Adobe Reader), `acrobat.exe` | `OFFICE_SPAWNED_SHELL` |
| Browser set (`_BROWSER_PARENTS`) | `chrome.exe`, `msedge.exe`, `firefox.exe` | `BROWSER_SPAWNED_SHELL` |
| Shell/script set (`_SUSPICIOUS_CHILDREN`) | shells: `powershell.exe`, `pwsh.exe`, `cmd.exe`; script hosts: `wscript.exe`, `cscript.exe`; LOLBins: `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe` | `OFFICE_SPAWNED_SHELL`, `BROWSER_SPAWNED_SHELL` |
| LOLBin set (`_LOLBINS`) | `certutil.exe`, `mshta.exe`, `regsvr32.exe`, `rundll32.exe`, `bitsadmin.exe` | `LOLBIN_DOWNLOAD` |
| PowerShell flags (`_ENCODED_PS_PATTERN`) | `-enc` / `-encodedcommand`; `-e` followed by a Base64 string of 20+ characters; `-noni` (non-interactive); `-nop` (no profile); `-w hidden` / `-windowstyle hidden`; `-bypass` (execution policy) | `ENCODED_POWERSHELL` |
| Download indicators (`_DOWNLOAD_INDICATORS`) | `http://`, `https://`, `-urlcache`, `bitstransfer`, `downloadstring`, `downloadfile` | `LOLBIN_DOWNLOAD` |
| Temp/download paths (`_SUSPICIOUS_PATHS`) | `\AppData\Local\Temp\`, `\Windows\Temp\`, `\Downloads\` | `EXEC_FROM_TEMP` |

The shell/script set includes four LOLBins as well as real shells, because
Word or a browser starting `mshta` or `regsvr32` is just as suspicious as
starting `cmd.exe`. `ENCODED_POWERSHELL` matches any image name containing
`powershell` or `pwsh`, and `SCHEDULED_TASK_CREATED` needs the image to be
`schtasks.exe` with `/create` in the command line.

The benchmark corpus catches a rule that skips its second condition: every
malicious case has a benign twin with the same binary (`certutil -urlcache`
vs. `certutil -verify`) or the same parent (`WINWORD → powershell` vs.
`WINWORD → splwow64`).

---

## 6. Scorer ([`hids/scorer.py`](hids/scorer.py))

It does two separate things.

### 6.1 `score_events`: scan output

Groups findings by `process_guid` into a `ProcessRisk`, whose `score` is the
sum of its findings' severities. If an event has no GUID (e.g. a 4698
scheduled-task event), it uses `image:pid` as the key instead. Results are
sorted highest score first, so `hids scan` shows the worst process at the top.

Why add them up: a process that trips three rules is more worrying than one
that trips a single higher-severity rule, and an analyst wants to know which
process to look at first.

### 6.2 `benchmark`: scoring the rules

`load_labeled_fixture` turns each fixture row into a tuple
`(event, is_malicious, expected_rule)`. It reads the same JSON file twice:

1. **As raw JSON** (`payload`). This keeps the labels: `label` and
   `expected_rule`.
2. **Through `load_json_fixture`** (`events`). This builds the `Event`
   objects the rules actually run on. `Event` has no label field, so the
   labels are lost here.

Then it pairs them up with `zip(events, payload)`: event 1 with row 1, event 2
with row 2, and so on. That only works if both lists have the same length and
the same order.

Today `load_json_fixture` makes exactly one event per row, so they always
match. But suppose a later change made it skip a row, for example a row with a
bad timestamp. Then `events` would have 15 items and `payload` 16, and two
things would go wrong without any error:

- **Labels shift.** Every event after the skipped row gets the label of the
  row before it. A benign event could be scored as malicious, and the other
  way round.
- **The last row drops off.** `zip` stops at the shorter list, so one case
  is never scored.

The benchmark would still print a score, but the score would be wrong. So
before zipping, the function checks `len(events) == len(payload)` and raises
a `ValueError` if they differ (e.g. "fixture has 16 rows but produced 15
events"). `test_scorer.py` covers this by faking a `load_json_fixture` that
returns no events and checking that the error is raised.

`BenchmarkResult`:

- **TP** = labeled malicious **and** at least one rule fired
- **FN** = malicious and nothing fired
- **FP** = labeled benign but a rule fired
- **`wrong_rule`** = malicious, a rule fired, but not the `expected_rule` named
  in the fixture. It still counts as a TP but is tallied separately. The CLI
  prints a warning when `wrong_rule > 0`.

Why `wrong_rule` exists: one event can trip several rules. A macro-dropper
case written as `WINWORD.EXE → powershell.exe -EncodedCommand ...` would fire
both `OFFICE_SPAWNED_SHELL` (the rule it's meant to test) and
`ENCODED_POWERSHELL`. If `OFFICE_SPAWNED_SHELL` were broken by accident,
`ENCODED_POWERSHELL` would still fire, the case would still count as caught,
and the score would stay 1.00/1.00, hiding the bug. Checking `expected_rule` catches that. Other rules
firing alongside the expected one is fine; the check only fails when the
expected rule isn't among them.

Precision, recall and F1 are properties that handle a zero denominator.

Current corpus: 16 cases (8 pairs), scoring 1.00/1.00/1.00. As the README
says, that shows the rules work as designed, not that they're accurate on
data they haven't seen.

---

## 7. The credential-auditor bridge ([`hids/credaudit_bridge.py`](hids/credaudit_bridge.py))

`hids audit-credentials` covers different risks (browser extensions, plaintext
secrets, browser settings). Instead of rewriting that, the bridge:

1. Calls `shutil.which("credaudit")` and raises `CredauditNotFound` with an
   install hint if it's missing. It's a separate package, not a dependency.
2. Runs `subprocess.run(["credaudit", "--json", ...])` with a 120 s timeout,
   **without `check=True`**: credaudit exits 1 when it finds HIGH/CRITICAL
   issues, which is a result, not an error.
3. Parses `findings[]` into `CredentialFinding`s, scored with
   `_SEVERITY_TO_SCORE = {LOW:3, MEDIUM:6, HIGH:8, CRITICAL:10}`. That's the
   **same 3/6/8/10 scale** the Sysmon rules use, so both kinds of finding can
   be compared directly.

The two projects are connected only through the CLI's `--json` output, not a
Python import, so either one can change without breaking the other.

---

## 8. Live collection

`read_evtx_via_wevtutil` was written and unit-tested against captured sample
output first. Installing Sysmon needs admin rights and changes system-wide
logging, so I did that by hand (see README "Installing Sysmon") and only then
pointed the tool at real logs.

The fixture path and the `wevtutil` path both produce the same `list[Event]`,
so the rules and scorer were already tested on realistic data before any real
log was read. In November 2026 I ran `hids scan` on five days of my
workstation's Sysmon log and tuned the allowlist from what fired (see
[DETAIL.md › Real-world scan](DETAIL.md#real-world-scan-november-2026)).

---

## 9. Testing

`pytest`, standard library only, CI on Linux and Windows with Python
3.10/3.12/3.13, plus `hids benchmark` as its own CI step.

| File | What it tests |
|---|---|
| `test_rules.py` | one malicious and one benign event per rule; the benign twin must *not* fire |
| `test_scorer.py` | regression test on the full labeled corpus (locks P/R/F1 and `wrong_rule`) |
| `test_collector.py` | `_parse_event_xml` / `_parse_systemtime` / `wevtutil` error paths on captured sample XML, `subprocess` mocked |
| `test_allowlist.py` | entries suppress only exact matches (full-match regex); `pwsh.exe` is trusted only from its install folders; per-entry suppression counts |
| `test_cli.py` | subcommand exit codes and output |
| `test_credaudit_bridge.py` | credaudit's output is faked (`subprocess`/`which` mocked), so credaudit doesn't need to be installed; checks findings are parsed correctly and `CredauditNotFound` is raised when it's missing |

The parts that always behave the same (XML parsing, scoring, severity math,
dispatch) are tested heavily. The one part that's hard to fake, a live Sysmon
install, sits behind the collector so nothing else depends on it.

---

## 10. Extension points

- **New rule:** write `(Event) -> Finding | None`, append it to `ALL_RULES`,
  and add a malicious/benign pair with an `expected_rule` to
  `tests/fixtures/labeled_events.json`.
- **New event source:** a function returning `Iterable[Event]`, added to the
  dispatch in `load_events`.
- **New Sysmon EventID:** add a branch in `_parse_event_xml` (or use the
  generic `extra=data` fallback) and read fields from `event.extra` in the rule.
- **Correlation across events** (roadmap): rules see one event at a time now. A
  correlation step would go between `load_events` and `evaluate`, either
  producing combined events or keeping a time window of recent ones. The
  `Finding` format wouldn't need to change.
- **Optional LLM pass** (roadmap): like the vuln scanner's comparison, an LLM
  that reads a process's full command line and parent chain, scored with the
  *same* `benchmark()` on the *same* corpus.

---

## 11. Known limitations

- No state across events, so a "created a scheduled task *and* came from Temp
  within N seconds" chain can't be seen; each rule sees one event.
- The corpus is 16 cases I wrote myself. 1.00/1.00 means the rules do what I
  designed them to do, not that they're accurate in the wild.
- `LOLBIN_DOWNLOAD` matches download indicators as plain text (URL, `-urlcache`,
  `DownloadString`, ...). A LOLBin pulling a file from a network share
  (`\\server\share\...`) or running a script that's already on disk has no
  indicator and isn't caught. The rule also only checks the five LOLBins, so
  `Start-BitsTransfer` typed straight into PowerShell is out of its scope.
- The real-log scan covers five days on one machine, with no attacks in it, so
  it tests false positives but says nothing about recall.
- Splitting `wevtutil` output on the literal string `</Event>` assumes that
  string never shows up inside event data. That's true for Sysmon EventID 1 but
  could break if unusual event types are added.
