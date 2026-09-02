# host_intrusion_detector

A lightweight host intrusion detection tool that reads Sysmon-instrumented
Windows Event Log data and flags suspicious behavior: encoded/obfuscated
PowerShell, Office/browser processes spawning shells (the classic
macro-dropper and drive-by-download chains), living-off-the-land binaries
(certutil, mshta, rundll32, ...) used to fetch remote payloads, new
scheduled tasks (a common persistence mechanism), and processes executing
from temp/download paths.

Like the companion [LLM_Vulnerability_Scanner](../LLM_Vulnerability_Scanner)
project, this isn't just a detector - it's a detector plus proof that the
detector works: a hand-labeled corpus of malicious and deliberately
similar-looking benign event pairs, graded with precision/recall/F1, so
"it catches bad stuff" is a checked claim, not an assertion.

## Status (2026-09-01)

Rule engine, scorer, and labeled benchmark corpus are done and passing - run
`python -m pytest -q` and `hids benchmark` for the current numbers (see
[Current results](#current-results) for a recent run). Live Sysmon collection
is code-complete (`hids scan` against the live `Microsoft-Windows-Sysmon/Operational`
channel via `wevtutil`) but **not yet run against a live Sysmon install** -
Sysmon requires an elevated installer and a system-wide logging config
change, which I'm doing manually rather than having an agent do it (see
[Installing Sysmon](#installing-sysmon)). The XML parser and `wevtutil`
error handling for that path are unit-tested against captured sample output,
but "tested against synthetic input" is not "run against real logs".

## Why this project exists

"AI/rules-based detection" claims in security tooling are almost always
unverifiable - a tool that flags something and a person nodding along.
The differentiator here is the same one as the vuln-scanner project: don't
just write detection logic, write the answer key first (a labeled set of
malicious-vs-benign-but-similar event pairs - e.g. `certutil -urlcache`
downloading a payload vs. `certutil -verify` checking a certificate, both
using the same binary), then grade the detector against it honestly. That
turns "I built an IDS" into "I built an IDS, and here's the precision/recall
on cases specifically chosen to be hard for it."

### Why endpoint telemetry, specifically

Network-layer security tooling (packet capture, firewall rules) is the
common freshman security project. Endpoint telemetry - what Sysmon actually
sees on a single host: full command lines, parent/child process trees,
image hashes - is what SOC/blue-team analysts spend most of their day
reading, and it's a different skill: understanding *normal* Windows process
behavior well enough to write a rule that doesn't false-positive on it. The
benchmark corpus below is built specifically around that - each malicious
case is paired with a benign case that shares the same binary or parent
process, so a rule that just pattern-matches "certutil.exe" or
"WINWORD.EXE spawned something" without checking the specific behavior
would fail the benchmark, not just look naively accurate.

## Architecture

```
hids/
  events.py      Normalized Event dataclass (Sysmon EventID 1 process-
                  create fields + a generic "extra" bag for other IDs)
  collector.py    Reads events from: a live Sysmon channel, an exported
                  .evtx file (both via wevtutil, no extra install), or a
                  JSON fixture (for tests/demos without Sysmon installed)
  rules.py        6 detection rules, each event-id-typed, each returning
                  a Finding with a severity and a MITRE ATT&CK technique ID
  scorer.py       Groups findings by process into a risk score; grades
                  the rule set against a labeled fixture (precision/recall/F1)
  credaudit_bridge.py  Shells out to the companion credential-auditor
                  project's `credaudit --json` and adapts its findings
                  into HIDS's own risk-score format
  cli.py          `hids scan <source>`, `hids benchmark [<fixture>]`,
                  and `hids audit-credentials`
tests/
  test_rules.py           unit tests, one malicious/benign pair per rule
  test_scorer.py          benchmark-corpus regression test
  test_collector.py       XML parsing + wevtutil error handling (sample output)
  test_cli.py             subcommand exit codes and output
  test_credaudit_bridge.py  bridge unit tests (subprocess mocked)
  fixtures/labeled_events.json   16 hand-labeled synthetic Sysmon events
                                  (8 malicious/benign pairs; malicious rows
                                  also name the rule expected to fire)
```

### Credential-hygiene audit

`hids audit-credentials` covers a different attack surface than the Sysmon rules
above: over-permissioned browser extensions, plaintext secrets in local config files,
and risky browser settings. Rather than duplicating that logic, it delegates to the
companion [`credential-auditor`](../credential_auditor) project's CLI and re-reports
its findings in HIDS's own risk-score format, so one periodic check can cover both
process-level and credential-hygiene risks. Requires `credaudit` to be installed
(`pip install -e .` in `../credential_auditor`) and on PATH.

### Detection rules

| Rule | Sysmon/Security Event | MITRE ATT&CK | Severity |
|---|---|---|---|
| `ENCODED_POWERSHELL` | ID 1 (process create) | T1059.001 | High |
| `OFFICE_SPAWNED_SHELL` | ID 1 | T1566.001 | Critical |
| `BROWSER_SPAWNED_SHELL` | ID 1 | T1189 | High |
| `SCHEDULED_TASK_CREATED` | ID 4698, or `schtasks /create` via ID 1 | T1053.005 | Medium |
| `LOLBIN_DOWNLOAD` | ID 1 (certutil/mshta/rundll32/regsvr32/bitsadmin) | T1105 | High |
| `EXEC_FROM_TEMP` | ID 1 | T1204 | Low |

Each rule is intentionally narrow rather than a broad keyword match - e.g.
`OFFICE_SPAWNED_SHELL` only fires when the *child* is a shell/scripting
engine, not any child process (Word legitimately spawns `splwow64.exe` for
printing constantly); `LOLBIN_DOWNLOAD` only fires when the command line
also contains a download indicator (URL, `-urlcache`, `DownloadString`),
not on every certutil invocation.

## Current results

Run `hids benchmark` (uses `tests/fixtures/labeled_events.json` by default).
A recent run:

```
Cases: 16  TP=8  FP=0  FN=0
Precision: 1.00  Recall: 1.00  F1: 1.00
```

Each malicious row also names the rule it was written to exercise, and the
benchmark warns if a different rule fired instead - so "a rule fired" and
"the intended rule fired" are checked separately, not conflated.

This is a small, hand-curated corpus (8 malicious/benign pairs, one per
rule), not a claim of production-grade coverage - the honest caveat is that
1.00/1.00 on 16 cases you wrote yourself is a sanity check that the rules
work as designed, not evidence they'll hold up against real, unseen
attacker behavior or a large false-positive-prone production environment.
The next real test is running `hids scan` against several days of this
machine's actual Sysmon log once it's installed, and seeing what fires on
ordinary daily use (that's where false positives actually get discovered).

## Installing Sysmon

Not done by this tool - deliberately kept as a manual, elevated step:

1. Download Sysmon from Microsoft Sysinternals:
   https://learn.microsoft.com/sysinternals/downloads/sysmon
2. Get a config file. [SwiftOnSecurity's sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
   is the widely-used community default (logs process creation with full
   command lines, network connections, and more, with sensible noise
   filtering).
3. From an elevated (Administrator) terminal:
   ```
   sysmon64.exe -accepteula -i sysmonconfig-export.xml
   ```
4. Verify it's running: `Get-Service Sysmon64` (PowerShell) should show
   `Running`, and Event Viewer should show a new
   `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`
   channel filling up with EventID 1 entries as you use the machine.

## Usage

```bash
# Install (editable, with test deps)
pip install -e ".[dev]"

# Run the unit tests + labeled benchmark
python -m pytest -q
python -m hids.cli benchmark

# Scan a JSON fixture (no Sysmon required)
python -m hids.cli scan tests/fixtures/labeled_events.json

# Scan the live Sysmon channel (requires Sysmon installed, admin rights
# to read the Operational log depending on local policy)
python -m hids.cli scan

# Scan an exported .evtx file
python -m hids.cli scan path\to\exported.evtx
```

## Roadmap

- Run against this machine's real Sysmon log once installed; document
  what false-positives show up in ordinary use and tune rules accordingly
  (mirrors the vuln-scanner's "measure, don't assert" approach).
- Stateful correlation across events (e.g. a process that creates a
  scheduled task *and* was itself spawned from Temp within N seconds -
  currently each rule only sees one event at a time).
- Optional: a small local LLM pass (same two-detector-comparison idea as
  LLM_Vulnerability_Scanner) that reasons over a process's full command
  line and ancestry chain, compared against the rule engine on the same
  benchmark methodology.

## License

MIT - see [LICENSE](LICENSE).
