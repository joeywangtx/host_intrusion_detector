# Host Intrusion Detector

[![CI](https://github.com/joeywangtx/host_intrusion_detector/actions/workflows/ci.yml/badge.svg)](https://github.com/joeywangtx/host_intrusion_detector/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A lightweight host intrusion detection tool that reads Sysmon-instrumented Windows Event Log data and flags suspicious behavior: encoded/obfuscated PowerShell, Office/browser processes spawning shells (macro-dropper and drive-by-download chains), living-off-the-land binaries (`certutil`, `mshta`, `rundll32`, ...) fetching remote payloads, new scheduled tasks (a common persistence mechanism), and processes executing from temp/download paths.

Like the companion [LLM_Vulnerability_Scanner](https://github.com/joeywangtx/LLM_Vulnerability_Scanner) project, this isn't just a detector — it ships with a hand-labeled corpus of malicious and deliberately similar-looking benign event pairs, graded by precision/recall/F1, so "it catches bad stuff" is a checked claim.

## Why

Detection-logic claims in security tooling are almost always unverifiable — a tool flags something and a person nods along. The differentiator here: write the answer key first (malicious-vs-benign-but-similar event pairs — e.g. `certutil -urlcache` downloading a payload vs. `certutil -verify` checking a certificate, both using the same binary), then grade the detector against it honestly.

Endpoint telemetry (full command lines, parent/child process trees) is what SOC analysts spend most of their day reading, and writing a rule that doesn't false-positive on *normal* Windows behavior is the actual skill being tested. The benchmark below is built around that: each malicious case is paired with a benign case sharing the same binary or parent process, so a rule that just pattern-matches "certutil.exe" would fail the benchmark, not just look naively accurate.

## Results

```
Cases: 16  TP=8  FP=0  FN=0
Precision: 1.00  Recall: 1.00  F1: 1.00
```

Each malicious row also names the rule it was written to exercise, and the benchmark separately checks that *that* rule fired, rather than just "a rule fired." Reproduce with `hids benchmark`.

Honest caveat: this is a small, hand-curated corpus (8 malicious/benign pairs, one per rule) — 1.00/1.00 on 16 cases you wrote yourself is a sanity check that the rules work as designed, not evidence they hold up against real, unseen attacker behavior or a noisy production environment. The next real test is running `hids scan` against several days of an actual Sysmon log and seeing what fires on ordinary daily use — that's where false positives actually get found.

## Detection rules

| Rule | Event source | MITRE ATT&CK | Severity |
|---|---|---|---|
| `ENCODED_POWERSHELL` | Sysmon ID 1 (process create) | T1059.001 | High |
| `OFFICE_SPAWNED_SHELL` | ID 1 | T1566.001 | Critical |
| `BROWSER_SPAWNED_SHELL` | ID 1 | T1189 | High |
| `SCHEDULED_TASK_CREATED` | ID 4698, or `schtasks /create` via ID 1 | T1053.005 | Medium |
| `LOLBIN_DOWNLOAD` | ID 1 (certutil/mshta/rundll32/regsvr32/bitsadmin) | T1105 | High |
| `EXEC_FROM_TEMP` | ID 1 | T1204 | Low |

Each rule is intentionally narrow rather than a broad keyword match — e.g. `OFFICE_SPAWNED_SHELL` only fires when the *child* is a shell/scripting engine (Word legitimately spawns `splwow64.exe` for printing constantly); `LOLBIN_DOWNLOAD` only fires when the command line also contains a download indicator, not on every certutil invocation.

## Install

```bash
pip install -e ".[dev]"
```

No live Sysmon install is required to run tests or the benchmark — both use a JSON fixture. Live collection (`hids scan` with no argument) does need Sysmon; see [Installing Sysmon](#installing-sysmon).

## Usage

`pip install -e .` puts a `hids` command on PATH; `python -m hids.cli <args>` is equivalent.

```bash
# Scan a JSON fixture (no Sysmon required)
hids scan tests/fixtures/labeled_events.json

# Scan the live Sysmon channel (requires Sysmon installed; admin rights to
# read the Operational log depending on local policy)
hids scan

# Scan an exported .evtx file
hids scan path\to\exported.evtx

# Run the labeled benchmark and print precision/recall/F1
hids benchmark

# Delegate to the companion credential-auditor project (needs `credaudit`
# installed and on PATH — see github.com/joeywangtx/credential_auditor)
hids audit-credentials
```

## Installing Sysmon

Not done by this tool — deliberately a manual, elevated step:

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/sysinternals/downloads/sysmon).
2. Get a config file — [SwiftOnSecurity's sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) is the widely-used community default.
3. From an elevated (Administrator) terminal:
   ```
   sysmon64.exe -accepteula -i sysmonconfig-export.xml
   ```
4. Verify: `Get-Service Sysmon64` (PowerShell) should show `Running`, and Event Viewer should show `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational` filling with EventID 1 entries as you use the machine.

## How it works

| Module | Responsibility |
|---|---|
| `hids/events.py` | Normalized `Event` dataclass (Sysmon EventID 1 process-create fields + a generic "extra" bag for other IDs) |
| `hids/collector.py` | Reads events from a live Sysmon channel, an exported `.evtx` file, or a JSON fixture — all via `wevtutil`, no extra install |
| `hids/rules.py` | 6 detection rules, each returning a `Finding` with a severity and MITRE ATT&CK technique ID |
| `hids/scorer.py` | Groups findings by process into a risk score; grades the rule set against the labeled fixture |
| `hids/credaudit_bridge.py` | Shells out to `credaudit --json` and adapts its findings into HIDS's risk-score format |
| `hids/cli.py` | `hids scan <source>`, `hids benchmark [<fixture>]`, `hids audit-credentials` |

Full architecture notes: [`DESIGN.md`](DESIGN.md). Extended writeup with worked examples: [`Detail.md`](Detail.md).

## Development

```bash
python -m pytest -q
```

34 tests covering: one malicious/benign pair per rule (`test_rules.py`), a benchmark-corpus regression test (`test_scorer.py`), XML parsing + `wevtutil` error handling against captured sample output (`test_collector.py`), subcommand exit codes (`test_cli.py`), and the credaudit bridge with subprocess mocked (`test_credaudit_bridge.py`). The labeled corpus itself is `tests/fixtures/labeled_events.json` (16 hand-labeled synthetic events, 8 malicious/benign pairs). CI runs the suite plus the benchmark on Linux and Windows against Python 3.10, 3.12, and 3.13.

## Status

Rule engine, scorer, and labeled benchmark are done and passing. Live Sysmon collection (`hids scan` against the live channel) is code-complete and unit-tested against captured sample output, but not yet run against a live Sysmon install.

## Roadmap

- Run against a real Sysmon log once installed; document false positives from ordinary use and tune rules accordingly.
- Stateful correlation across events (e.g. a process that creates a scheduled task *and* was itself spawned from Temp within N seconds — each rule currently sees one event at a time).
- Optional local-LLM pass compared against the rule engine on the same benchmark methodology, mirroring LLM_Vulnerability_Scanner.

## License

MIT — see [LICENSE](LICENSE).
