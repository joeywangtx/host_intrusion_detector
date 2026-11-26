# Host Intrusion Detector

[![CI](https://github.com/joeywangtx/host_intrusion_detector/actions/workflows/ci.yml/badge.svg)](https://github.com/joeywangtx/host_intrusion_detector/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A small host intrusion detection tool for Windows. It reads Sysmon event logs and flags suspicious behavior: encoded PowerShell, Office or a browser launching a shell (macro-dropper and drive-by-download chains), built-in binaries like `certutil`, `mshta` and `rundll32` downloading remote payloads, new scheduled tasks (a common persistence method), and programs running from temp or download folders. New to these terms? See the [Glossary](DETAIL.md#glossary).

I tested it in two ways, the same approach as my [LLM_Vulnerability_Scanner](https://github.com/joeywangtx/LLM_Vulnerability_Scanner) project:

- **A labeled benchmark.** A hand-labeled set of malicious events, each paired with a benign event that looks similar. The detector is scored on precision, recall and F1.
- **Real logs.** Five days of Sysmon logs from my dev workstation. I traced every false positive to its cause, then either fixed the allowlist or left the finding in and wrote down why.

## Why

Most detection tools ask you to trust that their rules work. I wanted to check mine, so I wrote the answer key first: pairs of malicious and benign events that use the same program. For example, `certutil -urlcache` downloading a payload vs. `certutil -verify` checking a certificate. Then I scored the detector against it.

Endpoint logs (full command lines, parent/child process trees) are what SOC analysts read most of the day. The hard part of writing a rule is not firing on normal Windows activity. Because every malicious case in the benchmark has a benign twin with the same binary or parent process, a rule that only matches on "certutil.exe" fails. The [real-world scan](#real-world-scan) then tries the rules on data I didn't write.

## Results

```
Cases: 16  TP=8  FP=0  FN=0
Precision: 1.00  Recall: 1.00  F1: 1.00
```

Each malicious case also names the rule it is meant to trigger, and the benchmark checks that this rule fired, not just any rule. Reproduce with `hids benchmark`.

Caveat: the corpus is small (8 malicious/benign pairs, one per rule). 1.00/1.00 on 16 cases written by myself shows the rules work as designed. It doesn't show they would catch real attackers or stay quiet on a busy production network.

### Real-world scan

Five days of Sysmon logging on my dev workstation (Nov 20–25, 2026: 38,060 events, 13,609 process creates):

- **Nothing malicious, and no hits** on the four behavior rules (LOLBin download, Office/browser spawning a shell, scheduled task).
- **2 allowlist gaps, both fixed.** Claude Code switched its shell to PowerShell 7 (`pwsh.exe`), and a VS Code update changed the quoting in one of its commands. Together they caused 53 `ENCODED_POWERSHELL` false positives.
- **2 `EXEC_FROM_TEMP` findings left in (Low).** One is a throwaway venv in an AI agent's Temp folder, the other an installer I opened from Downloads. The rule is right about the behavior; whether it's benign depends on who ran it.

What I learned:

- **Allowlists break when software updates.** Both gaps came from legitimate tools changing slightly. Entries must match exactly, so a gap shows up as a false positive instead of hiding something. The report prints how many findings each entry suppressed, which makes a drifted entry easy to spot.
- **The noisiest PowerShell user on my machine was an AI coding agent.** 70 of the 77 suppressed findings were Claude Code's own shell calls. They use the same hidden-window, policy-bypass, Base64-encoded flags the rule looks for.

Full breakdown: [DETAIL.md › Real-world scan](DETAIL.md#real-world-scan-november-2026).

## Detection rules

| Rule | Event source | MITRE ATT&CK | Severity |
|---|---|---|---|
| `ENCODED_POWERSHELL` | Sysmon ID 1 (process create) | T1059.001 | High |
| `OFFICE_SPAWNED_SHELL` | ID 1 | T1566.001 | Critical |
| `BROWSER_SPAWNED_SHELL` | ID 1 | T1189 | High |
| `SCHEDULED_TASK_CREATED` | ID 4698, or `schtasks /create` via ID 1 | T1053.005 | Medium |
| `LOLBIN_DOWNLOAD` | ID 1 (certutil/mshta/rundll32/regsvr32/bitsadmin) | T1105 | High |
| `EXEC_FROM_TEMP` | ID 1 | T1204 | Low |

The rules are narrow on purpose. `OFFICE_SPAWNED_SHELL` only fires when the child process is a shell or script engine, since Word starts `splwow64.exe` every time you print. `LOLBIN_DOWNLOAD` only fires when the command line also has a download indicator, not on every certutil call.

## Install

```bash
pip install -e ".[dev]"
```

You don't need Sysmon to run the tests or the benchmark; both use a JSON fixture. Live collection (`hids scan` with no argument) does need it. See [Installing Sysmon](#installing-sysmon).

## Usage

`pip install -e .` adds a `hids` command; `python -m hids.cli <args>` does the same thing.

```bash
# Scan a JSON fixture (no Sysmon required)
hids scan tests/fixtures/labeled_events.json

# Scan the live Sysmon channel (requires Sysmon; may need admin rights
# to read the Operational log, depending on local policy)
hids scan

# Scan an exported .evtx file
hids scan path\to\exported.evtx

# Only read the newest 500 events (default --max-events 0 = whole log)
hids scan --max-events 500

# Suppress known-good activity (Claude Code, VS Code updater, Office, ...);
# the report ends with a count of what each allowlist entry hid
hids scan --allowlist allowlist.example.json

# Run the labeled benchmark and print precision/recall/F1
hids benchmark

# Run my credential-auditor project (needs `credaudit` installed
# and on PATH, see github.com/joeywangtx/credential_auditor)
hids audit-credentials
```

## Installing Sysmon

The tool doesn't install Sysmon for you. It needs admin rights, so I kept it a manual step:

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/sysinternals/downloads/sysmon).
2. Get a config file. [SwiftOnSecurity's sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) is the common community default.
3. From an Administrator terminal:
   ```
   sysmon64.exe -accepteula -i sysmonconfig-export.xml
   ```
4. Check it: `Get-Service Sysmon64` (PowerShell) should show `Running`, and Event Viewer should show `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational` filling with EventID 1 entries as you use the machine.

## How it works

| Module | What it does |
|---|---|
| `hids/events.py` | `Event` dataclass: Sysmon EventID 1 (process create) fields, plus an `extra` dict for other event IDs |
| `hids/collector.py` | Reads events from the live Sysmon channel, an exported `.evtx` file, or a JSON fixture, using `wevtutil` (no extra install) |
| `hids/rules.py` | The 6 detection rules; each returns a `Finding` with a severity and MITRE ATT&CK ID |
| `hids/scorer.py` | Sums findings per process into a risk score; scores the rules against the labeled fixture |
| `hids/allowlist.py` | Loads a JSON allowlist and drops findings whose rule and event fields (full-match regex) match a known-good entry |
| `hids/credaudit_bridge.py` | Runs `credaudit --json` and converts its findings to HIDS risk scores |
| `hids/cli.py` | `hids scan <source>`, `hids benchmark [<fixture>]`, `hids audit-credentials` |

Architecture notes: [`DESIGN.md`](DESIGN.md). Longer writeup with examples and a glossary: [`DETAIL.md`](DETAIL.md).

## Development

```bash
python -m pytest -q
```

65 tests:
- `test_rules.py`: one malicious/benign pair per rule
- `test_scorer.py`: regression test on the benchmark corpus
- `test_collector.py`: XML parsing and `wevtutil` error handling, using captured sample output
- `test_allowlist.py`: the allowlist hides known-good activity but nothing else. For example, `pwsh.exe` is only trusted from its normal install folders and still gets flagged anywhere else.
- `test_cli.py`: subcommand exit codes
- `test_credaudit_bridge.py`: `hids audit-credentials`, which runs my separate credaudit tool. The tests fake credaudit's output, so credaudit doesn't need to be installed. They check that its findings are read correctly and that a clear error is shown when credaudit isn't installed.

The labeled corpus is `tests/fixtures/labeled_events.json` (16 hand-labeled synthetic events, 8 pairs). CI runs the tests and the benchmark on Linux and Windows with Python 3.10, 3.12 and 3.13.

## Status

The rule engine, scorer and benchmark are done and passing. I've run `hids scan` on five days of real Sysmon logs (see [Real-world scan](#real-world-scan)) and tuned the allowlist from the results.

## Roadmap

- Rescan now and then to check the allowlist still holds after software updates; add the Security log (ID 4698) to the export.
- Connect related events. Right now each rule looks at one event and forgets it. Some attacks only stand out when you link events together: a program starts from Downloads (Low on its own), then a few seconds later sets up a scheduled task (Medium on its own). Together that's a downloaded program making itself run again after every reboot, which should be one High alert. Catching it means remembering recent findings for a short time and checking whether a new event comes from a process that was just flagged.
- Try a local LLM pass and score it on the same benchmark, like in LLM_Vulnerability_Scanner.

## License

MIT, see [LICENSE](LICENSE).
