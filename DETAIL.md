# host_intrusion_detector

A lightweight host intrusion detection tool that reads Sysmon-instrumented
Windows Event Log data and flags suspicious behavior: encoded/obfuscated
PowerShell, Office/browser processes spawning shells (the classic
macro-dropper and drive-by-download chains), living-off-the-land binaries
(certutil, mshta, rundll32, ...) used to fetch remote payloads, new
scheduled tasks (a common persistence mechanism), and processes executing
from temp/download paths. New to these terms? See the [Glossary](#glossary).

Like the companion [LLM_Vulnerability_Scanner](../LLM_Vulnerability_Scanner)
project, this isn't just a detector - it's a detector plus proof that the
detector works: a hand-labeled corpus of malicious and deliberately
similar-looking benign event pairs, graded with precision/recall/F1, so
"it catches bad stuff" is a checked claim, not an assertion.

## Status

Rule engine, scorer, and labeled benchmark corpus are done and passing - run
`python -m pytest -q` and `hids benchmark` for the current numbers (see
[Current results](#current-results) for a recent run). Sysmon is installed
on my dev workstation, and `hids scan` has been run against five days of
its real log (see [Real-world scan](#real-world-scan-november-2026)). That
run found no attacks, two allowlist gaps (now fixed), and two known kinds
of false positive from `EXEC_FROM_TEMP`. Installing Sysmon stays a manual,
elevated step, as does exporting its log (see
[Installing Sysmon](#installing-sysmon)).

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

## Glossary

### Attack chains and techniques

- **Macro-dropper chain**: A phishing email delivers an Office document (Word, Excel) with an embedded VBA macro. When the user opens it and clicks "Enable Content", the macro launches a shell (`cmd.exe`, `powershell.exe`, `wscript.exe`), and that shell downloads ("drops") and runs the real malware. On the host this looks like `WINWORD.EXE → powershell.exe`, which normal Office use almost never produces. This is what `OFFICE_SPAWNED_SHELL` detects.
- **Drive-by-download chain**: The same pattern, but the entry point is the browser. A malicious or compromised website exploits the browser or tricks the user into running a file, which leads to `chrome.exe` / `msedge.exe` / `firefox.exe` spawning a shell. This is what `BROWSER_SPAWNED_SHELL` detects.
- **Living-off-the-land binaries (LOLBins)**: Legitimate, Microsoft-signed programs that ship with Windows and can be repurposed for attacks, such as downloading files, running scripts, or loading code. Attackers like them because they are already on every machine, trusted by allowlisting tools, and blend in with normal admin activity. The [LOLBAS project](https://lolbas-project.github.io/) catalogs them. The ones this tool watches:
  - `certutil.exe`: a certificate-management utility. `certutil -urlcache -split -f <url>` downloads arbitrary files.
  - `mshta.exe`: runs HTML Application (`.hta`) files, including ones fetched straight from a URL, which means it can execute remote script.
  - `rundll32.exe`: calls an exported function in a DLL. It can be abused to run attacker DLLs or inline script.
  - `regsvr32.exe`: registers COM DLLs. `regsvr32 /i:<url> scrobj.dll` fetches and runs a remote script (the "Squiblydoo" technique).
  - `bitsadmin.exe`: controls the Background Intelligent Transfer Service. `bitsadmin /transfer` downloads files in the background.
- **Payload**: The malicious code an attack ultimately delivers and runs (ransomware, a remote-access trojan, a credential stealer). Droppers and LOLBins are usually just the delivery mechanism.
- **Download indicator**: A command-line feature showing that a process is fetching remote content, such as a URL (`http://`, `https://`), `-urlcache`, or PowerShell's `DownloadString` / `DownloadFile` (from `System.Net.WebClient`). `LOLBIN_DOWNLOAD` requires one of these, so benign uses like `certutil -verify` don't fire.
- **Encoded / obfuscated PowerShell**: PowerShell accepts `-EncodedCommand` (or abbreviations like `-enc`, `-e`) followed by a Base64 string of the script, so the real command never appears in plain text in logs or to a casual reader. Legitimate software rarely needs this. Malware uses it constantly, often alongside `-NoProfile`, `-WindowStyle Hidden`, or `-ExecutionPolicy Bypass`. This is what `ENCODED_POWERSHELL` detects.
- **Persistence**: Any mechanism that lets malware survive a reboot or logoff and keep running, such as scheduled tasks, Run registry keys, services, or startup folders.
- **Scheduled task**: A Windows Task Scheduler job that runs a program on a trigger (at logon, every N minutes, at boot). It is created with `schtasks /create` or the Task Scheduler API, and it is one of the most common persistence methods. This is what `SCHEDULED_TASK_CREATED` detects.
- **Execution from temp/download paths**: Legitimate installed software runs from `C:\Program Files` or `C:\Windows`. Freshly dropped malware usually runs from user-writable locations like `%TEMP%`, `%APPDATA%`, or `Downloads`, because those need no admin rights to write to. This is a weak signal on its own (installers do it too), which is why `EXEC_FROM_TEMP` is rated Low.

### Windows telemetry

- **Endpoint telemetry**: Data collected on the host itself (processes, command lines, file writes, network connections), as opposed to network-layer data like packet captures.
- **Sysmon (System Monitor)**: A free Microsoft Sysinternals driver and service that logs detailed security events to the Windows Event Log, well beyond what Windows records by default. Its configuration file controls what is logged and what noise is filtered out.
- **Sysmon Event ID 1 (Process Create)**: Logged every time a process starts. It records the image path, full command line, parent process, user, and file hashes. Most rules in this tool read this event.
- **Security Event ID 4698**: A native Windows Security-log event, "A scheduled task was created". It only appears when the "Audit Other Object Access Events" policy is enabled.
- **Image**: In Sysmon terms, the executable file a process was started from (e.g. `C:\Windows\System32\certutil.exe`).
- **Parent/child process tree**: Every Windows process is started by another one. Following the chain (e.g. `explorer.exe → WINWORD.EXE → powershell.exe`) shows *how* something came to run, which often matters more than *what* ran.
- **`splwow64.exe`**: The print-driver host that Office legitimately spawns when printing. It's the classic benign child of `WINWORD.EXE`, and the reason `OFFICE_SPAWNED_SHELL` checks what the child is instead of firing on any child process.
- **`.evtx`**: The binary file format for Windows Event Log files. Logs can be exported to `.evtx` and analyzed on another machine.
- **`wevtutil`**: A built-in Windows command-line tool for querying and exporting event logs. This tool uses it to read both live channels and `.evtx` files without extra dependencies.

### Detection and evaluation

- **HIDS (Host-based Intrusion Detection System)**: A system that watches activity on a single machine for signs of compromise. It complements a network IDS, which watches traffic.
- **SOC / blue team**: The Security Operations Center, the defenders who triage alerts and investigate incidents. Most of their day is spent reading endpoint telemetry like this.
- **MITRE ATT&CK**: A public knowledge base of real-world attacker techniques, each with an ID. The IDs used here:
  - `T1059.001`: Command and Scripting Interpreter: PowerShell
  - `T1566.001`: Phishing: Spearphishing Attachment (the macro-dropper entry point)
  - `T1189`: Drive-by Compromise
  - `T1053.005`: Scheduled Task/Job: Scheduled Task
  - `T1105`: Ingress Tool Transfer (pulling tools or payloads onto the host)
  - `T1204`: User Execution (the user is tricked into running something)
- **Rule / Finding**: A rule is one detection check applied to an event. A finding is what a rule emits when it fires: the rule ID, severity, ATT&CK technique, and the event that triggered it.
- **Severity**: How urgent a finding is (Low / Medium / High / Critical), based on how strongly the behavior indicates compromise and how rarely it happens legitimately.
- **Risk score**: The total severity of all findings for one process, so a process that trips several rules ranks above one that trips a single weak rule.
- **Allowlist**: A list of known-good activity (by rule and event fields) whose findings are suppressed, so regular noise like an editor's auto-updater doesn't bury real alerts.
- **True positive (TP) / false positive (FP) / false negative (FN)**: A TP is a malicious event correctly flagged. An FP is a benign event wrongly flagged (alert fatigue). An FN is a malicious event missed (a blind spot).
- **Precision / recall / F1**: Precision = TP / (TP + FP), meaning "when it alerts, how often is it right?" Recall = TP / (TP + FN), meaning "of the real attacks, how many did it catch?" F1 is their harmonic mean, which is high only if both are.
- **Labeled corpus / benign-but-similar pair**: The answer key in `tests/fixtures/labeled_events.json`. Each malicious event is paired with a benign one that uses the same binary or parent (e.g. `certutil -urlcache <url>` vs. `certutil -verify`), so a rule only scores well if it checks the behavior and not just the program name.

## Architecture

```
hids/
  events.py              Normalized Event dataclass (Sysmon EventID 1 process-
                         create fields + a generic "extra" bag for other IDs)
  collector.py           Reads events from: a live Sysmon channel, an exported
                         .evtx file (both via wevtutil, no extra install), or a
                         JSON fixture (for tests/demos without Sysmon installed)
  rules.py               6 detection rules, each event-id-typed, each returning
                         a Finding with a severity and a MITRE ATT&CK technique ID
  scorer.py              Groups findings by process into a risk score; grades
                         the rule set against a labeled fixture (precision/recall/F1)
  credaudit_bridge.py    Shells out to the companion credential-auditor
                         project's `credaudit --json` and adapts its findings
                         into HIDS's own risk-score format
  cli.py                 `hids scan <source>`, `hids benchmark [<fixture>]`,
                         and `hids audit-credentials`
tests/
  test_rules.py                  unit tests, one malicious/benign pair per rule
  test_scorer.py                 benchmark-corpus regression test
  test_collector.py              XML parsing + wevtutil error handling (sample output)
  test_cli.py                    subcommand exit codes and output
  test_credaudit_bridge.py       bridge unit tests (subprocess mocked)
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
The real-world scan below is the other half: what fires on ordinary daily
use, which is where false positives actually get found.

## Real-world scan (November 2026)

Five days of Sysmon logging on my own dev workstation (Windows 11, SwiftOnSecurity
config), exported from an elevated terminal and scanned with the example
allowlist:

```powershell
# elevated
wevtutil epl Microsoft-Windows-Sysmon/Operational "$env:USERPROFILE\sysmon-export.evtx"
# normal
hids scan "$env:USERPROFILE\sysmon-export.evtx" --allowlist allowlist.example.json
```

| | |
|---|---|
| Time range | 2026-11-20 16:48 to 2026-11-25 16:44 UTC |
| Events read | 38,060 (13,609 process creates, ID 1; the rest are network, DNS, file, registry, etc.) |
| Rule hits | 109 (75 `ENCODED_POWERSHELL`, 34 `EXEC_FROM_TEMP`) |
| Other rules | 0 hits: no LOLBin downloads, no Office/browser spawning a shell, no scheduled-task creation |
| Confirmed malicious | 0 |

Normal daily use (coding, Claude Code sessions, a VS Code update, a driver
install) never triggered the four High/Critical behavior rules. Every hit came
from the two rules that look at flags and paths, not process ancestry.

### What fired, and what was done about it

**1. Claude Code's PowerShell 7 calls: 52 `ENCODED_POWERSHELL` hits, allowlist gap (fixed).**
Claude Code launches PowerShell with `-ExecutionPolicy Bypass` and, for its
command parser, `-EncodedCommand`. That is exactly the shape the rule is
built to catch. The allowlist already covered these command lines, but only
under Windows PowerShell 5.1 (`powershell.exe`). During the scan window
Claude Code switched to PowerShell 7 (`pwsh.exe`, installed from the
Microsoft Store under `C:\Program Files\WindowsApps\Microsoft.PowerShell_7.7.0.0_x64__8wekyb3d8bbwe\`),
so the same commands from a different binary got through. The two Claude
Code entries now also accept `pwsh.exe` from that Store path or
`C:\Program Files\PowerShell\7\`, which are admin-writable locations. A
`pwsh.exe` anywhere else (e.g. `C:\Users\Public\`) is still flagged, and
there is a test for that.

**2. VS Code updater: 1 `ENCODED_POWERSHELL` hit, allowlist gap (fixed).**
During its update, the VS Code installer (`CodeSetup-stable-*.tmp`) runs a
hidden PowerShell command that stops its Explorer context-menu `dllhost.exe`.
The allowlist entry was written from an October update, and this update's
command differs in two small ways: `\"` instead of `""` around the filter,
and no `/Processid:` prefix before the CLSID. The entry now accepts both
forms. The command itself must still match in full, so anything appended to
it still fires.

**3. A venv in a Claude Code scratchpad: 30 `EXEC_FROM_TEMP` hits, expected false positive (left in).**
An earlier Claude Code session built a throwaway virtualenv under
`%TEMP%\claude\<session>\scratchpad\ci_sim\venv\` to simulate a CI run of the
LLM_Vulnerability_Scanner project (`pip install`, `pytest`, `bandit`). The
rule is right that this is an executable running from Temp. It is benign
only because I know what made it. I did not allowlist it: the path is
user-writable and the parents vary (`bash.exe`, `env.exe`, `python.exe`), so
the only possible entry would match by path alone, which is the same
weakness the VS Code temp-setup entry already notes. At severity 3 (Low), 30
grouped findings collapse into one line of output, which is acceptable noise.

**4. An installer run from Downloads: 1 `EXEC_FROM_TEMP` hit, true positive of the behavior, benign intent (left in).**
`Downloads\sqliteodbc_w64 (1).exe` (the SQLite ODBC driver, installed for
another project) was started by `chrome.exe` when I opened it from the
download bar. This is exactly what the rule is for: a freshly downloaded
binary running from a user-writable folder. Only the person who ran it can
tell it's benign. `BROWSER_SPAWNED_SHELL` correctly stayed quiet, because
the child is an installer, not a shell.

After the two allowlist fixes, the same export produces:

```
[score 3] C:\Users\<user>\AppData\Local\Temp\claude\<session>\scratchpad\ci_sim\venv\Scripts\python.exe  (x30 processes)
    - EXEC_FROM_TEMP (severity 3, T1204)
[score 3] C:\Users\<user>\Downloads\sqliteodbc_w64 (1).exe  (x2 processes)
    - EXEC_FROM_TEMP (severity 3, T1204)

Suppressed by allowlist (77 findings):
       35  Claude Code: shell tool launcher
       35  Claude Code: PowerShell command parser
        2  VS Code updater: query installed AppX package
        2  VS Code updater: setup executables in temp
        1  VS Code updater: register AppX package
        1  VS Code updater: remove old AppX package
        1  VS Code updater: stop Explorer context-menu host
```

### Takeaways

- **Allowlists break when software updates.** Both gaps came from legitimate
  software changing slightly: a different PowerShell binary, different
  quoting. An exact-match allowlist fails safe (the finding shows up, nothing
  is silently hidden), but it needs re-checking after updates. The report's
  per-entry suppression counts make that visible: an entry that suddenly
  hits 0 times has probably drifted.
- **The heaviest PowerShell user on this machine is an AI coding agent.**
  Seventy of the 77 suppressed findings are Claude Code's own shell calls. On
  developer machines, agent tooling is now a major source of detection noise,
  and it looks a lot like what the rules are hunting: hidden windows,
  execution-policy bypass, Base64-encoded commands.
- **`EXEC_FROM_TEMP` is a context signal, not an alert.** Both remaining
  findings are correct about the behavior and benign in intent. That is why
  the rule is rated Low. It is most useful as a score booster when it
  coincides with another rule on the same process (see Roadmap: stateful
  correlation).
- **What this does *not* show:** five quiet days on one machine say nothing
  about recall against real attacks, because none happened. Recall is still
  measured only by the labeled benchmark.

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

- Stateful correlation across events (e.g. a process that creates a
  scheduled task *and* was itself spawned from Temp within N seconds -
  currently each rule only sees one event at a time).
- Optional: a small local LLM pass (same two-detector-comparison idea as
  LLM_Vulnerability_Scanner) that reasons over a process's full command
  line and ancestry chain, compared against the rule engine on the same
  benchmark methodology.

## License

MIT - see [LICENSE](LICENSE).
