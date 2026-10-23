"""Suppress findings from known-good software.

An allowlist is a JSON file:

    {"entries": [
        {"name": "Claude Code shell launcher",
         "rule": "ENCODED_POWERSHELL",
         "command_line": "\\"C:\\\\Windows\\\\...powershell\\\\.exe\\" ...",
         "note": "free text, ignored"}
    ]}

An entry suppresses a finding when `rule` equals the finding's rule_id AND
every matcher it sets fully matches the corresponding event field
(case-insensitive regex). Full match rather than search, so a known-good
command line with something appended to it no longer matches. Each entry
must name a rule and at least one matcher, and unknown keys are rejected,
so a typo can't turn into an entry that silently matches everything.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from hids.events import Event
from hids.rules import Finding

# Matcher key -> how to read that field off an event.
_MATCHERS = {
    "image": lambda e: e.image,
    "command_line": lambda e: e.command_line,
    "parent_image": lambda e: e.parent_image,
    "parent_command_line": lambda e: e.parent_command_line,
    # 4698 (Security log) events carry the task name, not a command line.
    "task_name": lambda e: e.extra.get("TaskName", ""),
}
_ALLOWED_KEYS = {"name", "rule", "note", *_MATCHERS}


class AllowlistError(ValueError):
    pass


@dataclass
class AllowEntry:
    name: str
    rule: str
    patterns: dict[str, re.Pattern]

    def matches(self, finding: Finding) -> bool:
        if finding.rule_id != self.rule:
            return False
        event: Event = finding.event
        return all(p.fullmatch(_MATCHERS[key](event)) for key, p in self.patterns.items())


@dataclass
class Allowlist:
    entries: list[AllowEntry]
    # Entry name -> number of findings it suppressed, so the CLI can report
    # what was hidden instead of hiding it silently.
    hits: Counter = field(default_factory=Counter)

    def suppresses(self, finding: Finding) -> bool:
        for entry in self.entries:
            if entry.matches(finding):
                self.hits[entry.name] += 1
                return True
        return False


def load_allowlist(path: str | Path) -> Allowlist:
    path = Path(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AllowlistError(f"could not read allowlist {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise AllowlistError(f"allowlist {path} is not valid JSON: {exc}") from exc

    raw_entries = payload.get("entries") if isinstance(payload, dict) else None
    if not isinstance(raw_entries, list):
        raise AllowlistError(f'allowlist {path} must be an object with an "entries" list')

    entries = []
    for i, raw in enumerate(raw_entries):
        where = f"allowlist {path}, entry {i}"
        if not isinstance(raw, dict):
            raise AllowlistError(f"{where}: must be an object")
        unknown = set(raw) - _ALLOWED_KEYS
        if unknown:
            raise AllowlistError(f"{where}: unknown key(s) {sorted(unknown)}")
        # A misspelled rule ID just never matches, which fails safe (the
        # finding still shows), so only the type is checked here.
        rule = raw.get("rule")
        if not isinstance(rule, str) or not rule:
            raise AllowlistError(f'{where}: "rule" must be a rule ID such as "ENCODED_POWERSHELL"')
        patterns = {}
        for key in _MATCHERS:
            if key in raw:
                try:
                    patterns[key] = re.compile(raw[key], re.IGNORECASE)
                except (re.error, TypeError) as exc:
                    raise AllowlistError(f"{where}: bad {key!r} pattern: {exc}") from exc
        if not patterns:
            raise AllowlistError(f"{where}: needs at least one of {sorted(_MATCHERS)}")
        entries.append(AllowEntry(name=raw.get("name") or f"entry {i}", rule=rule, patterns=patterns))
    return Allowlist(entries=entries)
