"""Emulate local_rules.xml matching against decoded Windows/Sysmon events."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
RULES_XML = ROOT / "wazuh" / "rules" / "local_rules.xml"

# §1.3 stock parent SID -> (providerName, eventID). None = any. 60001 uses channel.
PARENT_SID = {
    "61603": ("Microsoft-Windows-Sysmon", "1"),
    "61605": ("Microsoft-Windows-Sysmon", "3"),
    "61609": ("Microsoft-Windows-Sysmon", "7"),
    "61612": ("Microsoft-Windows-Sysmon", "10"),
    "61613": ("Microsoft-Windows-Sysmon", "11"),
    "61614": ("Microsoft-Windows-Sysmon", "12"),
    "61615": ("Microsoft-Windows-Sysmon", "13"),
    "61644": ("Microsoft-Windows-Sysmon", "22"),
    "60000": (None, None),
    "60100": ("Microsoft-Windows-Security-Auditing", None),
    "60001": ("System", None),
}
CHANNEL_PARENTS = {"60001"}
GROUP_PARENT = {"windows_powershell": ("Microsoft-Windows-PowerShell", "4104")}
PRIMARY_LO, PRIMARY_HI = 100100, 100111


@dataclass
class Rule:
    id: int
    level: int
    description: str
    mitre_ids: list
    groups: list
    if_sids: list
    if_group: str | None
    if_matched_sid: int | None
    same_field: str | None
    frequency: int | None
    timeframe: int | None
    fields: list = field(default_factory=list)


def get_field(event: dict, name: str):
    if name in event:
        return event[name]
    cur = event
    for part in name.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def parse_rules(path: Path | None = None) -> list[Rule]:
    out: list[Rule] = []
    for el in ET.parse(path or RULES_XML).getroot().iter("rule"):
        sid_raw = (el.findtext("if_sid") or "").replace(" ", "")
        matched = el.findtext("if_matched_sid")
        freq, tf = el.get("frequency"), el.get("timeframe")
        out.append(
            Rule(
                id=int(el.get("id")),
                level=int(el.get("level", "0")),
                description=(el.findtext("description") or "").strip(),
                mitre_ids=[m.text.strip() for m in el.findall("./mitre/id") if m.text],
                groups=[g for g in (el.findtext("group") or "").split(",") if g],
                if_sids=[s for s in sid_raw.split(",") if s],
                if_group=(el.findtext("if_group") or "").strip() or None,
                if_matched_sid=int(matched) if matched else None,
                same_field=(el.findtext("same_field") or "").strip() or None,
                frequency=int(freq) if freq else None,
                timeframe=int(tf) if tf else None,
                fields=[(f.get("name"), f.text or "") for f in el.findall("field")],
            )
        )
    return out


def _parent_matches(rule: Rule, event: dict) -> bool:
    got_p = get_field(event, "win.system.providerName")
    got_e = str(get_field(event, "win.system.eventID") or "")
    got_c = get_field(event, "win.system.channel") or ""
    if rule.if_group:
        want_p, want_e = GROUP_PARENT.get(rule.if_group, (None, None))
        return (want_p is None or got_p == want_p) and (want_e is None or got_e == want_e)
    if not rule.if_sids:
        return False
    for sid in rule.if_sids:
        if sid not in PARENT_SID:
            continue
        want_p, want_e = PARENT_SID[sid]
        if sid in CHANNEL_PARENTS:
            if got_c == want_p:
                return True
            continue
        if want_p is not None and got_p != want_p:
            continue
        if want_e is not None and got_e != str(want_e):
            continue
        return True
    return False


def match(rule: Rule, event: dict) -> bool:
    if not _parent_matches(rule, event):
        return False
    for name, pattern in rule.fields:
        val = get_field(event, name)
        if val is None or re.search(pattern, str(val)) is None:
            return False
    return True


def evaluate(event: dict, rules: list[Rule] | None = None) -> Rule | None:
    rules = rules if rules is not None else parse_rules()
    hits = [r for r in rules if PRIMARY_LO <= r.id <= PRIMARY_HI and match(r, event)]
    return max(hits, key=lambda r: (r.level, r.id)) if hits else None


def evaluate_frequency(events: list, rules: list[Rule] | None = None) -> list[Rule]:
    rules = rules if rules is not None else parse_rules()
    by_id = {r.id: r for r in rules}
    fired: list[Rule] = []
    for rule in rules:
        parent = by_id.get(rule.if_matched_sid or 0)
        if parent is None or not rule.frequency:
            continue
        groups: dict[str, list] = {}
        for ev in events:
            if match(parent, ev):
                key = str(get_field(ev, rule.same_field or "") or "")
                groups.setdefault(key, []).append(ev)
        if any(_burst(g, rule.frequency, rule.timeframe) for g in groups.values()):
            fired.append(rule)
    return fired


def _burst(events: list, frequency: int, timeframe: int | None) -> bool:
    if len(events) < frequency:
        return False
    if not timeframe:
        return True
    nums = []
    for ev in events:
        raw = ev.get("timestamp")
        if raw is None:
            return True
        try:
            nums.append(float(raw))
        except (TypeError, ValueError):
            return True
    nums.sort()
    i = 0
    for j, t in enumerate(nums):
        while nums[i] < t - timeframe:
            i += 1
        if j - i + 1 >= frequency:
            return True
    return False
