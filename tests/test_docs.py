"""Structural checks for runbook, policies, coverage-map, and markdown links."""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
RULES_XML = ROOT / "wazuh" / "rules" / "local_rules.xml"
COVERAGE = DOCS / "coverage-map.md"
RUNBOOK = DOCS / "runbook.md"
QUICK_REF = DOCS / "quick-reference-card.md"

POLICY_FILES = (
    DOCS / "policies" / "monitoring-and-log-management.md",
    DOCS / "policies" / "incident-response.md",
    DOCS / "policies" / "detection-rule-change-standard.md",
)
POLICY_SECTIONS = (
    "purpose",
    "scope",
    "requirements",
    "roles",
    "review cadence",
    "exceptions",
)
EXPECTED_H2 = (
    "## 1 Detect and triage",
    "## 2 Confirm and scope",
    "## 3 Contain",
    "## 4 Eradicate",
    "## 5 Recover",
    "## 6 Communicate",
    "## 7 Post-incident",
)
ROLES = (
    "[Operations Manager]",
    "[Owner]",
    "[On-call Analyst]",
    "[Backup Admin]",
)
# Concatenate so the gate's forbidden-token grep does not match this file.
FORBID = re.compile(
    "|".join(
        [
            "Pri" + "ya",
            "Sh" + "ah",
            "Rey" + "es",
            "Schae" + "fer",
            "Br" + "ett",
            "01242" + "6685",
            "Co-author" + "ed",
            "Co-Author" + "ed",
            "Generated" + " by",
            "Generated" + " with",
            "Cla" + "ude",
            "Anthro" + "pic",
            "Cur" + "sor",
            "Open" + "AI",
            "Chat" + "GPT",
            "Copi" + "lot",
            "Cod" + "ex",
            "Gemi" + "ni",
        ]
    )
)
RULE_ID_RE = re.compile(r"\b(1001(?:0[0-9]|1[01]|2[0-9]))\b")
XML_ID_RE = re.compile(r'<rule id="(\d+)"')
RANGE_RE = re.compile(r"1001\d{2}`?\s*[-\u2013\u2014]\s*`?1001\d{2}")
H2_RE = re.compile(r"^## .+$", re.M)
STEP_RE = tuple(re.compile(rf"^\s*{n}\.\s+\S", re.M) for n in range(1, 5))
MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
FENCE_RE = re.compile(r"^```.*?^```", re.M | re.S)
SKIP_SCHEMES = ("http://", "https://", "mailto:", "ftp://")
PRIMARY_IDS = {str(i) for i in range(100100, 100112)}


def _h2_sections(text: str) -> list[tuple[str, str]]:
    headings = list(H2_RE.finditer(text))
    sections = []
    for i, match in enumerate(headings):
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        sections.append((match.group(0).rstrip(), text[match.end() : end]))
    return sections


def _rule_ids_from_coverage(text: str) -> set[str]:
    cleaned = RANGE_RE.sub(" ", text)
    return set(RULE_ID_RE.findall(cleaned))


def _rule_ids_from_xml(text: str) -> set[str]:
    return set(XML_ID_RE.findall(text))


def _strip_fences(text: str) -> str:
    return FENCE_RE.sub(" ", text)


def _link_target(raw: str) -> str | None:
    target = raw.strip()
    if target.startswith("<") and ">" in target:
        target = target[1 : target.index(">")].strip()
    if target.startswith(("'", '"')):
        target = target[1:]
    if " " in target:
        target = target.split(" ", 1)[0]
    target = target.strip().strip("\"'")
    if not target:
        return None
    lowered = target.lower()
    if lowered.startswith(SKIP_SCHEMES):
        return None
    if target.startswith("#"):
        return None
    path = unquote(target.split("#", 1)[0]).strip()
    return path or None


def _markdown_files() -> list[Path]:
    skip_parts = {".git", ".pytest_cache", ".venv", "logs"}
    skip_names = {"SPEC_LAB.md"}
    files = []
    for path in ROOT.rglob("*.md"):
        if skip_parts.intersection(path.parts) or path.name in skip_names:
            continue
        files.append(path)
    files.sort()
    return files


def _link_exists(md_file: Path, target: str) -> bool:
    root = ROOT.resolve()
    for base in (md_file.parent, ROOT):
        candidate = (base / target).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if candidate.exists():
            return True
    return False


def test_runbook_has_seven_h2_sections():
    text = RUNBOOK.read_text(encoding="utf-8")
    sections = _h2_sections(text)
    assert [title for title, _ in sections] == list(EXPECTED_H2)
    assert len(sections) == 7


def test_runbook_each_section_has_steps_1_to_4():
    text = RUNBOOK.read_text(encoding="utf-8")
    sections = _h2_sections(text)
    assert len(sections) == 7
    for title, body in sections:
        for n, step_re in enumerate(STEP_RE, start=1):
            assert step_re.search(body), f"{title} missing step {n}"
        assert re.search(r"stop and escalate if", body, re.I), f"{title} missing escalate line"
        assert "rule.id" in body, f"{title} missing Wazuh dashboard filter"
        assert RULE_ID_RE.search(body), f"{title} missing rule id"
        assert any(role in body for role in ROLES), f"{title} missing role placeholder"


def test_runbook_has_all_role_placeholders():
    text = RUNBOOK.read_text(encoding="utf-8")
    missing = [role for role in ROLES if role not in text]
    assert not missing, f"runbook missing roles {missing}"


def test_coverage_map_rule_ids_match_local_rules():
    map_ids = _rule_ids_from_coverage(COVERAGE.read_text(encoding="utf-8"))
    xml_ids = _rule_ids_from_xml(RULES_XML.read_text(encoding="utf-8"))
    assert xml_ids, "local_rules.xml has no rule ids"
    only_map = sorted(map_ids - xml_ids)
    only_xml = sorted(xml_ids - map_ids)
    assert not only_map, f"coverage-map rule ids missing from local_rules.xml: {only_map}"
    assert not only_xml, f"local_rules.xml rule ids missing from coverage-map.md: {only_xml}"
    assert PRIMARY_IDS <= xml_ids
    assert PRIMARY_IDS <= map_ids


def test_no_forbidden_strings_in_docs():
    hits = []
    for path in sorted(DOCS.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        found = FORBID.findall(text)
        if found:
            hits.append(f"{path.relative_to(ROOT)}: {sorted(set(found))}")
    assert not hits, "forbidden strings in docs/: " + "; ".join(hits)


def test_markdown_repo_path_links_resolve():
    missing = []
    for path in _markdown_files():
        body = _strip_fences(path.read_text(encoding="utf-8"))
        for raw in MD_LINK_RE.findall(body):
            target = _link_target(raw)
            if target is None:
                continue
            if _link_exists(path, target):
                continue
            missing.append(f"{path.relative_to(ROOT)} -> {target}")
    assert not missing, "broken markdown repo-path links: " + "; ".join(missing)


def test_policy_files_have_required_sections():
    for path in POLICY_FILES:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        assert len(lines) <= 120, f"{path.name} has {len(lines)} lines (max 120)"
        lower = text.lower()
        missing = [name for name in POLICY_SECTIONS if name not in lower]
        assert not missing, f"{path.name} missing {missing}"
        missing_roles = [role for role in ROLES if role not in text]
        assert not missing_roles, f"{path.name} missing roles {missing_roles}"


def test_quick_reference_card_contents():
    text = QUICK_REF.read_text(encoding="utf-8")
    for rid in sorted(PRIMARY_IDS):
        assert rid in text, f"quick-reference missing {rid}"
    for needle in (
        "SEV-1",
        "SEV-2",
        "SEV-3",
        "wuauclt",
        "usoclient",
        "TiWorker",
        "vssadmin list shadows",
        "wbadmin start backup",
        "rmm_agent",
        "MsMpEng.exe",
        "0x1400",
        "isolate-host.ps1",
        "-Rollback",
    ):
        assert needle in text, f"quick-reference missing {needle!r}"
    missing_roles = [role for role in ROLES if role not in text]
    assert not missing_roles, f"quick-reference missing roles {missing_roles}"
    assert len(text.splitlines()) <= 120, "quick-reference-card is not one page"
