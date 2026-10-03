"""Emulate Sysmon ProcessAccess and ImageLoad filtering for the exclusion lists."""
from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

SYSMON_XML = Path(__file__).resolve().parents[1] / "sysmon" / "sysmonconfig.xml"
CONDITIONS = {
    "is": lambda v, p: v == p,
    "begin with": lambda v, p: v.startswith(p),
    "end with": lambda v, p: v.endswith(p),
    "contains": lambda v, p: p in v,
}
LSASS = r"C:\Windows\system32\lsass.exe"


def _section(onmatch: str, event_type: str = "ProcessAccess") -> ET.Element:
    root = ET.parse(SYSMON_XML).getroot()
    return root.find(f".//{event_type}[@onmatch='{onmatch}']")


def _field_hits(el: ET.Element, event: dict) -> bool:
    cond = el.get("condition", "is")
    if cond not in CONDITIONS:
        raise ValueError(f"unsupported Sysmon condition {cond!r}")
    value = event.get(el.tag)
    if value is None:
        return False
    return CONDITIONS[cond](value.lower(), (el.text or "").lower())


def _rule_hits(rule: ET.Element, event: dict) -> bool:
    results = [_field_hits(f, event) for f in rule]
    return all(results) if rule.get("groupRelation") == "and" else any(results)


def _section_hits(section: ET.Element, event: dict) -> bool:
    for child in section:
        if child.tag == "Rule":
            if _rule_hits(child, event):
                return True
        elif _field_hits(child, event):
            return True
    return False


def logged(source_image: str, granted: str = "0x1fffff") -> bool:
    event = {"SourceImage": source_image, "TargetImage": LSASS, "GrantedAccess": granted}
    return _section_hits(_section("include"), event) and not _section_hits(
        _section("exclude"), event
    )


@pytest.mark.parametrize(
    "image",
    [
        r"C:\Windows\System32\csrss.exe",
        r"C:\Windows\system32\wininit.exe",
        r"C:\Program Files\Windows Defender\MsMpEng.exe",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe",
        r"C:\Windows\Sysmon64.exe",
    ],
)
def test_real_system_binaries_are_excluded(image):
    assert not logged(image)


@pytest.mark.parametrize(
    "image",
    [
        r"C:\Users\Public\csrss.exe",
        r"C:\Windows\Temp\wininit.exe",
        r"C:\Users\jdoe\AppData\Local\Temp\MsMpEng.exe",
        r"C:\ProgramData\MsMpEng.exe",
        r"C:\Program Files\Windows Defender\Evil\MsMpEng.exe",
        r"C:\Users\jdoe\Downloads\Sysmon64.exe",
        r"C:\Users\jdoe\Desktop\NisSrv.exe",
    ],
)
def test_spoofed_names_in_other_folders_are_logged(image):
    assert logged(image)


def test_no_name_only_source_image_exclusion():
    for child in _section("exclude"):
        if child.tag == "SourceImage":
            assert child.get("condition") == "is", child.text
        if child.tag == "Rule":
            assert child.get("groupRelation") == "and"
            conds = {f.get("condition") for f in child if f.tag == "SourceImage"}
            assert "begin with" in conds, child.get("name")


def image_load_logged(image: str, image_loaded: str) -> bool:
    event = {"Image": image, "ImageLoaded": image_loaded}
    return _section_hits(_section("include", "ImageLoad"), event) and not _section_hits(
        _section("exclude", "ImageLoad"), event
    )


USER_DLL = r"C:\Users\jdoe\AppData\Local\Temp\payload.dll"


@pytest.mark.parametrize(
    "image",
    [
        r"C:\Windows\Sysmon64.exe",
        r"C:\Program Files\Windows Defender\MsMpEng.exe",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe",
        r"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe",
        r"C:\Windows\system32\wuauclt.exe",
        r"C:\Windows\System32\UsoClient.exe",
        r"C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.19041.4585_none_7e5bd4ef4ef10b48\TiWorker.exe",
    ],
)
def test_image_load_real_binaries_are_excluded(image):
    assert not image_load_logged(image, USER_DLL)


@pytest.mark.parametrize(
    "image",
    [
        r"C:\Users\jdoe\AppData\Local\Temp\MsMpEng.exe",
        r"C:\ProgramData\MsMpEng.exe",
        r"C:\Users\Public\TiWorker.exe",
        r"C:\Windows\Temp\wuauclt.exe",
        r"C:\Users\jdoe\Downloads\Sysmon64.exe",
        r"C:\Users\jdoe\Desktop\UsoClient.exe",
        r"C:\Program Files\Windows Defender\Evil\NisSrv.exe",
    ],
)
def test_image_load_spoofed_names_are_logged(image):
    assert image_load_logged(image, USER_DLL)


def test_no_name_only_image_load_exclusion():
    for child in _section("exclude", "ImageLoad"):
        if child.tag == "Image":
            assert child.get("condition") == "is", child.text
        if child.tag == "Rule":
            assert child.get("groupRelation") == "and"
            conds = {f.get("condition") for f in child if f.tag == "Image"}
            assert "begin with" in conds, child.get("name")
