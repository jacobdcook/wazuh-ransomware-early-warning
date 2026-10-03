import re
from pathlib import Path

import yaml

from tests.rule_engine import PRIMARY_HI, PRIMARY_LO

ATOMIC_DIR = Path(__file__).parent / "atomic"
REQUIRED_FIELDS = (
    "id",
    "name",
    "technique",
    "atomic_ref",
    "command",
    "expected_rule_ids",
    "expected_level",
    "cleanup",
    "notes",
)
PRIMARY_IDS = set(range(PRIMARY_LO, PRIMARY_HI + 1))
TC_IDS = [f"TC-{n:02d}" for n in range(1, 13)]


def _load_cases():
    files = sorted(ATOMIC_DIR.glob("TC-*.yaml"))
    cases = []
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        cases.append((path, data))
    return cases


def test_every_yaml_parses():
    cases = _load_cases()
    assert [p.stem for p, _ in cases] == TC_IDS
    for path, data in cases:
        assert isinstance(data, dict), path.name
        missing = [k for k in REQUIRED_FIELDS if k not in data]
        assert not missing, f"{path.name} missing {missing}"
        assert data["id"] == path.stem
        assert isinstance(data["name"], str) and data["name"].strip()
        assert isinstance(data["technique"], str) and data["technique"].strip()
        assert isinstance(data["atomic_ref"], str) and data["atomic_ref"].strip()
        assert isinstance(data["command"], str) and data["command"].strip()
        assert isinstance(data["cleanup"], str) and data["cleanup"].strip()
        assert isinstance(data["notes"], str) and data["notes"].strip()
        assert isinstance(data["expected_rule_ids"], list)
        assert all(isinstance(rid, int) for rid in data["expected_rule_ids"])
        assert isinstance(data["expected_level"], int)


def test_expected_rule_ids_exist_in_local_rules(rules):
    present = {r.id for r in rules}
    for path, data in _load_cases():
        missing = [rid for rid in data["expected_rule_ids"] if rid not in present]
        assert not missing, f"{path.name} expected unknown rule ids {missing}"


def test_every_primary_rule_expected_by_at_least_one_tc():
    seen = set()
    for _, data in _load_cases():
        seen.update(data["expected_rule_ids"])
    missing = sorted(PRIMARY_IDS - seen)
    assert not missing, f"primary rules never expected by a TC: {missing}"


def test_tc07_expects_empty_list():
    by_id = {data["id"]: data for _, data in _load_cases()}
    tc07 = by_id["TC-07"]
    assert tc07["expected_rule_ids"] == []
    assert tc07["expected_level"] == 0


def test_tc06_simulator_target_is_watched_by_burst_rule(rules):
    by_id = {data["id"]: data for _, data in _load_cases()}
    tc06 = by_id["TC-06"]
    assert 100121 in tc06["expected_rule_ids"]
    targets = {
        re.search(r"--target\s+(\S+)", tc06[key]).group(1)
        for key in ("command", "cleanup")
    }
    assert len(targets) == 1
    target = targets.pop()
    support = next(r for r in rules if r.id == 100120)
    pattern = dict(support.fields)["win.eventdata.targetFilename"]
    for name in ("file_0000.txt", r".sim_backup\file_0000.txt"):
        assert re.search(pattern, rf"{target}\{name}"), f"100120 misses {target}"
    readme = (Path(__file__).parents[1] / "simulator" / "README.md").read_text()
    assert f"--target {target} " in readme
