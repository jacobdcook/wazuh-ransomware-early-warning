import json
from pathlib import Path

import pytest

from tests.rule_engine import RULES_XML, parse_rules

SAMPLES = Path(__file__).parent / "sample_events"


@pytest.fixture(scope="session")
def rules():
    return parse_rules(RULES_XML)


@pytest.fixture(scope="session")
def sample_events():
    events = []
    for path in sorted(SAMPLES.glob("TC-*/*.json")):
        chunk = json.loads(path.read_text())
        if not isinstance(chunk, list):
            raise ValueError(f"{path} must be a JSON list")
        for ev in chunk:
            ev["_tc"] = path.parent.name
            ev["_file"] = path.name
            events.append(ev)
    return events


@pytest.fixture(scope="session")
def sample_events_by_tc(sample_events):
    by_tc = {}
    for ev in sample_events:
        by_tc.setdefault(ev["_tc"], []).append(ev)
    return by_tc
