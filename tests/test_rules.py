import re

from tests.rule_engine import evaluate, evaluate_frequency, match

PRIMARY_IDS = list(range(100100, 100112))
SEV_FOR_LEVEL = {14: "sev1", 15: "sev1", 12: "sev2", 13: "sev2", 10: "sev3", 11: "sev3"}
EXPECTED = {
    100100: (14, "sev1", "T1003.001"),
    100101: (14, "sev1", "T1490"),
    100102: (15, "sev1", "T1486"),
    100103: (12, "sev2", "T1021.002"),
    100104: (12, "sev2", "T1569.002"),
    100105: (12, "sev2", "T1547.001"),
    100106: (12, "sev2", "T1053.005"),
    100107: (12, "sev2", "T1543.003"),
    100108: (13, "sev2", "T1562.001"),
    100109: (13, "sev2", "T1070.001"),
    100110: (10, "sev3", "T1059.001"),
    100111: (10, "sev3", "T1105"),
}


def _primary(rules):
    return [r for r in rules if r.id in EXPECTED]


def test_twelve_primary_rules_unique_ids_and_mitre(rules):
    primary = _primary(rules)
    assert [r.id for r in primary] == PRIMARY_IDS
    assert len({r.id for r in primary}) == 12
    mitres = []
    for rule in primary:
        assert rule.mitre_ids, f"{rule.id} missing mitre id"
        mitres.extend(rule.mitre_ids)
    assert len(set(mitres)) == 12
    for rule in primary:
        level, _sev, technique = EXPECTED[rule.id]
        assert rule.level == level
        assert technique in rule.mitre_ids


def test_level_sev_mapping(rules):
    for rule in _primary(rules):
        band = SEV_FOR_LEVEL[rule.level]
        _, sev, _ = EXPECTED[rule.id]
        assert band == sev
        assert sev in rule.groups
        if sev == "sev1":
            assert 14 <= rule.level <= 15
        elif sev == "sev2":
            assert 12 <= rule.level <= 13
        else:
            assert 10 <= rule.level <= 11


def test_every_primary_rule_fires_on_a_sample(rules, sample_events):
    fired = set()
    for event in sample_events:
        hit = evaluate(event, rules)
        if hit is not None:
            fired.add(hit.id)
    missing = set(PRIMARY_IDS) - fired
    assert not missing, f"no sample fired {sorted(missing)}"


def test_expected_rule_id_on_samples(rules, sample_events):
    for event in sample_events:
        expected = event.get("expect", {}).get("rule_id")
        hit = evaluate(event, rules)
        got = None if hit is None else hit.id
        assert got == expected, (
            f"{event.get('_tc')}/{event.get('_file')} expected {expected} got {got}"
        )


def test_tc07_zero_alerts(rules, sample_events_by_tc):
    benign = sample_events_by_tc["TC-07"]
    assert len(benign) >= 10
    for event in benign:
        assert event.get("expect", {}).get("rule_id") is None
        assert evaluate(event, rules) is None
        for rule in _primary(rules):
            assert not match(rule, event)


def test_malicious_tcs_have_at_least_two_firing_events(sample_events_by_tc):
    for n in range(1, 13):
        tc = f"TC-{n:02d}"
        if tc == "TC-07":
            continue
        firing = [e for e in sample_events_by_tc[tc] if e.get("expect", {}).get("rule_id")]
        assert len(firing) >= 2, f"{tc} needs >= 2 malicious events"


def test_every_field_regex_compiles(rules):
    for rule in rules:
        for name, pattern in rule.fields:
            assert name
            re.compile(pattern)


def test_no_empty_description(rules):
    for rule in rules:
        assert rule.description, f"{rule.id} has an empty description"


def test_frequency_same_field_grouping(rules):
    def write_event(computer, n):
        return {
            "win": {
                "system": {
                    "eventID": "11",
                    "providerName": "Microsoft-Windows-Sysmon",
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "computer": computer,
                },
                "eventdata": {
                    "image": r"C:\Users\jdoe\AppData\Local\Temp\locker.exe",
                    "targetFilename": rf"C:\Users\jdoe\Documents\file{n}.docx",
                },
            }
        }

    burst = next(r for r in rules if r.id == 100121)
    same_host = [write_event("WS-FIN-02", i) for i in range(30)]
    ids = {r.id for r in evaluate_frequency(same_host, rules)}
    assert burst.id in ids
    ids_short = {r.id for r in evaluate_frequency(same_host[:29], rules)}
    assert burst.id not in ids_short
    split = [write_event("WS-FIN-02", i) for i in range(15)]
    split += [write_event("WS-OPS-07", i) for i in range(15)]
    ids_split = {r.id for r in evaluate_frequency(split, rules)}
    assert burst.id not in ids_split
