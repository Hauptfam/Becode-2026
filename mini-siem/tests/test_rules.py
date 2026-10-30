import pytest

from mini_siem.engine import run_rule
from mini_siem.rules import Rule, RuleError, compile_condition, find_regular_window, load_rules, match_field


def rule(**detection):
    return Rule.from_dict({"id": "T-1", "title": "test", "severity": "low", "detection": detection})


@pytest.mark.parametrize(("expr", "values", "expected"), [
    ("a and not b", {"a": True, "b": False}, True),
    ("a and not b", {"a": True, "b": True}, False),
    ("a or b and c", {"a": False, "b": True, "c": False}, False),   # "and" binds tighter than "or"
    ("(a or b) and c", {"a": True, "b": False, "c": True}, True),
    ("not (a or b)", {"a": False, "b": False}, True),
])
def test_condition_logic(expr, values, expected):
    assert compile_condition(expr, set(values))(values) is expected


@pytest.mark.parametrize("expr", ["a and", "a b", "(a", "unknown", "a or or b"])
def test_invalid_conditions(expr):
    with pytest.raises(RuleError):
        compile_condition(expr, {"a", "b"})


@pytest.mark.parametrize(("spec", "expected", "result"), [
    ("cmd|contains", "\\downloads\\", True),          # case-insensitive
    ("cmd|startswith", "WSCRIPT", True),
    ("cmd|endswith", ".js", True),
    ("cmd|re", r"\\Downloads\\.*\.pdf\.js$", True),
    ("cmd", ["cscript.exe", "wscript.exe c:\\users\\me\\downloads\\a.pdf.js"], True),   # list = any
    ("cmd|contains|all", ["wscript", "downloads"], True),
    ("cmd|contains|all", ["wscript", "powershell"], False),
    ("ip|cidr", "10.0.0.0/8", True),
    ("ip|cidr", "192.168.0.0/16", False),
    ("count|gte", 3, True),
    ("count|gt", 3, False),
    ("signed", False, True),
    ("signed", True, False),
    ("missing", None, True),
    ("missing|exists", False, True),
    ("cmd|exists", True, True),
])
def test_field_modifiers(spec, expected, result):
    event = {"cmd": "wscript.exe C:\\Users\\me\\Downloads\\a.pdf.js", "ip": "10.1.2.3", "count": 3, "signed": False}
    assert match_field(event, spec, expected) is result


def test_signed_false_does_not_match_missing_field():
    assert match_field({}, "signed", False) is False


def test_list_field_values_match_any_element():
    assert match_field({"urls": ["https://a.example", "https://evil.example/x"]}, "urls|contains", "evil")


def test_rule_validation():
    with pytest.raises(RuleError):
        rule(selection={"x|nonsense": 1}, condition="selection")
    with pytest.raises(RuleError):
        rule(selection={"x": 1})                                   # no condition
    with pytest.raises(RuleError):
        Rule.from_dict({"id": "T", "title": "t", "severity": "extreme", "detection": {"s": {}, "condition": "s"}})


def test_logsource_restricts_matching():
    r = Rule.from_dict({"id": "T", "title": "t", "severity": "low", "logsource": "edr",
                        "detection": {"s": {"x": 1}, "condition": "s"}})
    assert r.matches({"source": "edr", "x": 1}) and not r.matches({"source": "proxy", "x": 1})


def beacons(times, host="WS1"):
    return [{"id": f"e{i}", "ts": t, "timestamp": f"t{i}", "host": host, "dst_ip": "9.9.9.9", "dst_port": 443,
             "source": "firewall", "action": "allow"} for i, t in enumerate(times)]


def test_regular_window_found_for_beacons_not_for_irregular_traffic():
    regular = beacons([0, 60, 121, 180, 240, 301, 360])
    irregular = beacons([0, 7, 280, 302, 810, 1152])
    assert len(find_regular_window(regular, 6, 900, 5)) == 7
    assert find_regular_window(irregular, 6, 900, 5) is None
    assert find_regular_window(regular[:5], 6, 900, 5) is None      # not enough events


def test_aggregation_rule_groups_per_host():
    r = Rule.from_dict({"id": "B", "title": "beacon", "severity": "high", "logsource": "firewall",
                        "detection": {"s": {"action": "allow"}, "condition": "s"},
                        "aggregation": {"group_by": ["host", "dst_ip"], "min_count": 6, "timeframe": 900, "max_jitter": 5}})
    events = beacons([0, 60, 120, 180, 240, 300], "WS1") + beacons([0, 60, 120], "WS2")
    alerts = run_rule(r, events)
    assert [a["host"] for a in alerts] == ["WS1"]
    assert len(alerts[0]["event_ids"]) == 6


def test_builtin_rules_are_valid_and_mapped_to_attack():
    rules = load_rules()
    assert len(rules) == 8
    for r in rules:
        assert r.mitre and all(m["id"].startswith("T") and m["tactic"] for m in r.mitre), r.id
        assert r.description and r.falsepositives, r.id
