"""Tests for MITRE ATT&CK and Sigma-style rule metadata."""

import re
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
DETECTION_ENGINE_ROOT = ROOT / "detection-engine"
sys.path.insert(0, str(DETECTION_ENGINE_ROOT))

import detection_engine.rules as detection_rules  # noqa: E402


MITRE_MAPPING = ROOT / "docs" / "mitre-attack-mapping.md"
SIGMA_DIR = ROOT / "rules" / "sigma"
REQUIRED_SIGMA_FIELDS = {
    "title",
    "id",
    "rule_id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
    "detection",
    "fields",
    "falsepositives",
    "level",
    "tags",
}
EXPECTED_SIGMA_RULES = {
    "auth_brute_force.yml": "AUTH-BRUTE-FORCE-001",
    "web_sqli_pattern.yml": "WEB-SQLI-PATTERN-001",
}


def implemented_rule_ids() -> set[str]:
    """Return internal rule IDs exported by the Python detection module."""

    return {
        value
        for name, value in vars(detection_rules).items()
        if name.endswith("_RULE_ID") and isinstance(value, str)
    }


def read_mitre_rule_ids() -> set[str]:
    """Extract internal rule IDs from the MITRE mapping table."""

    text = MITRE_MAPPING.read_text(encoding="utf-8")
    return set(re.findall(r"\| `([A-Z0-9-]+)` \|", text))


def load_sigma_rule(file_name: str) -> dict:
    """Parse a Sigma-style YAML file and return its mapping."""

    with (SIGMA_DIR / file_name).open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    assert isinstance(data, dict)
    return data


def test_every_detection_rule_has_mitre_mapping():
    mapped = read_mitre_rule_ids()
    assert implemented_rule_ids() <= mapped


def test_mitre_mapping_rows_include_official_attack_links():
    text = MITRE_MAPPING.read_text(encoding="utf-8")
    for rule_id in implemented_rule_ids():
        row = next(line for line in text.splitlines() if f"`{rule_id}`" in line)
        assert "https://attack.mitre.org/techniques/" in row


def test_expected_sigma_rule_files_exist():
    assert {path.name for path in SIGMA_DIR.glob("*.yml")} == set(EXPECTED_SIGMA_RULES)


def test_sigma_rules_have_required_fields_and_valid_rule_ids():
    known_rule_ids = implemented_rule_ids()
    for file_name, expected_rule_id in EXPECTED_SIGMA_RULES.items():
        text = (SIGMA_DIR / file_name).read_text(encoding="utf-8")
        rule = load_sigma_rule(file_name)
        assert "\t" not in text
        assert REQUIRED_SIGMA_FIELDS <= set(rule)
        assert rule["status"] == "experimental"
        assert rule["author"] == "n1wo"
        assert rule["rule_id"] == expected_rule_id
        assert rule["rule_id"] in known_rule_ids
        assert isinstance(rule["logsource"], dict)
        assert isinstance(rule["detection"], dict)
        assert isinstance(rule["fields"], list)
        assert isinstance(rule["falsepositives"], list)
        assert isinstance(rule["tags"], list)
        assert rule["detection"].get("condition")


def test_sigma_rules_use_project_log_fields_and_attack_tags():
    for file_name in EXPECTED_SIGMA_RULES:
        rule = load_sigma_rule(file_name)
        assert "event_type" in str(rule["detection"])
        assert "source_ip" in rule["fields"]
        assert "username" in rule["fields"]
        assert any(str(tag).startswith("attack.") for tag in rule["tags"])
