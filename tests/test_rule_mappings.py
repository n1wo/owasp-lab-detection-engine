"""Tests for MITRE ATT&CK and Sigma-style rule metadata."""

import re
import sys
from pathlib import Path


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


def top_level_yaml_fields(text: str) -> set[str]:
    """Extract simple top-level YAML keys without requiring a YAML dependency."""

    return {
        line.split(":", 1)[0]
        for line in text.splitlines()
        if line and not line.startswith((" ", "-")) and ":" in line
    }


def field_value(text: str, field: str) -> str:
    """Return the scalar value for a simple top-level YAML field."""

    match = re.search(rf"^{re.escape(field)}:\s*(.+)$", text, flags=re.MULTILINE)
    return match.group(1).strip() if match else ""


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
        assert "\t" not in text
        assert REQUIRED_SIGMA_FIELDS <= top_level_yaml_fields(text)
        assert field_value(text, "status") == "experimental"
        assert field_value(text, "author") == "n1wo"
        assert field_value(text, "rule_id") == expected_rule_id
        assert field_value(text, "rule_id") in known_rule_ids


def test_sigma_rules_use_project_log_fields_and_attack_tags():
    for file_name in EXPECTED_SIGMA_RULES:
        text = (SIGMA_DIR / file_name).read_text(encoding="utf-8")
        assert "event_type:" in text
        assert "condition:" in text
        assert "source_ip" in text
        assert "username" in text
        assert "attack." in text
