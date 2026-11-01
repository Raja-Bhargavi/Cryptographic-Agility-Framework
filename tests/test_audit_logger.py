
import json

import pytest

from core.audit_logger import log_negotiation


def test_log_negotiation_creates_file(tmp_path):
    log_path = tmp_path / "audit.json"

    record = {
        "scenario": "Test Scenario",
        "negotiation_status": "SUCCESS",
        "selected_algorithm": "ML-KEM-768",
    }

    result = log_negotiation(record, log_path)

    assert result == log_path
    assert log_path.exists()

    with log_path.open("r", encoding="utf-8") as file:
        records = json.load(file)

    assert len(records) == 1
    assert records[0]["scenario"] == "Test Scenario"
    assert records[0]["negotiation_status"] == "SUCCESS"
    assert "timestamp" in records[0]


def test_log_negotiation_appends_records(tmp_path):
    log_path = tmp_path / "audit.json"

    log_negotiation({"scenario": "Scenario 1"}, log_path)
    log_negotiation({"scenario": "Scenario 2"}, log_path)

    with log_path.open("r", encoding="utf-8") as file:
        records = json.load(file)

    assert len(records) == 2
    assert records[0]["scenario"] == "Scenario 1"
    assert records[1]["scenario"] == "Scenario 2"


def test_log_negotiation_rejects_invalid_json(tmp_path):
    log_path = tmp_path / "audit.json"
    log_path.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid JSON"):
        log_negotiation({"scenario": "Test"}, log_path)


def test_log_negotiation_rejects_non_list_json(tmp_path):
    log_path = tmp_path / "audit.json"
    log_path.write_text('{"scenario": "Existing"}', encoding="utf-8")

    with pytest.raises(ValueError, match="must contain a JSON list"):
        log_negotiation({"scenario": "Test"}, log_path)
