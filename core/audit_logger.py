
"""Persistent JSON audit logging for cryptographic negotiation."""

import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG_PATH = PROJECT_ROOT / "logs" / "negotiation_audit.json"


def log_negotiation(record, log_path=DEFAULT_LOG_PATH):
    """Append one negotiation record to a JSON audit file."""

    log_path = Path(log_path)

    # Create the logs directory if it does not exist.
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Read existing records.
    if log_path.exists():
        try:
            with log_path.open("r", encoding="utf-8") as file:
                records = json.load(file)

            if not isinstance(records, list):
                raise ValueError("Audit log must contain a JSON list.")

        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Existing audit log contains invalid JSON: {log_path}"
            ) from exc
    else:
        records = []

    # Add a UTC timestamp to the new record.
    new_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **record,
    }

    records.append(new_record)

    # Write the updated records.
    with log_path.open("w", encoding="utf-8") as file:
        json.dump(records, file, indent=4)

    return log_path
