"""One report contract, used by the API, fixtures and agent validation tools."""

import json
import re
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema/report.schema.json").read_text())
FORMATS = FormatChecker()


@FORMATS.checks("date-time", raises=ValueError)
def date_time(value):
    # jsonschema's optional format extras must never silently disable timestamp checks.
    if not isinstance(value, str):
        return True  # The schema's type validator handles this case.
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})", value
    ):
        return False
    stamp = datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
    return stamp.tzinfo is not None


VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FORMATS)


def validate_report(report):
    VALIDATOR.validate(report)
    ids = [check["id"] for check in report["checks"]]
    if len(ids) != len(set(ids)):
        raise ValueError("Each check id must occur only once")
