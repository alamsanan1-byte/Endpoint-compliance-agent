"""Usage: python -m scripts.validate_report path/to/report.json"""

import json
import sys
from pathlib import Path

from collector.contract import validate_report


def main():
    for name in sys.argv[1:]:
        report = json.loads(Path(name).read_text(encoding="utf-8-sig"))
        validate_report(report)
        print(f"Valid: {name} ({len(report['checks'])} checks)")


if __name__ == "__main__":
    main()
