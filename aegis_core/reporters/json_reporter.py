"""
JSON Reporter for AegisSec.
"""

import json
from aegis_core.models import AuditResult


class JSONReporter:
    def __init__(self, result: AuditResult):
        self.result = result

    def render(self) -> str:
        return json.dumps(self.result.to_dict(), indent=2)

    def save(self, filepath: str) -> None:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.render())
