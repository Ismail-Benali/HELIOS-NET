"""HELIOS-NET :: modules/exfil/collector.py
جمع وربط البيانات (findings) من مصادر الحملة.

المسؤولية:
  - يدمج نتائج الوحدات المتفرقة في مستودع واحد منظم.
  - يضمّن الطوابع الزمنية ومعرّفات الحملة للتعقّب.
  - يخصص إخراجًا نهائيًا (JSON/JSONL) جاهزًا للتقرير أو التخزين.
"""

from __future__ import annotations

import json
import time
import uuid


class Collector:
    """تجميع وايجار صحائف الاكتشافات."""

    def __init__(self, campaign_id: str | None = None):
        self.campaign_id = campaign_id or uuid.uuid4().hex
        self._findings: list[dict] = []
        self._dedupe: set[tuple] = set()

    def add(self, finding: dict) -> bool:
        """يضيف اكتشافًا (مع إزالة تكرار بسيط بمعرّف طبيعي)."""
        natural_id = (finding.get("module"), finding.get("host"), finding.get("port"), finding.get("service"))
        if natural_id in self._dedupe:
            return False
        self._dedupe.add(natural_id)
        rec = dict(finding)
        rec.setdefault("ts", time.time())
        rec.setdefault("campaign_id", self.campaign_id)
        self._findings.append(rec)
        return True

    def extend(self, findings: list[dict]) -> int:
        n = 0
        for f in findings:
            n += int(self.add(f))
        return n

    def all(self) -> list[dict]:
        return list(self._findings)

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self._findings, ensure_ascii=False, indent=indent)

    def write(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())
