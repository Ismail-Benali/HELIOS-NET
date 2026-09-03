"""HELIOS-NET :: engine/verdict.py
قواعد «إذا/إذن» ذكية تصنّف المخاطر والقرارات الأولية.

المسؤولية:
  - تحويل صحائف الحقائق (findings) إلى حكم (verdict) بوزن وخطورة.
  - القواعد قابلة للتوسّع (plugins) وقابلة للاختبار، لا منطق مبعثر في الوحدات.
  - يبقى «الحكم» قائمًا على الحقائق المسجّلة، لا على تخمين خارج المشهد.

ملاحظة أمنية ثابتة:
  - هذا المكوّن يحلل مشهدًا داخليًا/مفوّضًا. أي استخدام خارج نطاق مفوَّض
    مسؤولية المستخدم، والقواعد هنا لا تجيز ولا تستهدف شيئًا سوى التصنيف.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Rule:
    """قاعدة تصنيف واحدة."""
    name: str
    weight: float                 # وزن الخطورة (0..1)
    test: Callable[[dict], bool]  # هل تنطبق على هذا الاكتشاف؟
    note: str = ""

    def applies(self, finding: dict) -> bool:
        try:
            return bool(self.test(finding))
        except Exception:
            return False


@dataclass
class Verdict:
    """النتيجة المصنّفة لاكتشاف واحد."""
    finding: dict
    rules_hit: list[str] = field(default_factory=list)
    max_weight: float = 0.0

    def to_dict(self) -> dict:
        return {
            "source": self.finding.get("module", "unknown"),
            "target": self.finding.get("target"),
            "finding": self.finding,
            "rules_hit": self.rules_hit,
            "max_weight": round(self.max_weight, 3),
            "severity": "high" if self.max_weight >= 0.7 else ("medium" if self.max_weight >= 0.4 else "low"),
        }


class VerdictEngine:
    """محرّك القواعد — كل قاعدة=مكوّن plugin قابل للنمو."""

    def __init__(self, rules: list[Rule] | None = None):
        self._rules: list[Rule] = list(rules or [])

    def add_rule(self, rule: Rule) -> None:
        self._rules.append(rule)

    def load_plugins(self, registry: dict[str, Callable[[], Rule]]) -> None:
        """يستورد قواعد من سجل plugins/ — قابل للتوسّع دون تعديل النواة."""
        for name, factory in registry.items():
            self._rules.append(factory())

    def judge(self, finding: dict) -> Verdict:
        v = Verdict(finding=finding)
        for r in self._rules:
            if r.applies(finding):
                v.rules_hit.append(r.name)
                v.max_weight = max(v.max_weight, r.weight)
        return v

    def judge_all(self, findings: list[dict]) -> list[Verdict]:
        return [self.judge(f) for f in findings]


# ----------------------------------------------------------------------------
# قواعد افتراضية جاهزة — تُحمَّل افتراضيًا.
# ----------------------------------------------------------------------------
def default_rules() -> list[Rule]:
    return [
        Rule(
            name="open_service",
            weight=0.3,
            test=lambda f: bool(f.get("open") is True or f.get("port") is not None),
            note="خدمة مفتوحة مشبوهة/جديرة بالفحص.",
        ),
        Rule(
            name="unpatched_hint",
            weight=0.6,
            test=lambda f: any(k in str(f.get("service", "")).lower() for k in ("old", "deprecated", "eol")),
            note="مؤشر على إصدار قديم غير محدّث.",
        ),
        Rule(
            name="admin_interface",
            weight=0.7,
            test=lambda f: any(k in str(f.get("service", "")).lower() for k in ("admin", "management", "ssh", "rdp")),
            note="واجهة إدارة/تحكم — أولوية الفحص.",
        ),
        Rule(
            name="default_credentials_hint",
            weight=0.8,
            test=lambda f: any(k in str(f.get("finding_note", "")).lower() for k in ("default", "factory", "weak")),
            note="مؤشر على بيانات اعتماد افتراضية/ضعيفة.",
        ),
    ]
