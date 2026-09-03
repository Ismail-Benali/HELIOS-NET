"""HELIOS-NET :: engine/algorithms/fingerprint.py
فئة خوارزميات البصمة القابلة للتبديل.

توضح كيف يرتقي «التعريف» من قاعدة TTL ثابتة إلى نماذج متعددة:
  - ttl_flat:     التقدير الثابت الحالي (سريع، قليل السياق).
  - bayes:        تمييز احتمالي يدمج عدة دلائل (TTL + Window + IP ID)
                  عبر الاحتمال اللوغاريتمي الزائف — أذكى، أثقل هامشيًا.

كل نموذج يسجَّل في السجل المركزي، ويُتبدَّل بالاسم. لا تُمس النواة.
"""

from __future__ import annotations

from . import register_algo


# دلائل أولية لكل عائلة (قيم تقريبية لبيئة تعليمية/مختبرية).
# البنية: family -> {ttl_mean, ttl_spread, window, tcp_options_len}
PROFILES = {
    "linux": {"ttl_mean": 64, "ttl_spread": 6, "window": 64240, "tcp_options_len": 20},
    "windows": {"ttl_mean": 128, "ttl_spread": 8, "window": 65535, "tcp_options_len": 40},
    "router": {"ttl_mean": 255, "ttl_spread": 4, "window": 16384, "tcp_options_len": 12},
}


def _ttl_flat(sig: dict) -> dict:
    """التقدير الثابت — دالة TTL الشائعة."""
    ttl = sig.get("ttl", 64)
    if ttl <= 64:
        fam = "linux"
    elif ttl <= 128:
        fam = "windows"
    else:
        fam = "router"
    return {"guess": fam, "confidence": 1.0, "method": "ttl_flat"}


def _bayes(sig: dict) -> dict:
    """تمييز بايزي زائف على دلائل متعددة.

    يحسب درجة لكل عائلة من انحراف الدلائل المرصودة عن ملفها،
    ثم يرجّح بأصدق عائلة. يدمج: TTL، window، طول خيارات TCP.
    """
    ttl = sig.get("ttl", 64)
    window = sig.get("window", 0)
    opt_len = sig.get("tcp_options_len", 0)

    best_fam, best_score = None, float("-inf")
    for fam, p in PROFILES.items():
        # انحراف TTL مضى إلى لوغاريتم احتمال زائف (أقرب لدليل أدقّ فائدة).
        ttl_dev = abs(ttl - p["ttl_mean"]) / max(1, p["ttl_spread"])
        win_dev = 0 if window == 0 else (window - p["window"]) ** 2 / 1e6
        opt_dev = 0 if opt_len == 0 else abs(opt_len - p["tcp_options_len"]) / 10.0
        score = -(ttl_dev + win_dev + opt_dev)
        if score > best_score:
            best_score, best_fam = score, fam

    # ثقة تقريبية: كلما كانت الدلائل أقرب كانت الثقة أعلى.
    confidence = 1.0 if best_score >= -1.0 else round(1.0 / (1.0 - best_score), 3)
    return {"guess": best_fam, "confidence": min(confidence, 1.0), "method": "bayes"}


register_algo("fingerprint", "ttl_flat", _ttl_flat, default=True)
register_algo("fingerprint", "bayes", _bayes)


def fingerprint_sig(sig: dict, kind: str = "ttl_flat") -> dict:
    """البوابة العامّة — يستدعيها محرّك recon عند تبديل النموذج."""
    from . import get_algo
    try:
        algo = get_algo("fingerprint", kind)
    except Exception:
        algo = _ttl_flat
    return algo(sig)
