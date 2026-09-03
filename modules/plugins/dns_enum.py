"""HELIOS-NET :: modules/plugins/dns_enum.py
وحدة توسّعية مثال: استطلاع DNS (تحليل النطاقات الفرعية).

تُسجَّل ذاتيًا عبر زخرفة @module — تُكتشف وتُحمَّل بـ modules.core.discover
بلا تعديل أي سجل يدوي. هذا مثال حيّ على كيف يُضاف استراتيجية جديدة
إلى النظام في سطرين فقط.
"""

from __future__ import annotations

import socket

from modules.core import module


def _subdomains(domain: str, wordlist: list[str],
                timeout: float = 2.0) -> list[dict]:
    """يلمس نطاقات فرعية قياسية ويحتفظ بالمستحق منها.

    Arg:
      domain: النطاق (مفوّض/مملوك).
      wordlist: كلمات تحويل النطاقات الفرعية.
      timeout: مهلة الاستعلام (جودة SQLite-أصلية، لا مكتبة).

    Returns:
      قائمة نطاقات فرعية مستحقة.
    """
    hits = []
    for w in wordlist:
        fqdn = f"{w}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            hits.append({"subdomain": fqdn, "resolves": True})
        except OSError:
            continue
    return hits


@module("dns_enum", kind="discovery", wordlist=("www", "admin", "api", "mail", "dev"))
def dns_runner(step, ctx) -> dict:
    """ينفّذ تعداد نطاقات فرعية على هدف الخطوة."""
    wordlist = step.params.get("wordlist", ("www", "admin", "api", "mail", "dev"))
    found = _subdomains(step.target, wordlist=list(wordlist))
    # تسجيل الاكتشافات الخام في سياق الحملة المشترك.
    ctx.setdefault("findings", []).extend(
        {"module": "dns_enum", "host": step.target, "subdomain": h["subdomain"]}
        for h in found
    )
    return {"module": "dns_enum", "host": step.target,
            "resolved": [h["subdomain"] for h in found], "count": len(found)}
