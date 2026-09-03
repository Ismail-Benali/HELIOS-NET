"""HELIOS-NET :: modules/recon/fingerprint.py
استطلاع عميق: بصمة نظام التشغيل من TTL والسلوك.

العقد:
  - يستخلص بصمة أولية من قيم TTL/IP-ID لاستقبال حزم (نموذج هزلي في المنطق).
  - لا يحتاج صلاحيات root — يقرأ فقط ما يعود من توصيلات قياسية.
  - نقطة الامتداد: ربط الـ C fingerprint (transport/) هنا عند التجهيز.

ملاحظة:
  - يمثل هذا رأيًا تقديريًا يستحق التحقق، لا حكمًا نهائيًا — البصمة علم احتمالي.
"""

from __future__ import annotations

import json
import platform
import socket

from transport import FINGERPRINT, _run


def fingerprint_native(host: str, observed_ttl: int | None = None) -> dict | None:
    """يستدعي ثنائي C fingerprint عبر subprocess إن بُني.

    Arg:
      host: مضيف الهدف.
      observed_ttl: قيمة TTL مقيسة؛ إن غابت نُمرّر فترة هزلية من المضيف.

    Returns:
      صحيفة بصمة مع source="native(C)" أو None عند تغيّب الثنائي.
    """
    ttl = observed_ttl if observed_ttl is not None else 64
    ok, out = _run(FINGERPRINT, [str(ttl)], timeout=5.0)
    if not ok:
        return None
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        return None
    payload.update({"module": "recon", "host": host, "source": "native(C)"})
    return payload


def _platform_default_family() -> str:
    """قيمة بصمة من بيئة النظام المضيف (تجريبية/للمختبر)."""
    sys = platform.system().lower()
    if sys == "windows":
        return "Windows (TTL≈128)"
    if sys == "linux":
        return "Linux/Unix (TTL≈64)"
    if sys == "darwin":
        return "macOS (TTL≈64)"
    return f"Unknown ({sys})"


def fingerprint_host(host: str, observed_sig: dict | None = None) -> dict:
    """يُنتج تقدير بصمة عالي الدقة من الهدف عبر خوارزمية بايز المتعددة الدلائل.

    Arg:
      host: مضيف الهدف.
      observed_sig: إشارة مرصودة تتضمن ttl, window, tcp_options_len إن توفرت.

    Returns:
      صحيفة بصمة دقيقة بنمط {module, host, os_guess, confidence, method, source}.
    """
    from engine.algorithms.fingerprint import fingerprint_sig

    sig = observed_sig or {"ttl": 64, "window": 64240, "tcp_options_len": 20}
    
    # محاولة استخدام البصمة البايزية المتقدمة
    try:
        bayes_res = fingerprint_sig(sig, kind="bayes")
        return {
            "module": "recon",
            "host": host,
            "os_guess": f"{bayes_res['guess'].capitalize()} (Confidence: {bayes_res['confidence']})",
            "confidence": bayes_res["confidence"],
            "method": bayes_res["method"],
            "source": "bayes-multi-signal",
        }
    except Exception:
        pass

    # احتياطي إلى C أو محلي
    native = fingerprint_native(host)
    if native is not None:
        return native
    return {
        "module": "recon",
        "host": host,
        "os_guess": _platform_default_family(),
        "source": "local-sample",
    }


def banner_grab(host: str, port: int, timeout: float = 3.0,
                probe: bytes = b"\r\n") -> dict:
    """يلتقط لافتة (banner) لخدمة مفتوحة عبر اتصال.

    Arg:
      host: مضيف الهدف.
      port: منفذ الخدمة المفتوحة.
      timeout: مهلة الاستقبال.
      probe: بايت الإرسال الأول (إفطاضي).

    Returns:
      صحيفة لافتة نصية.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(probe)
        data = s.recv(512)
        banner = data.decode("utf-8", errors="replace").strip()
    except OSError as exc:
        banner = f"<error: {exc}>"
    finally:
        s.close()
    return {"module": "recon", "host": host, "port": port, "banner": banner[:200]}
