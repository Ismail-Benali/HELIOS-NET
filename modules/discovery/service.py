"""HELIOS-NET :: modules/discovery/service.py
استطلاع: اكتشاف خدمات ومنافذ.

العقد:
  - يلمس الهدف (مفوّض/مملوك) ويُخرج صحيفة خدمات موحّدة.
  - لا يعتمد على أدوات خارجية في النواة — فقط socket قياسي.
  - أي توسّع (nmap-parser...) يُضاف كوحدة جانبية لا كفرع من هذا.
"""

from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor

from transport import RAWSYNC, _run

# منافذ شائعة للملاحظة السريعة — قابلة للتوسيع من الخارج.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt",
}


def discover_ports(host: str, ports: list[int] | None = None,
                   timeout: float = 2.0, max_workers: int = 64) -> list[dict]:
    """يكشف المنافذ المفتوحة على مضيف في المختبر.

    Args:
      host: مضيف الهدف (يجب أن يكون مفوّضًا/مملوكًا).
      ports: قائمة منافذ؛ يُلجأ إلى COMMON_PORTS إن لم تُعطَ.
      timeout: مهلة الاتصال بالثواني.
      max_workers: عدد موازي لعمليات الفحص.

    Returns:
      قائمة اكتشافات بنمط {module, host, port, service, open}.
    """
    ports = ports or list(COMMON_PORTS.keys())
    results: list[dict] = []
    lock = __import__("threading").Lock()

    def probe(p: int) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, p))
            open_port = True
        except OSError:
            open_port = False
        finally:
            s.close()
        if open_port:
            with lock:
                results.append({
                    "module": "discovery",
                    "host": host,
                    "port": p,
                    "service": COMMON_PORTS.get(p, "unknown"),
                    "open": True,
                })

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        list(pool.map(probe, ports))

    results.sort(key=lambda d: d["port"])
    return results


def native_syn_probe(host: str, port: int, timeout: float = 5.0) -> dict:
    """يمسح المنفذ عبر نواة Go (rawsync) بالاستماع الحقيقي لرد SYN-ACK.

    يعتمد على مخرج JSON الصادر من راو-سوكيت:
      - open:     تلقى SYN-ACK.
      - closed:   تلقى RST.
      - filtered: انتهت المهلة أو قيود مقبس خام.

    عند تعثّر الصلاحيات أو غياب الثنائي، يسقط أمنًا إلى المقبس القياسي.
    """
    ok, out = _run(RAWSYNC, [host, str(port)], timeout=timeout)
    if not ok:
        # سقوط أمن إلى المقبس القياسي عند قيود النظام
        return discover_ports(host, ports=[port], timeout=2.0) and {"module": "discovery", "host": host, "port": port, "open": True, "source": "fallback(socket)"} or {"module": "discovery", "host": host, "port": port, "open": False, "source": "fallback(socket)"}

    # محاولة قراءة مخرج JSON من الثنائي
    try:
        data = json.loads(out.strip())
        state = data.get("state", "filtered")
        is_open = (state == "open")
        return {
            "module": "discovery",
            "host": host,
            "port": port,
            "open": is_open,
            "state": state,
            "source": data.get("source", "native(Go-raw)"),
            "note": data.get("error", "")
        }
    except json.JSONDecodeError:
        # Fallback قياسي
        return {"module": "discovery", "host": host, "port": port, "open": False, "source": "native(Go-raw:parse-error)", "raw_out": out}
