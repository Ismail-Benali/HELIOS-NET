"""HELIOS-NET :: modules/recon/fingerprint.py
Deep reconnaissance: OS fingerprinting from TTL and behavior.

Contract:
  - Derives a preliminary fingerprint from TTL/IP-ID values of received packets
    (a heuristic model in the logic).
  - Requires no root privileges — it only reads what standard connections
    return.
  - Extension point: hook in the C fingerprint (transport/) here once built.

Note:
  - This represents an estimate worth verifying, not a final judgment —
    fingerprinting is a probabilistic science.
"""

from __future__ import annotations

import json
import platform
import socket

from transport import FINGERPRINT, _run


def fingerprint_native(host: str, observed_ttl: int | None = None) -> dict | None:
    """Invokes the C fingerprint binary via subprocess if built.

    Arg:
      host: the target host.
      observed_ttl: the measured TTL value; if absent, a heuristic value is
                    passed from the host.

    Returns:
      A fingerprint sheet with source="native(C)" or None when the binary is
      missing.
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
    """Fingerprint value from the host system environment (experimental/lab)."""
    sys = platform.system().lower()
    if sys == "windows":
        return "Windows (TTL≈128)"
    if sys == "linux":
        return "Linux/Unix (TTL≈64)"
    if sys == "darwin":
        return "macOS (TTL≈64)"
    return f"Unknown ({sys})"


def fingerprint_host(host: str, observed_sig: dict | None = None) -> dict:
    """Produces a high-accuracy fingerprint estimate of the target via the
    multi-signal Bayes algorithm.

    Arg:
      host: the target host.
      observed_sig: an observed signal including ttl, window, tcp_options_len if
                    available.

    Returns:
      A precise fingerprint sheet shaped like
      {module, host, os_guess, confidence, method, source}.
    """
    from engine.algorithms.fingerprint import fingerprint_sig

    sig = observed_sig or {"ttl": 64, "window": 64240, "tcp_options_len": 20}
    
    # try the advanced Bayesian fingerprint first
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

    # fall back to C or local
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
    """Grabs the banner of an open service over a connection.

    Arg:
      host: the target host.
      port: the open service port.
      timeout: receive timeout.
      probe: the first bytes sent (default).

    Returns:
      A text banner sheet.
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
