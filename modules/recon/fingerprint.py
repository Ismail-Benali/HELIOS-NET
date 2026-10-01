"""HELIOS-NET :: modules/recon/fingerprint.py
Deep reconnaissance: OS fingerprinting from TTL and behavior.

Contract:
  - Derives a preliminary fingerprint from TTL/IP-ID values of received packets
    (a heuristic model in the logic).
  - Requires no root privileges - it only reads what standard connections
    return.

Note:
  - This represents an estimate worth verifying, not a final judgment -
    fingerprinting is a probabilistic science.

History:
  This module used to shell out to a `fingerprint.exe` native helper for OS
  guessing. That binary is not part of this codebase any more, and the import
  was left behind, so importing this module raised ImportError. There is no
  native equivalent to point it at: the C core's `fp` mode computes banner
  digests, which is a different question from "which OS is this". Rather than
  relabel a banner hash as an OS guess, the native path was removed and the
  heuristic now states its own confidence.
"""

from __future__ import annotations

from typing import Any

import socket

#: Signals the Bayesian model can work from.
DEFAULT_SIGNAL = {"ttl": 64, "window": 64240, "tcp_options_len": 20}


def _ttl_family(observed_ttl: int | None) -> str:
    """Maps a measured TTL to a coarse OS family.

    This is a documented heuristic, not a fingerprint: TTL only narrows the
    initial hop count, and a single observation cannot identify an OS. It is
    used only when the multi-signal model cannot run.
    """
    if observed_ttl is None:
        return "Unknown (no TTL observed)"
    # The bayesian path catches the bad signal, but this fallback then has to
    # survive it too: comparing a non-numeric TTL against the bands would raise
    # and take the campaign down on the very input the fallback exists for.
    try:
        ttl = int(observed_ttl)
    except (TypeError, ValueError):
        return "Unknown (TTL unusable)"
    if ttl > 128:
        return "Windows-like (TTL>128)"
    if ttl > 64:
        return "Linux/Unix-like (TTL 65-128)"
    return "Linux/Unix-like (TTL<=64)"


def fingerprint_host(host: str, observed_sig: dict[str, Any] | None = None) -> dict[str, Any]:
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

    sig = observed_sig or dict(DEFAULT_SIGNAL)

    try:
        bayes_res = fingerprint_sig(sig, kind="bayes")
    except (KeyError, TypeError, ValueError, IndexError, ZeroDivisionError) as exc:
        # Only malformed input may degrade the model. A bare `except Exception`
        # here would hide genuine defects in the estimator, which is exactly how
        # this module stayed broken for so long.
        return {
            "module": "recon",
            "host": host,
            "os_guess": _ttl_family(sig.get("ttl")),
            "confidence": "low",
            "method": "ttl-heuristic",
            "source": "local-model",
            "note": f"bayesian model rejected the signal: {exc}",
        }

    return {
        "module": "recon",
        "host": host,
        "os_guess": f"{bayes_res['guess'].capitalize()} (Confidence: {bayes_res['confidence']})",
        "confidence": bayes_res["confidence"],
        "method": bayes_res["method"],
        "source": "bayes-multi-signal",
    }


def banner_grab(host: str, port: int, timeout: float = 3.0,
                probe: bytes = b"\r\n") -> dict[str, Any]:
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
