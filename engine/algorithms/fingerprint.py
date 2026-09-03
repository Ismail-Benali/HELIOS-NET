"""HELIOS-NET :: engine/algorithms/fingerprint.py
Swappable fingerprint algorithm family.

Shows how "identification" evolves from a fixed TTL rule into multiple models:
  - ttl_flat:    the current fixed estimator (fast, low context).
  - bayes:       probabilistic discrimination combining several signals
                 (TTL + Window + IP ID) via pseudo-log-likelihood — smarter,
                 marginally heavier.

Each model is registered in the central registry and switched by name. The core
is never touched.
"""

from __future__ import annotations

from . import register_algo


# Primary signals per family (approximate values for an educational/lab setting).
# Structure: family -> {ttl_mean, ttl_spread, window, tcp_options_len}
PROFILES = {
    "linux": {"ttl_mean": 64, "ttl_spread": 6, "window": 64240, "tcp_options_len": 20},
    "windows": {"ttl_mean": 128, "ttl_spread": 8, "window": 65535, "tcp_options_len": 40},
    "router": {"ttl_mean": 255, "ttl_spread": 4, "window": 16384, "tcp_options_len": 12},
}


def _ttl_flat(sig: dict) -> dict:
    """Fixed estimator — the common TTL function."""
    ttl = sig.get("ttl", 64)
    if ttl <= 64:
        fam = "linux"
    elif ttl <= 128:
        fam = "windows"
    else:
        fam = "router"
    return {"guess": fam, "confidence": 1.0, "method": "ttl_flat"}


def _bayes(sig: dict) -> dict:
    """Pseudo-Bayesian discrimination over multiple signals.

    Computes a score for each family from the deviation of the observed signals
    against its profile, then ranks the most plausible family. Combines: TTL,
    window, and TCP options length.
    """
    ttl = sig.get("ttl", 64)
    window = sig.get("window", 0)
    opt_len = sig.get("tcp_options_len", 0)

    best_fam, best_score = None, float("-inf")
    for fam, p in PROFILES.items():
        # TTL deviation feeds a pseudo-log-likelihood (a closer signal is more informative).
        ttl_dev = abs(ttl - p["ttl_mean"]) / max(1, p["ttl_spread"])
        win_dev = 0 if window == 0 else (window - p["window"]) ** 2 / 1e6
        opt_dev = 0 if opt_len == 0 else abs(opt_len - p["tcp_options_len"]) / 10.0
        score = -(ttl_dev + win_dev + opt_dev)
        if score > best_score:
            best_score, best_fam = score, fam

    # Approximate confidence: the closer the signals, the higher the confidence.
    confidence = 1.0 if best_score >= -1.0 else round(1.0 / (1.0 - best_score), 3)
    return {"guess": best_fam, "confidence": min(confidence, 1.0), "method": "bayes"}


register_algo("fingerprint", "ttl_flat", _ttl_flat, default=True)
register_algo("fingerprint", "bayes", _bayes)


def fingerprint_sig(sig: dict, kind: str = "ttl_flat") -> dict:
    """The public gateway — invoked by the recon engine when switching models."""
    from . import get_algo
    try:
        algo = get_algo("fingerprint", kind)
    except Exception:
        algo = _ttl_flat
    return algo(sig)
