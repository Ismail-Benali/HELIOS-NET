"""HELIOS-NET :: core/mutation_engine.py
Autonomous Self-Healing & Tactical Mutation Engine.

Monitors target anomaly responses (Honeypots, Tarpits, WAF traps),
wipes local operational footprints securely, mutates encryption keys and
network signatures, and consumes standardized error envelopes to adapt
tactics automatically (e.g. pivot from direct_syscalls to memory_loader).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

from core.error_envelope import (
    TACTIC_FALLBACK,
    ERR_EDR_BLOCKED,
    ERR_WAF_TRAP,
    ERR_MODULE_MISSING,
    ERR_BINARY_MISSING,
)


class MutationEngine:
    """Automated self-healing and tactical mutation engine."""

    # Tactics that the engine may pivot between when an alarm is raised.
    TACTICS = (
        "direct_syscalls",
        "memory_loader",
        "fingerprint",
        "evasion",
        "indirect_syscalls",
    )

    def __init__(self, state_dir: str | Path):
        self.state_dir = Path(state_dir)
        self.mutation_generation = 1
        self.current_tactic = "direct_syscalls"
        self.tactic_history: list[str] = []

    def detect_trap(self, response_latency: float, http_status: int) -> bool:
        """Detects if a response indicates a honeypot, tarpit, or WAF trap."""
        if response_latency > 5.0 or http_status == 999:
            return True
        return False

    # ------------------------------------------------------------------
    # Tactic adaptation driven by standardized error envelopes
    # ------------------------------------------------------------------
    def adapt_to_envelope(self, envelope: Dict[str, Any]) -> Optional[str]:
        """Consumes a standardized error envelope and returns the new tactic to pivot to.

        Returns None when no pivot is required.
        """
        if not envelope:
            return None

        code = envelope.get("code")
        previous_tactic = envelope.get("module") or self.current_tactic

        if code in (ERR_EDR_BLOCKED, ERR_WAF_TRAP):
            new_tactic = TACTIC_FALLBACK.get(previous_tactic)
            if new_tactic and new_tactic != self.current_tactic:
                self.tactic_history.append(
                    f"{previous_tactic}->{new_tactic}@{self.mutation_generation}"
                )
                self.current_tactic = new_tactic
                return new_tactic
        return None

    def select_tactical_target(self, envelope: Dict[str, Any]) -> str:
        """Resolves the next tactic based on the envelope, mutating identity when needed."""
        new_tactic = self.adapt_to_envelope(envelope)
        if new_tactic:
            self.mutation_generation += 1
            return new_tactic
        return self.current_tactic

    def trigger_self_destruct_and_mutate(self) -> dict:
        """Wipes local footprints, mutates generation and keys, and creates new identity."""
        self.mutation_generation += 1
        
        # 1. Secure wiping of temporary state logs
        shredded_files = 0
        if self.state_dir.exists():
            for f in self.state_dir.glob("*.tmp"):
                try:
                    f.write_bytes(os.urandom(f.stat().st_size))
                    f.unlink()
                    shredded_files += 1
                except Exception:
                    pass

        # 2. Generate new polymorphic mutation key
        new_mutation_key = os.urandom(32).hex()

        return {
            "status": "MUTATED",
            "generation": self.mutation_generation,
            "traces_shredded": shredded_files,
            "new_mutation_key": new_mutation_key[:12] + "...",
            "action": "Redirecting orchestrator to an alternate route."
        }
