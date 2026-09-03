"""HELIOS-NET :: core/state.py
إدارة حالة الحملة (campaign state) والمخزن الموزّع القابل للتبديل.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Protocol

STATUS_CHOICES = {"idle", "planning", "scanning", "analyzing", "executing", "done", "failed", "aborted"}


class CampaignState:
    def __init__(self, target: str, campaign_id: str | None = None, meta: dict | None = None):
        if not target or not str(target).strip():
            raise ValueError("target cannot be empty")
        self.campaign_id = campaign_id or uuid.uuid4().hex
        self.target = str(target).strip()
        self.status = "idle"
        self.meta = meta or {}
        self.created_at = time.time()
        self.updated_at = self.created_at
        self.completed_at: float | None = None

    def to_dict(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "target": self.target,
            "status": self.status,
            "meta": self.meta,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CampaignState":
        obj = cls(target=data["target"], campaign_id=data.get("campaign_id"), meta=data.get("meta", {}))
        obj.status = data.get("status", "idle")
        obj.created_at = data.get("created_at", time.time())
        obj.updated_at = data.get("updated_at", obj.created_at)
        obj.completed_at = data.get("completed_at")
        return obj

    def transition(self, new_status: str) -> None:
        if new_status not in STATUS_CHOICES:
            raise ValueError(f"invalid status: {new_status!r}")
        if new_status == self.status:
            return
        self.status = new_status
        self.updated_at = time.time()
        if new_status in ("done", "failed", "aborted"):
            self.completed_at = self.updated_at


class StorageBackend(Protocol):
    """عقد المخزن الموزّع للقابلية للتوسّع (Local / Redis / Postgres)."""
    def save(self, state: CampaignState) -> None: ...
    def load(self, campaign_id: str) -> CampaignState: ...
    def load_all(self) -> list[CampaignState]: ...
    def delete(self, campaign_id: str) -> None: ...
    def log_event(self, state: CampaignState, event: str, **payload) -> None: ...
    def read_log(self, campaign_id: str) -> list[dict]: ...


class StateStore:
    """مخزن الحالة المحلي القائم على ملفات JSONL المضمونة."""

    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.campaigns_dir = self.data_dir / "campaigns"
        self.campaigns_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _state_path(self, campaign_id: str) -> Path:
        return self.campaigns_dir / f"{campaign_id}.json"

    def _log_path(self, campaign_id: str) -> Path:
        return self.campaigns_dir / f"{campaign_id}.log.jsonl"

    def save(self, state: CampaignState) -> None:
        with self._lock:
            tmp = self._state_path(state.campaign_id).with_suffix(".json.tmp")
            final = self._state_path(state.campaign_id)
            tmp.write_text(json.dumps(state.to_dict(), indent=2), encoding="utf-8")
            tmp.replace(final)

    def load(self, campaign_id: str) -> CampaignState:
        p = self._state_path(campaign_id)
        if not p.exists():
            raise FileNotFoundError(f"no campaign {campaign_id!r}")
        return CampaignState.from_dict(json.loads(p.read_text(encoding="utf-8")))

    def load_all(self) -> list[CampaignState]:
        out = []
        for p in sorted(self.campaigns_dir.glob("*.json")):
            if p.name.endswith(".tmp"):
                continue
            try:
                out.append(CampaignState.from_dict(json.loads(p.read_text(encoding="utf-8"))))
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
        return out

    def delete(self, campaign_id: str) -> None:
        with self._lock:
            for p in (self._state_path(campaign_id), self._log_path(campaign_id)):
                if p.exists():
                    p.unlink()

    def log_event(self, state: CampaignState, event: str, **payload) -> None:
        record = {"ts": time.time(), "campaign_id": state.campaign_id, "event": event, **payload}
        with self._lock:
            with self._log_path(state.campaign_id).open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")

    def read_log(self, campaign_id: str) -> list[dict]:
        p = self._log_path(campaign_id)
        if not p.exists():
            return []
        out = []
        with p.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out
