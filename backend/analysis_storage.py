"""
Filesystem-backed storage for completed analysis reports.

This module intentionally exposes a small repository-like API so it can be
replaced by a database implementation when user accounts are introduced.
"""

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from config import ANALYSIS_STORAGE_DIR, ANALYSIS_STORAGE_ENABLED, ANALYSIS_STORAGE_MAX_ITEMS
from models import AnalysisResult, StoredAnalysisSummary


def _storage_dir() -> Path:
    """Return the configured storage directory and create it on demand."""
    path = Path(ANALYSIS_STORAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _report_path(analysis_id: str) -> Path:
    """Resolve a report path without allowing path traversal."""
    safe_id = "".join(char for char in analysis_id if char.isalnum() or char == "-")
    return _storage_dir() / f"{safe_id}.json"


def _utc_now() -> str:
    """Return a stable UTC timestamp for stored reports."""
    return datetime.now(timezone.utc).isoformat()


def _dump_model(result: AnalysisResult) -> dict:
    """Serialize a Pydantic model across Pydantic v1/v2 style APIs."""
    if hasattr(result, "model_dump"):
        return result.model_dump(mode="json")
    return result.dict()


def _summary_from_result(result: AnalysisResult) -> StoredAnalysisSummary:
    """Build lightweight metadata used by the homepage reload list."""
    return StoredAnalysisSummary(
        analysis_id=result.analysis_id or "",
        filename=result.filename,
        created_at=result.analyzed_at or _utc_now(),
        original_size_bytes=result.original_size_bytes or 0,
        total_packets=result.summary.total_packets,
        total_bytes=result.summary.total_bytes,
        duration_seconds=result.summary.duration_seconds,
        stored_packet_rows=len(result.packets),
        owner_user_id=result.owner_user_id,
    )


def _prune_old_reports() -> None:
    """Keep the newest configured reports and remove older JSON files."""
    files = sorted(_storage_dir().glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    for path in files[ANALYSIS_STORAGE_MAX_ITEMS:]:
        try:
            path.unlink()
        except OSError:
            continue


def save_analysis(result: AnalysisResult, original_size_bytes: int, owner_user_id: Optional[str] = None) -> AnalysisResult:
    """Persist an analysis report and return the same report with storage metadata."""
    if not ANALYSIS_STORAGE_ENABLED:
        return result

    result.analysis_id = result.analysis_id or str(uuid.uuid4())
    result.analyzed_at = result.analyzed_at or _utc_now()
    result.original_size_bytes = original_size_bytes
    result.owner_user_id = owner_user_id or result.owner_user_id

    path = _report_path(result.analysis_id)
    tmp_path = path.with_suffix(".json.tmp")
    payload = _dump_model(result)
    payload["_storage_summary"] = _summary_from_result(result).model_dump(mode="json")

    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, separators=(",", ":"), default=str)
    os.replace(tmp_path, path)
    _prune_old_reports()
    return result


def update_analysis(analysis_id: str, result: AnalysisResult) -> Optional[AnalysisResult]:
    """Replace an existing persisted report while preserving its stable id."""
    if not ANALYSIS_STORAGE_ENABLED:
        return None
    existing = load_analysis(analysis_id)
    if existing is None:
        return None

    result.analysis_id = analysis_id
    result.analyzed_at = existing.analyzed_at
    result.original_size_bytes = result.original_size_bytes or existing.original_size_bytes or 0
    return save_analysis(result, result.original_size_bytes or 0)


def update_user_analysis(analysis_id: str, result: AnalysisResult, owner_user_id: str) -> Optional[AnalysisResult]:
    """Replace a persisted report only when it belongs to the current user."""
    existing = load_analysis(analysis_id, owner_user_id=owner_user_id)
    if existing is None:
        return None
    result.analysis_id = analysis_id
    result.analyzed_at = existing.analyzed_at
    result.original_size_bytes = result.original_size_bytes or existing.original_size_bytes or 0
    result.owner_user_id = owner_user_id
    return save_analysis(result, result.original_size_bytes or 0, owner_user_id=owner_user_id)


def list_analyses(owner_user_id: Optional[str] = None) -> List[StoredAnalysisSummary]:
    """Return saved report metadata ordered from newest to oldest."""
    if not ANALYSIS_STORAGE_ENABLED:
        return []

    summaries: List[StoredAnalysisSummary] = []
    for path in sorted(_storage_dir().glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            summary = payload.get("_storage_summary")
            if summary:
                item = StoredAnalysisSummary(**summary)
                if owner_user_id is None or item.owner_user_id == owner_user_id:
                    summaries.append(item)
                continue
            result = AnalysisResult(**payload)
            item = _summary_from_result(result)
            if owner_user_id is None or item.owner_user_id == owner_user_id:
                summaries.append(item)
        except Exception:
            continue
    return summaries


def load_analysis(analysis_id: str, owner_user_id: Optional[str] = None) -> Optional[AnalysisResult]:
    """Load one persisted report by id."""
    if not ANALYSIS_STORAGE_ENABLED:
        return None

    path = _report_path(analysis_id)
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    payload.pop("_storage_summary", None)
    result = AnalysisResult(**payload)
    if owner_user_id is not None and result.owner_user_id != owner_user_id:
        return None
    return result
