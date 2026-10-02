"""
app/audit/writer.py – append-only audit log writer.

This is the ONLY place that creates AuditLog rows.
There is no update or delete path anywhere in the codebase.
"""
import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.models import AuditLog


def log_action(
    db: Session,
    *,
    action: str,
    user_id: Optional[int] = None,
    case_id: Optional[int] = None,
    detail: Optional[dict] = None,
    ip: Optional[str] = None,
) -> AuditLog:
    """
    Append one entry to the audit log.

    Always call db.commit() after this (or rely on the caller's commit)
    to persist the entry.  Uses db.flush() so the row gets an id without
    committing, allowing the caller to batch-commit several writes.
    """
    entry = AuditLog(
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        user_id=user_id,
        case_id=case_id,
        action=action,
        detail=detail,
        ip=ip,
    )
    db.add(entry)
    db.flush()
    return entry
