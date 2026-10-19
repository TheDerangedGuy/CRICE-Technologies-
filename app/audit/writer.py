"""
app/audit/writer.py – append-only audit log writer.

This is the ONLY place that creates AuditLog rows.
There is no update or delete path anywhere in the codebase.
Postgres trigger blocks UPDATE and DELETE at the database level.
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
    from_stage: Optional[str] = None,
    to_stage: Optional[str] = None,
    allowed: bool = True,
    detail: Optional[dict] = None,
    ip: Optional[str] = None,
    commit: bool = False,
) -> AuditLog:
    """
    Append one entry to the audit log.

    If commit=True, commits immediately (crucial for persisting denied transitions
    before raising an HTTPException).
    Otherwise flushes so the row gets an id without committing.
    """
    entry = AuditLog(
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        user_id=user_id,
        case_id=case_id,
        action=action,
        from_stage=from_stage,
        to_stage=to_stage,
        allowed=allowed,
        detail=detail,
        ip=ip,
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    else:
        db.flush()
    return entry
