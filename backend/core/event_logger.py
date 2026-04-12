import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    from api.event_stream import publish_sync
except ModuleNotFoundError:
    from backend.api.event_stream import publish_sync


def _import_security_event():
    try:
        from models.schemas import SecurityEvent
    except ModuleNotFoundError:
        from backend.models.schemas import SecurityEvent
    return SecurityEvent


class SecurityEventLogger:
    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory

    def record(
        self,
        event_type: str,
        source: str,
        title: str,
        message: str = "",
        severity: str = "info",
        target_ip: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        db = self.db_session_factory()
        try:
            SecurityEvent = _import_security_event()
            entry = SecurityEvent(
                event_type=event_type,
                source=source,
                title=title,
                message=message,
                severity=severity,
                target_ip=target_ip,
                event_metadata=metadata or {},
            )
            db.add(entry)
            db.commit()
            db.refresh(entry)
            publish_sync(
                "security_event",
                {
                    "id": entry.id,
                    "event_type": entry.event_type,
                    "source": entry.source,
                    "title": entry.title,
                    "message": entry.message,
                    "severity": entry.severity,
                    "target_ip": entry.target_ip,
                    "created_at": entry.created_at.isoformat() if entry.created_at else None,
                    "metadata": dict(entry.event_metadata or {}),
                },
            )
        except Exception as exc:
            if "no such table" not in str(exc).lower():
                logger.error(f"Failed to record security event '{event_type}': {exc}")
            db.rollback()
        finally:
            db.close()
