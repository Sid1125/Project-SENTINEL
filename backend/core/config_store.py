import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


DEFAULT_CONFIG: Dict[str, Any] = {
    "llm_host": "http://localhost:11434",
    "llm_model": "phi:latest",
    "scan_timeout": 30,
    "auto_scan_interval": 1800,
    "alert_notifications": True,
    "auto_block_critical": True,
    "auto_quarantine": False,
    "notify_on_high": True,
    "traffic_interface": "auto",
    "traffic_autostart": False,
    "dns_sinkhole_enabled": False,
    "dns_sinkhole_redirect_ip": "0.0.0.0",
    "dns_blocked_domains": [],
    "dns_resolver_enabled": False,
    "dns_resolver_host": "127.0.0.1",
    "dns_resolver_port": 5353,
    "dns_upstream_server": "8.8.8.8",
    "enforcement_mode": "active",
    "containment_allowed_segments": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
    "containment_allowed_destinations": [],
    "containment_segments": [
        "users:192.168.1.0/24",
        "iot:192.168.50.0/24",
        "guest:192.168.75.0/24",
    ],
    "containment_segment_policies": [
        "users:restricted_network",
        "iot:segment_isolation:192.168.1.1,8.8.8.8",
        "guest:full_isolation",
    ],
    "containment_segment_conditions": [
        "iot:critical_ports:critical_service_isolation",
        "guest:trusted_device:restricted_network",
        "users:failed_logins:defensive_lockdown",
        "iot:scan_burst:full_isolation",
    ],
    "containment_segment_thresholds": [
        "users:failed_logins:3:600:defensive_lockdown",
        "iot:port_scan_pattern:2:600:full_isolation",
    ],
}


def _import_system_config():
    try:
        from models.schemas import SystemConfig
    except ModuleNotFoundError:
        from backend.models.schemas import SystemConfig
    return SystemConfig


class ConfigStore:
    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory

    def get(self, key: str, default: Any = None) -> Any:
        db = self.db_session_factory()
        try:
            SystemConfig = _import_system_config()
            entry = db.query(SystemConfig).filter_by(key=key).first()
            if not entry:
                return DEFAULT_CONFIG.get(key, default)
            return self._deserialize(entry.value, DEFAULT_CONFIG.get(key, default))
        except Exception as exc:
            if "no such table" not in str(exc).lower():
                logger.error(f"Failed to read config key '{key}': {exc}")
            return DEFAULT_CONFIG.get(key, default)
        finally:
            db.close()

    def get_many(self, keys: Optional[list[str]] = None) -> Dict[str, Any]:
        keys = keys or list(DEFAULT_CONFIG.keys())
        return {key: self.get(key, DEFAULT_CONFIG.get(key)) for key in keys}

    def set(self, key: str, value: Any, description: str = "") -> Any:
        db = self.db_session_factory()
        try:
            SystemConfig = _import_system_config()
            entry = db.query(SystemConfig).filter_by(key=key).first()
            serialized = self._serialize(value)
            if entry:
                entry.value = serialized
                if description:
                    entry.description = description
            else:
                db.add(SystemConfig(key=key, value=serialized, description=description or key))
            db.commit()
            return value
        except Exception as exc:
            logger.error(f"Failed to persist config key '{key}': {exc}")
            db.rollback()
            raise
        finally:
            db.close()

    def set_many(self, values: Dict[str, Any]):
        db = self.db_session_factory()
        try:
            SystemConfig = _import_system_config()
            existing = {entry.key: entry for entry in db.query(SystemConfig).filter(SystemConfig.key.in_(values.keys())).all()}
            for key, value in values.items():
                serialized = self._serialize(value)
                if key in existing:
                    existing[key].value = serialized
                else:
                    db.add(SystemConfig(key=key, value=serialized, description=key))
            db.commit()
        except Exception as exc:
            logger.error(f"Failed to persist config batch: {exc}")
            db.rollback()
            raise
        finally:
            db.close()

    def _serialize(self, value: Any) -> str:
        return json.dumps(value)

    def _deserialize(self, raw: str, default: Any) -> Any:
        try:
            return json.loads(raw)
        except Exception:
            return default
