import ipaddress
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    from core.config_store import ConfigStore
    from core.event_logger import SecurityEventLogger
    from core.firewall_adapters import FirewallAdapter, get_default_firewall_adapter, get_firewall_adapter_catalog
    from core.system_integration import is_running_as_admin
except ModuleNotFoundError:
    from backend.core.config_store import ConfigStore
    from backend.core.event_logger import SecurityEventLogger
    from backend.core.firewall_adapters import FirewallAdapter, get_default_firewall_adapter, get_firewall_adapter_catalog
    from backend.core.system_integration import is_running_as_admin

logger = logging.getLogger(__name__)

try:
    from api.event_stream import publish_sync
except ModuleNotFoundError:
    from backend.api.event_stream import publish_sync


def _import_schema_model(name: str):
    try:
        import models.schemas as schemas
    except ModuleNotFoundError:
        import backend.models.schemas as schemas
    return getattr(schemas, name)


class AutoDefenseEngine:
    def __init__(self, db_session, activity_logger, firewall_adapter: Optional[FirewallAdapter] = None):
        self.get_db = db_session
        self.activity_logger = activity_logger
        self.firewall_adapter = firewall_adapter or get_default_firewall_adapter()
        self.config_store = ConfigStore(db_session) if db_session else None
        self.event_logger = SecurityEventLogger(db_session) if db_session else None
        self.defense_rules = self._load_defense_rules()
        self.playbooks = self._load_playbooks()

    def _load_defense_rules(self) -> Dict[str, Any]:
        rules = {
            "auto_block_critical": True,
            "auto_quarantine": False,
            "notify_on_high": True,
            "block_after_failed_logins": 5,
            "max_risk_score_for_auto_block": 80,
            "default_block_expiry_minutes": 240,
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
        if self.config_store:
            rules.update(self.config_store.get_many(list(rules.keys())))
        return rules

    def _normalize_network_allowlist(self, values: Optional[List[str]]) -> List[str]:
        normalized: List[str] = []
        for value in values or []:
            candidate = str(value).strip()
            if not candidate:
                continue
            try:
                normalized.append(str(ipaddress.ip_network(candidate, strict=False)))
            except ValueError:
                logger.warning(f"Ignoring invalid containment network allowlist entry: {candidate}")
        return sorted(set(normalized))

    def _normalize_destination_allowlist(self, values: Optional[List[str]]) -> List[str]:
        normalized: List[str] = []
        for value in values or []:
            candidate = str(value).strip()
            if not candidate:
                continue
            try:
                normalized.append(str(ipaddress.ip_address(candidate)))
                continue
            except ValueError:
                pass
            try:
                normalized.append(str(ipaddress.ip_network(candidate, strict=False)))
            except ValueError:
                logger.warning(f"Ignoring invalid containment destination allowlist entry: {candidate}")
        return sorted(set(normalized))

    def _containment_allowlists(self) -> Dict[str, List[str]]:
        return {
            "allowed_networks": self._normalize_network_allowlist(
                self.defense_rules.get("containment_allowed_segments", [])
            ),
            "allowed_destinations": self._normalize_destination_allowlist(
                self.defense_rules.get("containment_allowed_destinations", [])
            ),
        }

    def _append_decision_trace(
        self,
        containment: Dict[str, Any],
        stage: str,
        outcome: str,
        detail: str,
        priority: int,
    ) -> Dict[str, Any]:
        trace = list(containment.get("decision_trace") or [])
        trace.append({
            "stage": stage,
            "outcome": outcome,
            "detail": detail,
            "priority": priority,
            "recorded_at": datetime.utcnow().isoformat(),
        })
        containment["decision_trace"] = trace
        return containment

    def _apply_profile_to_containment(
        self,
        containment: Dict[str, Any],
        profile: str,
        *,
        segment: Optional[Dict[str, str]] = None,
        port_set: Optional[set] = None,
        allowed_destinations: Optional[List[str]] = None,
        allowed_networks: Optional[List[str]] = None,
        policy_name: Optional[str] = None,
        condition_name: Optional[str] = None,
        summary: Optional[str] = None,
        trace_stage: Optional[str] = None,
        trace_detail: Optional[str] = None,
        trace_priority: Optional[int] = None,
    ) -> Dict[str, Any]:
        normalized_allowed_destinations = self._normalize_destination_allowlist(allowed_destinations)
        normalized_allowed_networks = self._normalize_network_allowlist(allowed_networks)
        containment["profile"] = profile
        if policy_name is not None:
            containment["policy_name"] = policy_name
        if condition_name is not None:
            containment["condition_name"] = condition_name
        if summary is not None:
            containment["summary"] = summary

        if profile == "critical_service_isolation":
            containment["scope"] = "critical_services"
            containment["ports"] = sorted({port for port in (port_set or set()) if port in {445, 3389}}) or [445, 3389]
            containment["allowed_networks"] = []
            containment["allowed_destinations"] = []
        elif profile == "segment_isolation":
            containment["scope"] = "network_segment"
            containment["ports"] = []
            containment["allowed_networks"] = normalized_allowed_networks or ([segment["network"]] if segment else [])
            containment["allowed_destinations"] = normalized_allowed_destinations
        elif profile in {"full_isolation", "defensive_lockdown"}:
            containment["scope"] = "all_traffic"
            containment["ports"] = []
            containment["allowed_networks"] = []
            containment["allowed_destinations"] = []
        else:
            containment["scope"] = "lan_traffic"
            containment["ports"] = []
            containment["allowed_networks"] = normalized_allowed_networks
            containment["allowed_destinations"] = normalized_allowed_destinations

        if trace_stage and trace_detail and trace_priority is not None:
            self._append_decision_trace(
                containment,
                trace_stage,
                profile,
                trace_detail,
                trace_priority,
            )
        return containment

    def _normalize_segments(self, values: Optional[List[str]]) -> List[Dict[str, str]]:
        normalized: List[Dict[str, str]] = []
        for value in values or []:
            candidate = str(value).strip()
            if not candidate or ":" not in candidate:
                continue
            name, raw_network = candidate.split(":", 1)
            name = name.strip()
            raw_network = raw_network.strip()
            if not name or not raw_network:
                continue
            try:
                normalized.append({
                    "name": name,
                    "network": str(ipaddress.ip_network(raw_network, strict=False)),
                })
            except ValueError:
                logger.warning(f"Ignoring invalid containment segment definition: {candidate}")
        seen = set()
        deduped: List[Dict[str, str]] = []
        for segment in normalized:
            key = (segment["name"], segment["network"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(segment)
        return deduped

    def _segment_for_ip(self, ip: str) -> Optional[Dict[str, str]]:
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError:
            return None

        for segment in self._normalize_segments(self.defense_rules.get("containment_segments", [])):
            if parsed_ip in ipaddress.ip_network(segment["network"], strict=False):
                return segment
        return None

    def _normalize_segment_policies(self, values: Optional[List[str]]) -> Dict[str, Dict[str, Any]]:
        policies: Dict[str, Dict[str, Any]] = {}
        valid_profiles = {"restricted_network", "segment_isolation", "full_isolation", "critical_service_isolation", "defensive_lockdown"}
        for value in values or []:
            candidate = str(value).strip()
            if not candidate or ":" not in candidate:
                continue
            parts = [part.strip() for part in candidate.split(":")]
            if len(parts) < 2:
                continue
            segment_name, profile = parts[0], parts[1]
            if not segment_name or profile not in valid_profiles:
                continue
            destinations = []
            if len(parts) > 2 and parts[2]:
                destinations = self._normalize_destination_allowlist(parts[2].split(","))
            policies[segment_name] = {
                "profile": profile,
                "allowed_destinations": destinations,
            }
        return policies

    def _policy_for_segment(self, segment_name: Optional[str]) -> Optional[Dict[str, Any]]:
        if not segment_name:
            return None
        return self._normalize_segment_policies(
            self.defense_rules.get("containment_segment_policies", [])
        ).get(segment_name)

    def _normalize_segment_conditions(self, values: Optional[List[str]]) -> Dict[str, List[Dict[str, str]]]:
        conditions: Dict[str, List[Dict[str, str]]] = {}
        valid_profiles = {"restricted_network", "segment_isolation", "full_isolation", "critical_service_isolation", "defensive_lockdown"}
        valid_conditions = {
            "critical_ports",
            "high_risk",
            "trusted_device",
            "failed_logins",
            "scan_burst",
            "malicious_request",
            "honeypot_activity",
        }
        for value in values or []:
            candidate = str(value).strip()
            parts = [part.strip() for part in candidate.split(":")]
            if len(parts) < 3:
                continue
            segment_name, condition_name, profile = parts[0], parts[1], parts[2]
            if not segment_name or condition_name not in valid_conditions or profile not in valid_profiles:
                continue
            conditions.setdefault(segment_name, []).append({
                "condition": condition_name,
                "profile": profile,
            })
        return conditions

    def _normalize_segment_thresholds(self, values: Optional[List[str]]) -> Dict[str, List[Dict[str, Any]]]:
        thresholds: Dict[str, List[Dict[str, Any]]] = {}
        valid_profiles = {"restricted_network", "segment_isolation", "full_isolation", "critical_service_isolation", "defensive_lockdown"}
        for value in values or []:
            candidate = str(value).strip()
            parts = [part.strip() for part in candidate.split(":")]
            if len(parts) < 5:
                continue
            segment_name, trigger_name, count_raw, window_raw, profile = parts[0], parts[1], parts[2], parts[3], parts[4]
            if not segment_name or profile not in valid_profiles:
                continue
            try:
                count = max(1, int(count_raw))
                window_seconds = max(60, int(window_raw))
            except ValueError:
                continue
            thresholds.setdefault(segment_name, []).append({
                "trigger": trigger_name,
                "count": count,
                "window_seconds": window_seconds,
                "profile": profile,
            })
        return thresholds

    def _record_trigger_observation(
        self,
        ip: str,
        trigger_reason: str,
        risk_score: float,
        open_ports: List[int],
        details: Optional[Dict[str, Any]] = None,
    ):
        segment = self._segment_for_ip(ip)
        self._record_event(
            "defense_trigger_observed",
            f"Observed trigger {trigger_reason}",
            f"Observed {trigger_reason} for {ip}",
            severity="warning" if risk_score >= 70 else "info",
            target_ip=ip,
            metadata={
                "trigger_reason": trigger_reason,
                "risk_score": risk_score,
                "open_ports": open_ports,
                "details": details or {},
                "segment_name": segment["name"] if segment else None,
            },
        )

    def _recent_trigger_count(self, segment_name: str, trigger_reason: str, window_seconds: int) -> int:
        if not self.get_db:
            return 0

        db = self.get_db()
        try:
            SecurityEvent = _import_schema_model("SecurityEvent")
            window_start = datetime.utcnow() - timedelta(seconds=window_seconds)
            events = (
                db.query(SecurityEvent)
                .filter(SecurityEvent.event_type == "defense_trigger_observed")
                .filter(SecurityEvent.created_at >= window_start)
                .all()
            )
            count = 0
            for event in events:
                metadata = dict(event.event_metadata or {})
                if metadata.get("segment_name") == segment_name and metadata.get("trigger_reason") == trigger_reason:
                    count += 1
            return count
        except Exception as exc:
            logger.error(f"Failed to count recent trigger history for {segment_name}/{trigger_reason}: {exc}")
            return 0
        finally:
            db.close()

    def _get_device_traits(self, ip: str) -> Dict[str, Any]:
        if not self.get_db:
            return {"is_trusted": False, "status": None}

        db = self.get_db()
        try:
            NetworkDevice = _import_schema_model("NetworkDevice")
            device = db.query(NetworkDevice).filter_by(ip_address=ip).first()
            if not device:
                return {"is_trusted": False, "status": None}
            return {
                "is_trusted": bool(device.is_trusted),
                "status": device.status,
                "vendor": device.vendor,
                "hostname": device.hostname,
            }
        except Exception as exc:
            logger.error(f"Failed to load device traits for {ip}: {exc}")
            return {"is_trusted": False, "status": None}
        finally:
            db.close()

    def _apply_segment_condition_overrides(
        self,
        containment: Dict[str, Any],
        segment: Dict[str, str],
        risk_score: float,
        open_ports: List[int],
        device_traits: Dict[str, Any],
        trigger_reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        segment_conditions = self._normalize_segment_conditions(
            self.defense_rules.get("containment_segment_conditions", [])
        ).get(segment["name"], [])
        port_set = {int(port) for port in open_ports if port}
        details = details or {}

        for condition in segment_conditions:
            condition_name = condition["condition"]
            matched = (
                (condition_name == "critical_ports" and bool({445, 3389} & port_set))
                or (condition_name == "high_risk" and risk_score >= self.defense_rules.get("max_risk_score_for_auto_block", 80))
                or (condition_name == "trusted_device" and bool(device_traits.get("is_trusted")))
                or (condition_name == "failed_logins" and trigger_reason == "failed_logins")
                or (condition_name == "scan_burst" and trigger_reason == "port_scan_pattern")
                or (condition_name == "malicious_request" and trigger_reason in {"malicious_request", "rate_limit_exceeded"})
                or (condition_name == "honeypot_activity" and trigger_reason == "honeypot_attack")
            )
            if not matched:
                continue

            containment = self._apply_profile_to_containment(
                containment,
                condition["profile"],
                segment=segment,
                port_set=port_set,
                allowed_destinations=containment.get("allowed_destinations"),
                allowed_networks=[segment["network"]] if condition["profile"] == "segment_isolation" else containment.get("allowed_networks"),
                policy_name=f"{segment['name']}:{condition_name}",
                condition_name=condition_name,
                summary=f"Apply {condition['profile']} because {condition_name} matched for the {segment['name']} segment.",
                trace_stage="condition_override",
                trace_detail=f"Condition {condition_name} matched for segment {segment['name']}.",
                trace_priority=20,
            )
            break

        segment_thresholds = self._normalize_segment_thresholds(
            self.defense_rules.get("containment_segment_thresholds", [])
        ).get(segment["name"], [])
        for threshold in segment_thresholds:
            if trigger_reason != threshold["trigger"]:
                continue
            observed_count = self._recent_trigger_count(segment["name"], trigger_reason or "", threshold["window_seconds"])
            if observed_count < threshold["count"]:
                continue

            containment = self._apply_profile_to_containment(
                containment,
                threshold["profile"],
                segment=segment,
                port_set=port_set,
                allowed_destinations=containment.get("allowed_destinations"),
                allowed_networks=[segment["network"]] if threshold["profile"] == "segment_isolation" else containment.get("allowed_networks"),
                policy_name=f"{segment['name']}:{trigger_reason}:{threshold['count']}",
                condition_name=f"threshold:{trigger_reason}:{observed_count}/{threshold['window_seconds']}",
                summary=(
                    f"Apply {threshold['profile']} because {trigger_reason} fired "
                    f"{observed_count} times within {threshold['window_seconds']} seconds for the {segment['name']} segment."
                ),
                trace_stage="threshold_override",
                trace_detail=(
                    f"Trigger {trigger_reason} reached {observed_count}/{threshold['count']} "
                    f"events in {threshold['window_seconds']} seconds for segment {segment['name']}."
                ),
                trace_priority=30,
            )
            break

        return containment

    def _load_playbooks(self) -> Dict[str, Dict[str, Any]]:
        return {
            "failed_login_lockdown": {
                "name": "failed_login_lockdown",
                "title": "Failed Login Lockdown",
                "description": "Block a source after repeated failed login attempts cross the configured threshold.",
                "trigger": "trigger_reason == failed_logins",
                "steps": ["block_device", "create_alert"],
            },
            "malicious_request_block": {
                "name": "malicious_request_block",
                "title": "Malicious Request Block",
                "description": "Block a source that sends clearly malicious request patterns or abusive bursts.",
                "trigger": "trigger_reason in [malicious_request, rate_limit_exceeded]",
                "steps": ["block_device", "create_alert"],
            },
            "critical_risk_block": {
                "name": "critical_risk_block",
                "title": "Critical Risk Block",
                "description": "Block a device when its risk score reaches the critical threshold.",
                "trigger": "risk_score >= max_risk_score_for_auto_block",
                "steps": ["block_device", "create_alert"],
            },
            "elevated_risk_quarantine": {
                "name": "elevated_risk_quarantine",
                "title": "Elevated Risk Quarantine",
                "description": "Quarantine a device showing elevated risk without going straight to a full block.",
                "trigger": "auto_quarantine and risk_score >= 60",
                "steps": ["quarantine_device", "create_alert"],
            },
            "port_scan_containment": {
                "name": "port_scan_containment",
                "title": "Port Scan Containment",
                "description": "Contain scanning behavior and raise an alert for analyst review.",
                "trigger": "trigger_reason == port_scan_pattern",
                "steps": ["quarantine_device", "create_alert"],
            },
            "smb_rdp_exposure_lockdown": {
                "name": "smb_rdp_exposure_lockdown",
                "title": "SMB/RDP Exposure Lockdown",
                "description": "Block high-risk devices exposing SMB or RDP when risk rises sharply.",
                "trigger": "risk_score >= 70 and open_ports intersects [445,3389]",
                "steps": ["block_device", "create_alert"],
            },
            "honeypot_attacker_block": {
                "name": "honeypot_attacker_block",
                "title": "Honeypot Attacker Block",
                "description": "Block an attacker observed engaging the honeypot.",
                "trigger": "trigger_reason == honeypot_attack",
                "steps": ["block_device", "create_alert"],
            },
        }

    def _record_event(
        self,
        event_type: str,
        title: str,
        message: str,
        severity: str = "info",
        target_ip: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        if self.event_logger:
            self.event_logger.record(
                event_type=event_type,
                source="auto_defense",
                title=title,
                message=message,
                severity=severity,
                target_ip=target_ip,
                metadata=metadata,
            )
        if event_type.startswith("defense_"):
            publish_sync("defense_status", self.get_firewall_status())

    def evaluate_and_respond(
        self,
        device_ip: str,
        risk_score: float,
        open_ports: List[int],
        trigger_reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        response = {
            "device_ip": device_ip,
            "risk_score": risk_score,
            "actions_taken": [],
            "playbook": None,
            "timestamp": datetime.utcnow().isoformat(),
        }

        playbook = self.recommend_playbook(risk_score, open_ports, trigger_reason=trigger_reason)
        if playbook:
            response["playbook"] = playbook["name"]
            response["actions_taken"] = self.execute_playbook(
                playbook["name"],
                device_ip,
                risk_score=risk_score,
                open_ports=open_ports,
                trigger_reason=trigger_reason,
            )
            if response["actions_taken"]:
                self.activity_logger.log_threat_detected(device_ip, risk_score, open_ports)
        elif self.defense_rules["notify_on_high"] and risk_score >= 40:
            self._create_alert(device_ip, risk_score, open_ports)
            response["actions_taken"].append({
                "action": "alert_created",
                "message": "High risk alert created",
            })

        return response

    def respond_to_trigger(
        self,
        ip: str,
        trigger_reason: str,
        risk_score: Optional[float] = None,
        open_ports: Optional[List[int]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        open_ports = open_ports or []
        details = details or {}
        computed_risk = risk_score if risk_score is not None else self._risk_for_trigger(trigger_reason, open_ports)
        self._record_trigger_observation(ip, trigger_reason, computed_risk, open_ports, details=details)
        playbook = self.recommend_playbook(computed_risk, open_ports, trigger_reason=trigger_reason)
        if not playbook:
            return {
                "device_ip": ip,
                "risk_score": computed_risk,
                "trigger_reason": trigger_reason,
                "playbook": None,
                "actions_taken": [],
                "timestamp": datetime.utcnow().isoformat(),
            }

        return {
            "device_ip": ip,
            "risk_score": computed_risk,
            "trigger_reason": trigger_reason,
            "playbook": playbook["name"],
            "actions_taken": self.execute_playbook(
                playbook["name"],
                ip,
                risk_score=computed_risk,
                open_ports=open_ports,
                trigger_reason=trigger_reason,
                details=details,
            ),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _risk_for_trigger(self, trigger_reason: str, open_ports: List[int]) -> float:
        port_set = {int(port) for port in open_ports if port}
        if trigger_reason == "honeypot_attack":
            return 95
        if trigger_reason == "malicious_request":
            return 90
        if trigger_reason == "rate_limit_exceeded":
            return 75
        if trigger_reason == "failed_logins":
            return 85
        if trigger_reason == "port_scan_pattern":
            return 70
        if {445, 3389} & port_set:
            return 80
        return 50

    def _containment_profile_for(
        self,
        risk_score: float,
        open_ports: List[int],
        trigger_reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        port_set = {int(port) for port in open_ports if port}
        if trigger_reason == "honeypot_attack":
            return {
                "profile": "full_isolation",
                "scope": "all_traffic",
                "summary": "Block all device traffic after hostile honeypot interaction.",
            }
        if trigger_reason in {"failed_logins", "malicious_request"}:
            return {
                "profile": "defensive_lockdown",
                "scope": "all_traffic",
                "summary": "Lock down the source while preserving audit state for investigation.",
            }
        if trigger_reason == "port_scan_pattern":
            allowlists = self._containment_allowlists()
            return {
                "profile": "restricted_network",
                "scope": "lan_traffic",
                "allowed_networks": allowlists["allowed_networks"],
                "allowed_destinations": allowlists["allowed_destinations"],
                "summary": "Contain the source from lateral movement while allowing controlled review.",
            }
        if {445, 3389} & port_set:
            targeted_ports = sorted({port for port in port_set if port in {445, 3389}})
            return {
                "profile": "critical_service_isolation",
                "scope": "critical_services",
                "ports": targeted_ports or [445, 3389],
                "summary": "Isolate only critical remote-access services while preserving broader visibility.",
            }
        if risk_score >= self.defense_rules.get("max_risk_score_for_auto_block", 80):
            return {
                "profile": "full_isolation",
                "scope": "all_traffic",
                "summary": "Cut off all traffic for critical-risk devices.",
            }
        return {
            "profile": "restricted_network",
            "scope": "lan_traffic",
            **self._containment_allowlists(),
            "summary": "Restrict local-network exposure while retaining analyst visibility.",
        }

    def recommend_playbook(
        self,
        risk_score: float,
        open_ports: List[int],
        trigger_reason: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        port_set = {int(port) for port in open_ports if port}
        if trigger_reason == "failed_logins":
            return self.playbooks["failed_login_lockdown"]
        if trigger_reason in {"malicious_request", "rate_limit_exceeded"}:
            return self.playbooks["malicious_request_block"]
        if trigger_reason == "honeypot_attack":
            return self.playbooks["honeypot_attacker_block"]
        if trigger_reason == "port_scan_pattern":
            return self.playbooks["port_scan_containment"]
        if risk_score >= 70 and ({445, 3389} & port_set):
            return self.playbooks["smb_rdp_exposure_lockdown"]
        if risk_score >= self.defense_rules["max_risk_score_for_auto_block"]:
            return self.playbooks["critical_risk_block"]
        if self.defense_rules.get("auto_quarantine") and risk_score >= 60:
            return self.playbooks["elevated_risk_quarantine"]
        return None

    def execute_playbook(
        self,
        playbook_name: str,
        ip: str,
        risk_score: float = 0,
        open_ports: Optional[List[int]] = None,
        trigger_reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        playbook = self.playbooks.get(playbook_name)
        if not playbook:
            return [{
                "action": "playbook_error",
                "success": False,
                "message": f"Unknown playbook: {playbook_name}",
            }]

        actions_taken: List[Dict[str, Any]] = []
        open_ports = open_ports or []
        details = details or {}
        containment = self._containment_profile_for(risk_score, open_ports, trigger_reason=trigger_reason)
        containment["decision_trace"] = []
        self._append_decision_trace(
            containment,
            "base_profile",
            containment["profile"],
            f"Base containment profile selected from risk={risk_score} and ports={sorted({int(port) for port in open_ports if port})}.",
            10,
        )
        segment = self._segment_for_ip(ip)
        device_traits = self._get_device_traits(ip)
        if segment:
            containment["segment_name"] = segment["name"]
            self._append_decision_trace(
                containment,
                "segment_match",
                segment["name"],
                f"Matched device {ip} to segment {segment['name']} ({segment['network']}).",
                15,
            )
            policy = self._policy_for_segment(segment["name"])
            containment["policy_name"] = segment["name"]
            if containment["profile"] == "restricted_network":
                selected_profile = policy["profile"] if policy else "segment_isolation"
                selected_destinations = policy.get("allowed_destinations") if policy else containment.get("allowed_destinations")
                containment = self._apply_profile_to_containment(
                    containment,
                    selected_profile,
                    segment=segment,
                    allowed_destinations=selected_destinations,
                    allowed_networks=[segment["network"]] if selected_profile == "segment_isolation" else containment.get("allowed_networks"),
                    policy_name=segment["name"],
                    summary=(
                        f"Keep the device inside the {segment['name']} segment while blocking lateral movement elsewhere."
                        if selected_profile == "segment_isolation"
                        else f"Apply the {selected_profile} policy for the {segment['name']} segment."
                    ),
                    trace_stage="segment_policy",
                    trace_detail=(
                        f"Applied segment default for {segment['name']}."
                        if policy
                        else f"No explicit segment policy for {segment['name']}; defaulted to segment_isolation."
                    ),
                    trace_priority=18,
                )
            containment = self._apply_segment_condition_overrides(
                containment,
                segment,
                risk_score,
                open_ports,
                device_traits,
                trigger_reason=trigger_reason,
                details=details,
            )
        self._append_decision_trace(
            containment,
            "final_selection",
            containment["profile"],
            (
                f"Final containment profile is {containment['profile']} with scope "
                f"{containment.get('scope', 'lan_traffic')}."
            ),
            100,
        )

        for step in playbook["steps"]:
            if step == "block_device":
                actions_taken.append(self.block_device(ip, reason=f"Playbook: {playbook['title']}"))
            elif step == "quarantine_device":
                actions_taken.append(
                    self.quarantine_device(
                        ip,
                        reason=f"Playbook: {playbook['title']}",
                        profile=containment["profile"],
                        scope=containment["scope"],
                        ports=containment.get("ports"),
                        allowed_networks=containment.get("allowed_networks"),
                        allowed_destinations=containment.get("allowed_destinations"),
                        segment_name=containment.get("segment_name"),
                        policy_name=containment.get("policy_name"),
                        condition_name=containment.get("condition_name"),
                        trigger_reason=trigger_reason,
                        decision_trace=containment.get("decision_trace"),
                    )
                )
            elif step == "create_alert":
                self._create_alert(ip, risk_score, open_ports)
                actions_taken.append({
                    "action": "alert_created",
                    "success": True,
                    "message": f"Alert created for playbook {playbook['title']}",
                })

        self._record_event(
            "defense_playbook_executed",
            f"Executed playbook {playbook['title']}",
            f"Playbook {playbook_name} executed for {ip}",
            severity="high" if risk_score >= 70 else "info",
            target_ip=ip,
            metadata={
                "playbook": playbook_name,
                "risk_score": risk_score,
                "open_ports": open_ports,
                "trigger_reason": trigger_reason,
                "details": details,
                "containment": containment,
            },
        )
        return actions_taken

    def _validate_block_target(self, ip: str) -> Optional[str]:
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError:
            return "Invalid IP"

        if parsed_ip.is_loopback or parsed_ip.is_multicast or parsed_ip.is_unspecified:
            return "Protected IP"

        protected_exact = {
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
            "208.67.222.222", "9.9.9.9",
        }
        if ip in protected_exact:
            return "Protected IP"

        protected_private_gateways = {
            "192.168.1.1", "192.168.0.1", "192.168.1.254",
            "10.0.0.1", "10.0.0.254", "10.0.1.1",
            "172.16.0.1", "172.16.255.254",
        }
        if ip in protected_private_gateways:
            return "Protected gateway"

        return None

    def _record_blacklist_entry(self, ip: str, reason: str, is_active: bool, expires_minutes: Optional[int] = None):
        if not self.get_db:
            return

        db = self.get_db()
        try:
            BlacklistedIP = _import_schema_model("BlacklistedIP")

            existing = db.query(BlacklistedIP).filter_by(ip_address=ip).first()
            expires_at = None
            if expires_minutes:
                expires_at = datetime.utcnow() + timedelta(minutes=expires_minutes)

            if existing:
                existing.reason = reason
                existing.source = self.firewall_adapter.name
                existing.is_active = is_active
                existing.expires_at = expires_at
            else:
                db.add(
                    BlacklistedIP(
                        ip_address=ip,
                        source=self.firewall_adapter.name,
                        reason=reason,
                        is_active=is_active,
                        expires_at=expires_at,
                    )
                )
            db.commit()
        except Exception as exc:
            if "no such table" not in str(exc).lower():
                logger.error(f"Failed to persist blacklist entry for {ip}: {exc}")
        finally:
            db.close()

    def block_device(self, ip: str, reason: str = "") -> Dict[str, Any]:
        validation_error = self._validate_block_target(ip)
        if validation_error:
            logger.warning(f"Refusing to block {ip}: {validation_error}")
            return {
                "action": "device_blocked",
                "ip": ip,
                "success": False,
                "adapter": self.firewall_adapter.name,
                "reason": validation_error,
            }

        mode = self.defense_rules.get("enforcement_mode", "active")
        if mode != "active":
            self._record_blacklist_entry(ip, f"Dry-run only: {reason}", True, self.defense_rules["default_block_expiry_minutes"])
            self.activity_logger.log_system(f"Dry-run block recorded for {ip}")
            self._record_event(
                "defense_block_dry_run",
                f"Dry-run block for {ip}",
                reason or "Dry-run block requested",
                target_ip=ip,
                metadata={"adapter": self.firewall_adapter.name, "mode": mode},
            )
            return {
                "action": "device_blocked",
                "ip": ip,
                "success": True,
                "adapter": self.firewall_adapter.name,
                "reason": reason,
                "mode": mode,
                "message": "Dry-run mode enabled; firewall rule not applied",
            }

        operation = self.firewall_adapter.block_ip(ip)
        if operation.success:
            self._record_blacklist_entry(ip, reason or "Manual block", True, self.defense_rules["default_block_expiry_minutes"])
            self.activity_logger.log_device_block(ip, True)
            self._mark_device_blocked(ip, True)
            self._record_event(
                "defense_block",
                f"Blocked {ip}",
                reason or operation.message,
                severity="high",
                target_ip=ip,
                metadata={"adapter": self.firewall_adapter.name, "commands": operation.commands or []},
            )
        else:
            logger.warning(f"Firewall adapter failed to block {ip}: {operation.message}")
            self._record_event(
                "defense_block_failed",
                f"Failed to block {ip}",
                operation.message,
                severity="warning",
                target_ip=ip,
                metadata={"adapter": self.firewall_adapter.name},
            )

        payload = {
            "action": "device_blocked",
            "ip": ip,
            "reason": reason,
            "mode": mode,
            **operation.to_dict(),
        }
        return payload

    def unblock_device(self, ip: str) -> Dict[str, Any]:
        validation_error = None
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            validation_error = "Invalid IP"

        if validation_error:
            return {
                "action": "device_unblocked",
                "ip": ip,
                "success": False,
                "adapter": self.firewall_adapter.name,
                "reason": validation_error,
            }

        mode = self.defense_rules.get("enforcement_mode", "active")
        if mode != "active":
            self._record_blacklist_entry(ip, "Dry-run unblock", False)
            self._mark_device_blocked(ip, False)
            self._record_event(
                "defense_unblock_dry_run",
                f"Dry-run unblock for {ip}",
                "Dry-run mode enabled",
                target_ip=ip,
                metadata={"adapter": self.firewall_adapter.name, "mode": mode},
            )
            return {
                "action": "device_unblocked",
                "ip": ip,
                "success": True,
                "adapter": self.firewall_adapter.name,
                "mode": mode,
                "message": "Dry-run mode enabled; firewall rule not changed",
            }

        operation = self.firewall_adapter.unblock_ip(ip)
        if operation.success:
            self._record_blacklist_entry(ip, "Unblocked", False)
            self.activity_logger.log_device_block(ip, False)
            self._mark_device_blocked(ip, False)
            self._record_event(
                "defense_unblock",
                f"Unblocked {ip}",
                operation.message,
                target_ip=ip,
                metadata={"adapter": self.firewall_adapter.name, "commands": operation.commands or []},
            )
        else:
            self._record_event(
                "defense_unblock_failed",
                f"Failed to unblock {ip}",
                operation.message,
                severity="warning",
                target_ip=ip,
                metadata={"adapter": self.firewall_adapter.name},
            )

        payload = {
            "action": "device_unblocked",
            "ip": ip,
            "mode": mode,
            **operation.to_dict(),
        }
        return payload

    def quarantine_device(
        self,
        ip: str,
        reason: str = "",
        profile: str = "restricted_network",
        scope: str = "lan_traffic",
        ports: Optional[List[int]] = None,
        allowed_networks: Optional[List[str]] = None,
        allowed_destinations: Optional[List[str]] = None,
        segment_name: Optional[str] = None,
        policy_name: Optional[str] = None,
        condition_name: Optional[str] = None,
        trigger_reason: Optional[str] = None,
        decision_trace: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        validation_error = self._validate_block_target(ip)
        if validation_error:
            return {
                "action": "device_quarantined",
                "ip": ip,
                "success": False,
                "adapter": self.firewall_adapter.name,
                "reason": validation_error,
                "profile": profile,
                "scope": scope,
                "ports": ports or [],
            }

        mode = self.defense_rules.get("enforcement_mode", "active")
        normalized_ports = sorted({int(port) for port in (ports or []) if int(port) > 0})
        if profile == "critical_service_isolation" and not normalized_ports:
            normalized_ports = [445, 3389]
        segment = self._segment_for_ip(ip)
        resolved_segment_name = segment_name or (segment["name"] if segment else None)
        if profile == "segment_isolation" and not allowed_networks and segment:
            allowed_networks = [segment["network"]]
        if profile == "segment_isolation" and not allowed_networks and not segment:
            allowlists = self._containment_allowlists()
            allowed_networks = allowlists["allowed_networks"]
            resolved_segment_name = resolved_segment_name or "fallback_allowlist"
        normalized_networks = self._normalize_network_allowlist(allowed_networks)
        normalized_destinations = self._normalize_destination_allowlist(allowed_destinations)
        if mode != "active":
            self._record_blacklist_entry(
                ip,
                f"Dry-run quarantine: {reason}",
                True,
                self.defense_rules["default_block_expiry_minutes"],
            )
            self._mark_device_quarantined(
                ip,
                True,
                reason=reason,
                profile=profile,
                scope=scope,
                ports=normalized_ports,
                allowed_networks=normalized_networks,
                allowed_destinations=normalized_destinations,
                segment_name=resolved_segment_name,
                policy_name=policy_name,
                condition_name=condition_name,
                trigger_reason=trigger_reason,
                decision_trace=decision_trace,
            )
            self._record_event(
                "defense_quarantine_dry_run",
                f"Dry-run quarantine for {ip}",
                reason or "Dry-run quarantine requested",
                severity="warning",
                target_ip=ip,
                metadata={
                    "adapter": self.firewall_adapter.name,
                    "mode": mode,
                    "profile": profile,
                    "scope": scope,
                    "ports": normalized_ports,
                    "allowed_networks": normalized_networks,
                    "allowed_destinations": normalized_destinations,
                    "segment_name": resolved_segment_name,
                    "policy_name": policy_name,
                    "condition_name": condition_name,
                    "trigger_reason": trigger_reason,
                    "decision_trace": decision_trace or [],
                },
            )
            return {
                "action": "device_quarantined",
                "ip": ip,
                "success": True,
                "adapter": self.firewall_adapter.name,
                "mode": mode,
                "message": "Dry-run mode enabled; quarantine rule not applied",
                "profile": profile,
                "scope": scope,
                "ports": normalized_ports,
                "allowed_networks": normalized_networks,
                "allowed_destinations": normalized_destinations,
                "segment_name": resolved_segment_name,
                "policy_name": policy_name,
                "condition_name": condition_name,
                "decision_trace": decision_trace or [],
            }

        operation = self.firewall_adapter.quarantine_ip(
            ip,
            profile=profile,
            scope=scope,
            ports=normalized_ports,
            allowed_networks=normalized_networks,
            allowed_destinations=normalized_destinations,
        )
        if operation.success:
            self._record_blacklist_entry(
                ip,
                reason or "Device quarantined",
                True,
                self.defense_rules["default_block_expiry_minutes"],
            )
            self._mark_device_quarantined(
                ip,
                True,
                reason=reason,
                profile=profile,
                scope=scope,
                ports=normalized_ports,
                allowed_networks=normalized_networks,
                allowed_destinations=normalized_destinations,
                segment_name=resolved_segment_name,
                policy_name=policy_name,
                condition_name=condition_name,
                trigger_reason=trigger_reason,
                decision_trace=decision_trace,
            )
            self._record_event(
                "defense_quarantine",
                f"Quarantined {ip}",
                reason or operation.message,
                severity="high",
                target_ip=ip,
                metadata={
                    "adapter": self.firewall_adapter.name,
                    "commands": operation.commands or [],
                    "profile": profile,
                    "scope": scope,
                    "ports": normalized_ports,
                    "allowed_networks": normalized_networks,
                    "allowed_destinations": normalized_destinations,
                    "segment_name": resolved_segment_name,
                    "policy_name": policy_name,
                    "condition_name": condition_name,
                    "trigger_reason": trigger_reason,
                    "decision_trace": decision_trace or [],
                },
            )
        else:
            self._record_event(
                "defense_quarantine_failed",
                f"Failed to quarantine {ip}",
                operation.message,
                severity="warning",
                target_ip=ip,
                metadata={
                    "adapter": self.firewall_adapter.name,
                    "profile": profile,
                    "scope": scope,
                    "ports": normalized_ports,
                    "allowed_networks": normalized_networks,
                    "allowed_destinations": normalized_destinations,
                    "segment_name": resolved_segment_name,
                    "policy_name": policy_name,
                    "condition_name": condition_name,
                    "trigger_reason": trigger_reason,
                    "decision_trace": decision_trace or [],
                },
            )

        return {
            "action": "device_quarantined",
            "ip": ip,
            "reason": reason,
            "mode": mode,
            "profile": profile,
            "scope": scope,
            "ports": normalized_ports,
            "allowed_networks": normalized_networks,
            "allowed_destinations": normalized_destinations,
            "segment_name": resolved_segment_name,
            "policy_name": policy_name,
            "condition_name": condition_name,
            "decision_trace": decision_trace or [],
            **operation.to_dict(),
        }

    def unquarantine_device(self, ip: str) -> Dict[str, Any]:
        mode = self.defense_rules.get("enforcement_mode", "active")
        containment = self._get_device_containment(ip)
        if mode != "active":
            self._record_blacklist_entry(ip, "Dry-run unquarantine", False)
            self._mark_device_quarantined(ip, False)
            self._record_event(
                "defense_unquarantine_dry_run",
                f"Dry-run unquarantine for {ip}",
                "Dry-run mode enabled",
                target_ip=ip,
                metadata={"adapter": self.firewall_adapter.name, "mode": mode},
            )
            return {
                "action": "device_unquarantined",
                "ip": ip,
                "success": True,
                "adapter": self.firewall_adapter.name,
                "mode": mode,
                "message": "Dry-run mode enabled; quarantine rule not changed",
            }

        operation = self.firewall_adapter.unquarantine_ip(
            ip,
            profile=containment.get("profile", "restricted_network"),
            scope=containment.get("scope", "lan_traffic"),
            ports=containment.get("ports") or [],
            allowed_networks=containment.get("allowed_networks") or [],
            allowed_destinations=containment.get("allowed_destinations") or [],
        )
        if operation.success:
            self._record_blacklist_entry(ip, "Unquarantined", False)
            self._mark_device_quarantined(ip, False)
            self._record_event(
                "defense_unquarantine",
                f"Unquarantined {ip}",
                operation.message,
                target_ip=ip,
                metadata={"adapter": self.firewall_adapter.name, "commands": operation.commands or []},
            )
        else:
            self._record_event(
                "defense_unquarantine_failed",
                f"Failed to unquarantine {ip}",
                operation.message,
                severity="warning",
                target_ip=ip,
                metadata={"adapter": self.firewall_adapter.name},
            )

        return {
            "action": "device_unquarantined",
            "ip": ip,
            "mode": mode,
            **operation.to_dict(),
        }

    def _mark_device_blocked(self, ip: str, blocked: bool):
        if not self.get_db:
            return

        db = self.get_db()
        try:
            NetworkDevice = _import_schema_model("NetworkDevice")

            device = db.query(NetworkDevice).filter_by(ip_address=ip).first()
            if device:
                device.is_blocked = blocked
                if blocked:
                    device.is_trusted = False
                    device.status = "blocked"
                elif device.status == "blocked":
                    device.status = "online"
                device_info = dict(device.device_info or {})
                containment = dict(device_info.get("containment", {}))
                if blocked:
                    containment.update({
                        "active": True,
                        "profile": "full_isolation",
                        "scope": "all_traffic",
                        "reason": "Device blocked",
                        "adapter": self.firewall_adapter.name,
                        "applied_at": datetime.utcnow().isoformat(),
                    })
                else:
                    containment.update({
                        "active": False,
                        "released_at": datetime.utcnow().isoformat(),
                    })
                device_info["containment"] = containment
                device.device_info = device_info
                db.commit()
        except Exception as exc:
            logger.error(f"Failed to update device block state for {ip}: {exc}")
        finally:
            db.close()

    def _mark_device_quarantined(
        self,
        ip: str,
        quarantined: bool,
        reason: str = "",
        profile: str = "restricted_network",
        scope: str = "lan_traffic",
        ports: Optional[List[int]] = None,
        allowed_networks: Optional[List[str]] = None,
        allowed_destinations: Optional[List[str]] = None,
        segment_name: Optional[str] = None,
        policy_name: Optional[str] = None,
        condition_name: Optional[str] = None,
        trigger_reason: Optional[str] = None,
        decision_trace: Optional[List[Dict[str, Any]]] = None,
    ):
        if not self.get_db:
            return

        db = self.get_db()
        try:
            NetworkDevice = _import_schema_model("NetworkDevice")

            device = db.query(NetworkDevice).filter_by(ip_address=ip).first()
            if device:
                device.is_blocked = quarantined
                device.status = "quarantined" if quarantined else "online"
                if quarantined:
                    device.is_trusted = False
                device_info = dict(device.device_info or {})
                containment = dict(device_info.get("containment", {}))
                if quarantined:
                    containment.update({
                        "active": True,
                        "profile": profile,
                        "scope": scope,
                        "ports": sorted({int(port) for port in (ports or []) if int(port) > 0}),
                        "allowed_networks": self._normalize_network_allowlist(allowed_networks),
                        "allowed_destinations": self._normalize_destination_allowlist(allowed_destinations),
                        "segment_name": segment_name,
                        "policy_name": policy_name,
                        "condition_name": condition_name,
                        "decision_trace": list(decision_trace or []),
                        "reason": reason or "Device quarantined",
                        "trigger_reason": trigger_reason,
                        "adapter": self.firewall_adapter.name,
                        "applied_at": datetime.utcnow().isoformat(),
                    })
                else:
                    containment.update({
                        "active": False,
                        "ports": [],
                        "allowed_networks": [],
                        "allowed_destinations": [],
                        "segment_name": None,
                        "policy_name": None,
                        "condition_name": None,
                        "decision_trace": [],
                        "released_at": datetime.utcnow().isoformat(),
                    })
                device_info["containment"] = containment
                device.device_info = device_info
                db.commit()
        except Exception as exc:
            logger.error(f"Failed to update device quarantine state for {ip}: {exc}")
        finally:
            db.close()

    def _get_device_containment(self, ip: str) -> Dict[str, Any]:
        if not self.get_db:
            return {}

        db = self.get_db()
        try:
            NetworkDevice = _import_schema_model("NetworkDevice")
            device = db.query(NetworkDevice).filter_by(ip_address=ip).first()
            if not device:
                return {}
            return dict((device.device_info or {}).get("containment", {}))
        except Exception as exc:
            logger.error(f"Failed to load containment state for {ip}: {exc}")
            return {}
        finally:
            db.close()

    def _create_alert(self, ip: str, risk_score: float, ports: List[int]):
        db = self.get_db()
        try:
            Alert = _import_schema_model("Alert")

            severity = "critical" if risk_score >= 70 else "high"
            alert = Alert(
                alert_type="auto_defense",
                severity=severity,
                title=f"Auto-Defense: High risk device {ip}",
                message=f"Risk score: {risk_score}. Open ports: {ports}",
                source_ip=ip,
                is_resolved=False,
                created_at=datetime.utcnow(),
            )
            db.add(alert)
            db.commit()
        except Exception as exc:
            logger.error(f"Failed to create alert: {exc}")
        finally:
            db.close()

    def get_blocked_ips(self) -> List[str]:
        adapter_blocked = set(self.firewall_adapter.get_blocked_ips())

        if self.get_db:
            db = self.get_db()
            try:
                BlacklistedIP = _import_schema_model("BlacklistedIP")

                db_blocked = {
                    entry.ip_address
                    for entry in db.query(BlacklistedIP).filter_by(is_active=True).all()
                }
                adapter_blocked |= db_blocked
            except Exception as exc:
                if "no such table" not in str(exc).lower():
                    logger.error(f"Failed to load persisted blocked IPs: {exc}")
            finally:
                db.close()

        return sorted(adapter_blocked)

    def get_firewall_status(self) -> Dict[str, Any]:
        diagnostics = self.firewall_adapter.diagnostics()
        diagnostics.update({
            "blocked_ips": self.get_blocked_ips(),
            "available_adapters": get_firewall_adapter_catalog(),
            "enforcement_mode": self.defense_rules.get("enforcement_mode", "active"),
            "rules": self.get_defense_rules(),
            "admin": is_running_as_admin(),
        })
        return diagnostics

    def set_defense_rule(self, rule: str, value: Any):
        if rule in self.defense_rules:
            self.defense_rules[rule] = value
            if self.config_store:
                self.config_store.set(rule, value, description=f"Defense setting: {rule}")
            self.activity_logger.log_system(f"Defense rule updated: {rule} = {value}")
            self._record_event(
                "defense_rule_updated",
                f"Defense rule updated: {rule}",
                f"Set {rule} to {value}",
                metadata={"rule": rule, "value": value},
            )
            publish_sync("defense_status", self.get_firewall_status())

    def get_defense_rules(self) -> Dict[str, Any]:
        rules = self.defense_rules.copy()
        rules["firewall_adapter"] = self.firewall_adapter.name
        return rules

    def get_playbooks(self) -> List[Dict[str, Any]]:
        return list(self.playbooks.values())


auto_defense = None


def init_auto_defense(db_session, activity_logger):
    global auto_defense
    auto_defense = AutoDefenseEngine(db_session, activity_logger)
    return auto_defense
