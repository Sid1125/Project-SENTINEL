import secrets

from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import time

from models.database import get_db, SessionLocal, settings
from models.schemas import NetworkDevice, PortScanResult, Vulnerability, Alert, ScanHistory, SecurityEvent
from core.scanner import NetworkScanner
from core.threats import ThreatIntelligence
from core.vuln_scanner import VulnerabilityScanner, vuln_scanner
from core.anomaly_detector import anomaly_detector
from core.traffic_monitor import TrafficMonitor
from core.auto_defense import AutoDefenseEngine
from core.config_store import ConfigStore, DEFAULT_CONFIG
from core.logger import activity_logger
from core.auth import (
    AUTH_HEADER,
    extract_token_from_request,
    get_configured_roles,
    get_request_role,
    get_token_hint,
    has_minimum_role,
    is_auth_enabled,
)
from core.security import validate_ip_address, validate_port, validate_domain, sanitize_input, validate_scan_target
from core.system_integration import get_system_info, get_network_interfaces, get_default_gateway, get_dns_servers, check_port_conflicts
from ai.nlp import NLPProcessor, LocalLLM

router = APIRouter()


def require_role(request: Request, minimum_role: str):
    if has_minimum_role(request, minimum_role):
        return
    raise HTTPException(
        status_code=403,
        detail={
            "message": f"{minimum_role.title()} role required",
            "required_role": minimum_role,
            "current_role": get_request_role(request),
        },
    )

scanner = NetworkScanner()
threat_intel = ThreatIntelligence()
llm = LocalLLM()
nlp = NLPProcessor(llm)

auto_scanner = None
traffic_monitor = None
_auto_defense_instance = None

def get_auto_scanner():
    global auto_scanner
    try:
        from api.main import auto_scanner as main_as
        if main_as:
            auto_scanner = main_as
            return main_as
    except Exception:
        pass
    return None

def get_traffic_monitor():
    global traffic_monitor
    if traffic_monitor is not None:
        return traffic_monitor
    
    try:
        from api.main import traffic_monitor as main_tm
        if main_tm:
            traffic_monitor = main_tm
            return main_tm
    except Exception:
        pass
    
    traffic_monitor = TrafficMonitor(SessionLocal, threat_intel, activity_logger)
    return traffic_monitor

def get_auto_defense():
    global _auto_defense_instance
    if _auto_defense_instance is not None:
        return _auto_defense_instance
    
    try:
        from api.main import auto_defense
        if auto_defense:
            _auto_defense_instance = auto_defense
            return auto_defense
    except Exception:
        pass
    
    _auto_defense_instance = AutoDefenseEngine(SessionLocal, activity_logger)
    return _auto_defense_instance


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"
    quick: bool = False

class NLPPromptRequest(BaseModel):
    prompt: str

class DeviceUpdateRequest(BaseModel):
    ip_address: str
    is_trusted: Optional[bool] = None
    is_blocked: Optional[bool] = None


class SettingsUpdateRequest(BaseModel):
    llm_host: Optional[str] = None
    llm_model: Optional[str] = None
    scan_timeout: Optional[int] = None
    auto_scan_interval: Optional[int] = None
    alert_notifications: Optional[bool] = None
    auto_block_critical: Optional[bool] = None
    auto_quarantine: Optional[bool] = None
    notify_on_high: Optional[bool] = None
    traffic_interface: Optional[str] = None
    traffic_autostart: Optional[bool] = None
    dns_sinkhole_enabled: Optional[bool] = None
    dns_sinkhole_redirect_ip: Optional[str] = None
    dns_blocked_domains: Optional[List[str]] = None
    dns_resolver_enabled: Optional[bool] = None
    dns_resolver_host: Optional[str] = None
    dns_resolver_port: Optional[int] = None
    dns_upstream_server: Optional[str] = None
    enforcement_mode: Optional[str] = None
    containment_allowed_segments: Optional[List[str]] = None
    containment_allowed_destinations: Optional[List[str]] = None
    containment_segments: Optional[List[str]] = None
    containment_segment_policies: Optional[List[str]] = None
    containment_segment_conditions: Optional[List[str]] = None
    containment_segment_thresholds: Optional[List[str]] = None


class PlaybookExecutionRequest(BaseModel):
    ip_address: str
    risk_score: Optional[float] = 0
    open_ports: Optional[List[int]] = None
    trigger_reason: Optional[str] = None


def get_config_store():
    return ConfigStore(SessionLocal)


def get_dns_filter():
    from core.dns_filter import dns_filter

    config_store = get_config_store()
    dns_filter.configure(
        enabled=config_store.get("dns_sinkhole_enabled", False),
        redirect_ip=config_store.get("dns_sinkhole_redirect_ip", "0.0.0.0"),
        resolver_enabled=config_store.get("dns_resolver_enabled", False),
        resolver_host=config_store.get("dns_resolver_host", "127.0.0.1"),
        resolver_port=config_store.get("dns_resolver_port", 5353),
        upstream_server=config_store.get("dns_upstream_server", "8.8.8.8"),
    )
    dns_filter.replace_blocklist(config_store.get("dns_blocked_domains", []))
    return dns_filter, config_store


@router.get("/auth/config")
async def get_auth_config():
    return {
        "enabled": is_auth_enabled(),
        "header": AUTH_HEADER,
        "token_hint": get_token_hint(),
        "configured_roles": sorted(get_configured_roles().keys()),
        "message": "Set SENTINEL_AUTH_TOKEN in the backend environment to require operator authentication.",
    }


@router.get("/auth/verify")
async def verify_auth(request: Request):
    if not is_auth_enabled():
        return {
            "authenticated": True,
            "role": "admin",
            "enabled": False,
            "message": "Operator authentication is currently disabled.",
        }

    role = get_request_role(request)
    return {
        "authenticated": role is not None,
        "role": role,
        "enabled": True,
        "header": AUTH_HEADER,
    }


@router.get("/config")
async def get_config():
    config_store = get_config_store()
    config = config_store.get_many(list(DEFAULT_CONFIG.keys()))
    return {"settings": config}


@router.put("/config")
async def update_config(request: SettingsUpdateRequest, http_request: Request):
    require_role(http_request, "admin")
    config_store = get_config_store()
    payload = request.model_dump() if hasattr(request, "model_dump") else request.dict()
    updates = {key: value for key, value in payload.items() if value is not None}
    if not updates:
        return {"status": "no_changes", "settings": config_store.get_many(list(DEFAULT_CONFIG.keys()))}

    if "enforcement_mode" in updates and updates["enforcement_mode"] not in {"active", "dry_run"}:
        raise HTTPException(status_code=400, detail="enforcement_mode must be 'active' or 'dry_run'")

    config_store.set_many(updates)

    ad = get_auto_defense()
    for key, value in updates.items():
        if key in ad.defense_rules:
            ad.set_defense_rule(key, value)

    return {"status": "updated", "settings": config_store.get_many(list(DEFAULT_CONFIG.keys()))}


@router.get("/events/security")
async def get_security_events(limit: int = 50, severity: Optional[str] = None, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    try:
        query = db.query(SecurityEvent)
        if severity:
            query = query.filter_by(severity=severity)

        events = query.order_by(SecurityEvent.created_at.desc()).limit(limit).all()
    except Exception as exc:
        if "no such table" in str(exc).lower():
            return {"events": [], "status": "uninitialized"}
        raise

    return {
        "events": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "severity": event.severity,
                "source": event.source,
                "title": event.title,
                "message": event.message,
                "target_ip": event.target_ip,
                "metadata": event.event_metadata or {},
                "created_at": event.created_at.isoformat() if event.created_at else None,
            }
            for event in events
        ]
    }


@router.get("/devices")
async def get_devices(db: Session = Depends(get_db)):
    devices = db.query(NetworkDevice).all()
    return {
        "devices": [
            {
                "id": d.id,
                "ip_address": d.ip_address,
                "mac_address": d.mac_address,
                "hostname": d.hostname,
                "vendor": d.vendor,
                "is_trusted": d.is_trusted,
                "is_blocked": d.is_blocked,
                "risk_score": d.risk_score,
                "status": d.status,
                "containment": (d.device_info or {}).get("containment", {}),
                "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                "ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": p.service,
                        "service_version": p.service_version
                    }
                    for p in db.query(PortScanResult).filter_by(device_id=d.id, state='open').all()
                ]
            }
            for d in devices
        ]
    }


@router.post("/scan/network")
async def scan_network(request: Request, db: Session = Depends(get_db)):
    require_role(request, "operator")
    target = scanner.local_networks[0] if scanner.local_networks else '192.168.1.0/24'
    
    if not validate_scan_target(target):
        raise HTTPException(status_code=400, detail="Invalid scan target")
    
    devices = scanner.arp_scan()
    
    saved_count = 0
    for dev in devices:
        existing = db.query(NetworkDevice).filter_by(ip_address=dev['ip_address']).first()
        if existing:
            existing.last_seen = datetime.utcnow()
            if dev.get('mac_address'):
                existing.mac_address = dev['mac_address']
            if dev.get('hostname'):
                existing.hostname = dev['hostname']
            device_id = existing.id
            device_obj = existing
        else:
            new_device = NetworkDevice(
                ip_address=dev['ip_address'],
                mac_address=dev.get('mac_address'),
                hostname=dev.get('hostname'),
                vendor=dev.get('vendor'),
                status=dev.get('status', 'unknown')
            )
            db.add(new_device)
            db.flush()
            device_id = new_device.id
            device_obj = new_device
            saved_count += 1
        
        port_results = scanner.port_scan(dev['ip_address'], ports="1-1000")
        
        for port_info in port_results:
            if port_info.get('state') == 'open':
                existing_port = db.query(PortScanResult).filter_by(
                    device_id=device_id, 
                    port=port_info['port']
                ).first()
                
                if not existing_port:
                    port_result = PortScanResult(
                        device_id=device_id,
                        port=port_info['port'],
                        protocol=port_info.get('protocol', 'tcp'),
                        state=port_info.get('state', 'unknown'),
                        service=port_info.get('service', 'unknown'),
                        service_version=port_info.get('service_version', '')
                    )
                    db.add(port_result)
        
        dev['ports'] = [p for p in port_results if p.get('state') == 'open']
    
    scan_history = ScanHistory(
        scan_type='network_discovery',
        target_range=scanner.local_networks[0] if scanner.local_networks else '192.168.1.0/24',
        devices_found=len(devices),
        status='completed'
    )
    db.add(scan_history)
    db.commit()
    
    activity_logger.log_scan('network', scanner.local_networks[0] if scanner.local_networks else '192.168.1.0/24', len(devices))
    
    return {
        "status": "completed",
        "devices_found": len(devices),
        "new_devices": saved_count,
        "devices": devices
    }


@router.post("/scan/ports")
async def scan_ports(target: str, ports: str = "1-1000", request: Request = None, db: Session = Depends(get_db)):
    require_role(request, "operator")
    if not validate_ip_address(target):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    
    port_list = []
    if '-' in ports:
        parts = ports.split('-')
        try:
            start, end = int(parts[0]), int(parts[1])
            if not (validate_port(start) and validate_port(end)):
                raise ValueError()
            port_list = list(range(start, min(end + 1, 1001)))
        except:
            raise HTTPException(status_code=400, detail="Invalid port range")
    
    results = scanner.port_scan(target, ports)
    
    device = db.query(NetworkDevice).filter_by(ip_address=target).first()
    if device:
        for port_info in results:
            if port_info.get('state') == 'open':
                existing = db.query(PortScanResult).filter_by(
                    device_id=device.id, 
                    port=port_info['port']
                ).first()
                
                if not existing:
                    port_result = PortScanResult(
                        device_id=device.id,
                        port=port_info['port'],
                        protocol=port_info.get('protocol', 'tcp'),
                        state=port_info.get('state', 'unknown'),
                        service=port_info.get('name', 'unknown'),
                        service_version=port_info.get('version', '')
                    )
                    db.add(port_result)
        
        db.commit()
    
    activity_logger.log_port_scan(target, len([r for r in results if r.get('state') == 'open']))
    
    return {
        "target": target,
        "ports": results,
        "open_ports": len([r for r in results if r.get('state') == 'open'])
    }


@router.post("/nlp/prompt")
async def nlp_prompt(request: NLPPromptRequest, http_request: Request, db: Session = Depends(get_db)):
    require_role(http_request, "operator")
    intent_data = nlp.parse_intent(request.prompt)
    intent = intent_data.get('intent')
    entities = intent_data.get('entities', {})
    
    result_data = {}
    
    if intent == 'scan_network':
        devices = scanner.arp_scan()
        result_data = {'devices': devices}
        
    elif intent in ('scan_ports', 'scan_device'):
        target = entities.get('ips', [None])[0] if entities.get('ips') else None
        if not target:
            target = entities.get('networks', [None])[0]
        
        if target:
            ports = scanner.port_scan(target)
            result_data = {'ports': ports, 'target': target}
        else:
            result_data = {'error': 'No target specified'}
    
    elif intent == 'threat_check':
        devices = db.query(NetworkDevice).all()
        results = []
        for dev in devices:
            ports = db.query(PortScanResult).filter_by(device_id=dev.id).all()
            port_data = [{'port': p.port, 'service': p.service, 'service_version': p.service_version} for p in ports]
            analysis = threat_intel.analyze_device(port_data, dev.hostname, dev.os_guess)
            results.append({
                'ip': dev.ip_address,
                'risk_category': analysis.get('risk_category'),
                'risk_score': analysis.get('risk_score')
            })
        result_data = {'threats': results}
    
    elif intent == 'get_status':
        total = db.query(NetworkDevice).count()
        trusted = db.query(NetworkDevice).filter_by(is_trusted=True).count()
        threats = db.query(NetworkDevice).filter(NetworkDevice.risk_score >= 40).count()
        result_data = {
            'total_devices': total,
            'trusted_devices': trusted,
            'active_threats': threats
        }
    
    elif intent == 'block_device':
        target_ip = entities.get('ips', [None])[0]
        if target_ip:
            ad = get_auto_defense()
            block_result = ad.block_device(target_ip, reason="Manual block via NLP")
            result_data = {'ip': target_ip, 'success': block_result.get('success', False)}
        else:
            result_data = {'error': 'No IP address specified'}
    
    elif intent == 'unblock_device':
        target_ip = entities.get('ips', [None])[0]
        if target_ip:
            ad = get_auto_defense()
            unblock_result = ad.unblock_device(target_ip)
            result_data = {'ip': target_ip, 'success': unblock_result.get('success', False)}
        else:
            result_data = {'error': 'No IP address specified'}
    
    elif intent == 'trust_device':
        target_ip = entities.get('ips', [None])[0]
        if target_ip:
            device = db.query(NetworkDevice).filter_by(ip_address=target_ip).first()
            if device:
                device.is_trusted = True
                device.is_blocked = False
                db.commit()
                result_data = {'ip': target_ip, 'trusted': True}
            else:
                result_data = {'error': 'Device not found'}
        else:
            result_data = {'error': 'No IP address specified'}
    
    elif intent == 'vuln_scan':
        target_ip = entities.get('ips', [None])[0] if entities.get('ips') else 'localhost'
        result = vuln_scanner.scan_target(target_ip)
        result_data = {
            'target': target_ip,
            'vulnerabilities': [{'cve': v.cve, 'severity': v.severity, 'description': v.description} for v in result.vulnerabilities],
            'risk_score': result.risk_score
        }
    
    elif intent == 'anomaly_check':
        devices = db.query(NetworkDevice).all()
        results = []
        for device in devices:
            ports = db.query(PortScanResult).filter_by(device_id=device.id).all()
            port_data = [{'port': p.port, 'service': p.service} for p in ports]
            result = anomaly_detector.analyze_device(device.ip_address, port_data)
            results.append(result)
        anomalies = [r for r in results if r.get('is_anomaly')]
        result_data = {
            'total_devices': len(results),
            'anomalies_detected': len(anomalies),
            'anomalies': anomalies[:5]
        }
    
    elif intent == 'auto_defense':
        ad = get_auto_defense()
        rules = ad.get_defense_rules()
        result_data = {'enabled': rules.get('auto_block_critical', False), 'rules': rules}
    
    response_text = nlp.generate_response(intent or 'unknown', result_data)
    
    return {
        "intent": intent,
        "entities": entities,
        "result": result_data,
        "response": response_text
    }


@router.put("/device")
async def update_device(request: DeviceUpdateRequest, http_request: Request, db: Session = Depends(get_db)):
    require_role(http_request, "operator")
    device = db.query(NetworkDevice).filter_by(ip_address=request.ip_address).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    if request.is_trusted is not None:
        device.is_trusted = request.is_trusted
        if request.is_trusted:
            device.is_blocked = False
    if request.is_blocked is not None:
        device.is_blocked = request.is_blocked
        if request.is_blocked:
            device.is_trusted = False
    
    db.commit()
    
    return {"status": "updated", "device": request.ip_address}


@router.get("/alerts")
async def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(50).all()
    return {
        "alerts": [
            {
                "id": a.id,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "title": a.title,
                "message": a.message,
                "source_ip": a.source_ip,
                "is_resolved": a.is_resolved,
                "resolved": a.is_resolved,
                "created_at": a.created_at.isoformat() if a.created_at else None
            }
            for a in alerts
        ]
    }


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter_by(id=alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.is_resolved = True
    db.commit()
    
    return {"status": "resolved", "alert_id": alert_id}


@router.get("/history")
async def get_scan_history(db: Session = Depends(get_db)):
    history = db.query(ScanHistory).order_by(ScanHistory.start_time.desc()).limit(20).all()
    return {
        "history": [
            {
                "id": h.id,
                "scan_type": h.scan_type,
                "target_range": h.target_range,
                "devices_found": h.devices_found,
                "status": h.status,
                "start_time": h.start_time.isoformat() if h.start_time else None
            }
            for h in history
        ]
    }


@router.get("/status")
async def get_status(db: Session = Depends(get_db)):
    try:
        total = db.query(NetworkDevice).count()
        trusted = db.query(NetworkDevice).filter_by(is_trusted=True).count()
        blocked = db.query(NetworkDevice).filter_by(is_blocked=True).count()
        high_risk = db.query(NetworkDevice).filter(NetworkDevice.risk_score >= 70).count()
        medium_risk = db.query(NetworkDevice).filter(
            NetworkDevice.risk_score >= 40,
            NetworkDevice.risk_score < 70
        ).count()
        alerts = db.query(Alert).filter_by(is_resolved=False).count()
        scans = db.query(ScanHistory).count()
    except Exception as e:
        return {"error": str(e), "note": "Database may not be initialized"}
    
    as_inst = get_auto_scanner()
    tm_inst = get_traffic_monitor()
    
    return {
        "total_devices": total,
        "trusted_devices": trusted,
        "blocked_devices": blocked,
        "high_risk_devices": high_risk,
        "medium_risk_devices": medium_risk,
        "active_alerts": alerts,
        "total_scans": scans,
        "llm_available": llm.is_available(),
        "auto_scan_enabled": as_inst.running if as_inst and hasattr(as_inst, 'running') else False,
        "traffic_monitor_enabled": tm_inst.running if tm_inst and hasattr(tm_inst, 'running') else False
    }


@router.post("/auto-scan/start")
async def start_auto_scan(request: Request, db: Session = Depends(get_db)):
    require_role(request, "operator")
    as_inst = get_auto_scanner()
    if as_inst and not as_inst.running:
        import asyncio
        asyncio.create_task(as_inst.start())
        activity_logger.log_system("Auto scanner started via API")
        return {"status": "started", "message": "Auto scanning enabled"}
    return {"status": "already_running"}


@router.post("/auto-scan/stop")
async def stop_auto_scan(request: Request, db: Session = Depends(get_db)):
    require_role(request, "operator")
    as_inst = get_auto_scanner()
    if as_inst and as_inst.running:
        as_inst.stop()
        activity_logger.log_system("Auto scanner stopped via API")
        return {"status": "stopped", "message": "Auto scanning disabled"}
    return {"status": "not_running"}


@router.get("/traffic/stats")
async def get_traffic_stats():
    tm_inst = get_traffic_monitor()
    return tm_inst.get_stats()


@router.get("/traffic/interfaces")
async def get_traffic_interfaces():
    tm_inst = get_traffic_monitor()
    return {"interfaces": tm_inst.get_available_interfaces()}


@router.post("/traffic/start")
async def start_traffic_monitor(request: Request, interface: Optional[str] = None):
    require_role(request, "operator")
    tm_inst = get_traffic_monitor()
    result = tm_inst.start(interface=interface)
    activity_logger.log_system("Traffic monitor started via API")
    return result


@router.post("/traffic/stop")
async def stop_traffic_monitor(request: Request):
    require_role(request, "operator")
    tm_inst = get_traffic_monitor()
    result = tm_inst.stop()
    activity_logger.log_system("Traffic monitor stopped via API")
    return result


@router.get("/logs")
async def get_logs(lines: int = 50):
    try:
        from core.logger import activity_logger
        logs = activity_logger.get_logs(lines)
        return {"logs": logs}
    except Exception as e:
        return {"logs": [], "error": str(e)}


@router.get("/vuln/scan/{ip}")
async def scan_vulnerabilities(ip: str, db: Session = Depends(get_db)):
    device = db.query(NetworkDevice).filter_by(ip_address=ip).first()
    
    ports = []
    if device:
        port_results = db.query(PortScanResult).filter_by(device_id=device.id, state='open').all()
        ports = [{'port': p.port, 'service': p.service, 'state': p.state} for p in port_results]
    
    if not ports:
        ports = [{'port': 80, 'service': 'http', 'state': 'open'}]
    
    result = vuln_scanner.scan_for_vulnerabilities(ip, ports)
    
    if device:
        device.risk_score = result.risk_score
        db.commit()
    
    return {
        "target": ip,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "vulnerabilities": [
            {
                "cve": v.cve,
                "description": v.description,
                "severity": v.severity,
                "cvss": v.cvss,
                "port": v.port,
                "service": v.service
            }
            for v in result.vulnerabilities
        ],
        "recommendations": result.recommendations,
        "scan_time": result.scan_time.isoformat()
    }


@router.get("/vuln/db/{service}")
async def get_service_cves(service: str):
    cves = vuln_scanner.get_cve_details(service)
    return {"service": service, "cves": cves}


@router.post("/defense/block/{ip}")
async def block_ip(ip: str, request: Request, db: Session = Depends(get_db)):
    require_role(request, "operator")
    ad = get_auto_defense()
    result = ad.block_device(ip, reason="Manual block via API")
    return result


@router.post("/defense/unblock/{ip}")
async def unblock_ip(ip: str, request: Request, db: Session = Depends(get_db)):
    require_role(request, "operator")
    ad = get_auto_defense()
    result = ad.unblock_device(ip)
    return result


@router.post("/defense/quarantine/{ip}")
async def quarantine_ip(
    ip: str,
    profile: str = "restricted_network",
    scope: str = "lan_traffic",
    ports: Optional[str] = None,
    request: Request = None,
    db: Session = Depends(get_db),
):
    require_role(request, "operator")
    ad = get_auto_defense()
    parsed_ports = []
    if ports:
        parsed_ports = [
            int(segment.strip())
            for segment in ports.split(",")
            if segment.strip().isdigit()
        ]
    return ad.quarantine_device(
        ip,
        reason="Manual quarantine via API",
        profile=profile,
        scope=scope,
        ports=parsed_ports,
        trigger_reason="manual_quarantine",
    )


@router.post("/defense/unquarantine/{ip}")
async def unquarantine_ip(ip: str, request: Request, db: Session = Depends(get_db)):
    require_role(request, "operator")
    ad = get_auto_defense()
    return ad.unquarantine_device(ip)


@router.get("/defense/blocked")
async def get_blocked_ips(db: Session = Depends(get_db)):
    ad = get_auto_defense()
    blocked = ad.get_blocked_ips()
    return {"blocked_ips": blocked}


@router.get("/defense/quarantined")
async def get_quarantined_devices(db: Session = Depends(get_db)):
    devices = db.query(NetworkDevice).filter_by(status="quarantined").all()
    return {
        "devices": [
            {
                "ip_address": device.ip_address,
                "hostname": device.hostname,
                "risk_score": device.risk_score,
                "status": device.status,
                "containment": (device.device_info or {}).get("containment", {}),
            }
            for device in devices
        ]
    }


@router.get("/defense/rules")
async def get_defense_rules(db: Session = Depends(get_db)):
    ad = get_auto_defense()
    return ad.get_defense_rules()


@router.get("/defense/status")
async def get_defense_status(db: Session = Depends(get_db)):
    ad = get_auto_defense()
    return ad.get_firewall_status()


@router.get("/defense/playbooks")
async def get_defense_playbooks(db: Session = Depends(get_db)):
    ad = get_auto_defense()
    return {"playbooks": ad.get_playbooks()}


@router.post("/defense/playbooks/{playbook_name}/execute")
async def execute_defense_playbook(playbook_name: str, request: PlaybookExecutionRequest, http_request: Request, db: Session = Depends(get_db)):
    require_role(http_request, "operator")
    ad = get_auto_defense()
    actions = ad.execute_playbook(
        playbook_name,
        request.ip_address,
        risk_score=request.risk_score or 0,
        open_ports=request.open_ports or [],
        trigger_reason=request.trigger_reason,
    )
    return {"playbook": playbook_name, "actions": actions}


@router.post("/defense/rules")
async def update_defense_rules(rule: str, value: bool, request: Request, db: Session = Depends(get_db)):
    require_role(request, "admin")
    ad = get_auto_defense()
    ad.set_defense_rule(rule, value)
    return {"status": "updated", "rule": rule, "value": value}


@router.get("/analyze/device/{ip}")
async def analyze_device_anomaly(ip: str, db: Session = Depends(get_db)):
    device = db.query(NetworkDevice).filter_by(ip_address=ip).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    ports = db.query(PortScanResult).filter_by(device_id=device.id).all()
    port_data = [{'port': p.port, 'service': p.service, 'service_version': p.service_version} for p in ports]
    
    result = anomaly_detector.analyze_device(ip, port_data)
    return result


@router.get("/analyze/network")
async def analyze_network_anomalies(db: Session = Depends(get_db)):
    devices = db.query(NetworkDevice).all()
    results = []
    
    for device in devices:
        ports = db.query(PortScanResult).filter_by(device_id=device.id).all()
        port_data = [{'port': p.port, 'service': p.service, 'service_version': p.service_version} for p in ports]
        result = anomaly_detector.analyze_device(device.ip_address, port_data)
        results.append(result)
    
    anomalies = [r for r in results if r.get('is_anomaly')]
    return {
        "total_devices": len(results),
        "anomalies_detected": len(anomalies),
        "results": results,
        "anomalies": anomalies
    }


@router.post("/analyze/train")
async def train_anomaly_model(request: Request, db: Session = Depends(get_db)):
    require_role(request, "operator")
    devices = db.query(NetworkDevice).all()
    training_data = []
    
    for device in devices[:50]:
        ports = db.query(PortScanResult).filter_by(device_id=device.id).all()
        port_data = [{'port': p.port, 'service': p.service, 'service_version': p.service_version} for p in ports]
        if port_data:
            training_data.append(port_data)
    
    if len(training_data) < 10:
        return {"status": "error", "message": "Insufficient training data (need at least 10 devices with port scans)"}
    
    success = anomaly_detector.train(training_data)
    return {"status": "success" if success else "error", "samples": len(training_data)}


@router.get("/dns/blocked")
async def get_blocked_domains():
    dns_filter, _ = get_dns_filter()
    return {"domains": dns_filter.get_blocked_domains()}


@router.post("/dns/block")
async def block_domain(domain: str, request: Request):
    require_role(request, "operator")
    if not validate_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    
    domain = sanitize_input(domain, max_length=253)
    
    dns_filter, config_store = get_dns_filter()
    success = dns_filter.add_blocked_domain(domain)
    if success:
        config_store.set("dns_blocked_domains", dns_filter.get_blocked_domains())
    return {"status": "success" if success else "error", "domain": domain}


@router.post("/dns/unblock")
async def unblock_domain(domain: str, request: Request):
    require_role(request, "operator")
    if not validate_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    
    dns_filter, config_store = get_dns_filter()
    success = dns_filter.remove_blocked_domain(domain)
    if success:
        config_store.set("dns_blocked_domains", dns_filter.get_blocked_domains())
    return {"status": "success" if success else "error", "domain": domain}


@router.get("/dns/stats")
async def get_dns_stats():
    dns_filter, _ = get_dns_filter()
    stats = dns_filter.get_stats()
    resolver_port = int(stats.get("resolver_port") or 5353)
    resolver_host = stats.get("resolver_host") or "127.0.0.1"
    default_gateway = get_default_gateway()
    current_dns_servers = get_dns_servers()
    stats["port_conflicts"] = check_port_conflicts([resolver_port])
    stats["setup_steps"] = [
        f"Point a test client DNS server to {resolver_host}:{resolver_port} first.",
        "If local testing looks good, update your router DHCP DNS setting to the SENTINEL resolver host.",
        f"Keep an upstream resolver configured, currently {stats.get('upstream_server')}, for non-blocked lookups.",
    ]
    stats["deployment_presets"] = [
        {
            "id": "windows_client",
            "title": "Windows Client Test",
            "target": "Single Windows machine",
            "summary": "Use this first to validate the sinkhole without changing the router.",
            "copy_block": f"DNS server: {resolver_host}\nPort: {resolver_port}\nFallback upstream: {stats.get('upstream_server')}",
            "steps": [
                "Open the active adapter IPv4 settings.",
                f"Set the preferred DNS server to {resolver_host}.",
                f"If you keep the resolver on port {resolver_port}, test with a local DNS client that supports custom ports before changing system-wide DNS.",
            ],
        },
        {
            "id": "linux_client",
            "title": "Linux Client Test",
            "target": "Single Linux machine",
            "summary": "Validate the resolver from one workstation before wider rollout.",
            "copy_block": f"nameserver {resolver_host}\n# resolver port {resolver_port}\n# upstream {stats.get('upstream_server')}",
            "steps": [
                "Update NetworkManager or resolv.conf for one client.",
                f"Point DNS to {resolver_host}.",
                "Confirm blocked domains resolve to the sinkhole address before broader deployment.",
            ],
        },
        {
            "id": "router_dhcp",
            "title": "Router DHCP Rollout",
            "target": "Whole LAN",
            "summary": "Use after client testing passes and ideally when the resolver listens on port 53.",
            "copy_block": (
                f"Router LAN DNS: {resolver_host}\n"
                f"Router gateway: {default_gateway or 'set per router'}\n"
                f"Current upstreams: {', '.join(current_dns_servers) if current_dns_servers else stats.get('upstream_server')}"
            ),
            "steps": [
                "Reserve the SENTINEL device IP on the router if possible.",
                f"Set DHCP/LAN DNS to {resolver_host}.",
                "For router-wide rollout, bind the resolver to port 53 instead of a test port like 5353.",
            ],
        },
        {
            "id": "monitor_only",
            "title": "Monitor-Only Fallback",
            "target": "Low-risk rollout",
            "summary": "Keep hosts-file sinkholing enabled locally while you observe traffic and alerts.",
            "copy_block": f"Hosts sinkhole: {'enabled' if stats.get('enabled') else 'disabled'}\nRedirect IP: {stats.get('redirect_ip')}",
            "steps": [
                "Use the local hosts-file sinkhole on the SENTINEL device.",
                "Keep router DNS unchanged.",
                "Watch alerts, DNS counters, and false positives before escalating to LAN-wide DNS control.",
            ],
        },
    ]
    return stats


@router.post("/dns/configure")
async def configure_dns_sinkhole(
    enabled: Optional[bool] = None,
    redirect_ip: Optional[str] = None,
    resolver_enabled: Optional[bool] = None,
    resolver_host: Optional[str] = None,
    resolver_port: Optional[int] = None,
    upstream_server: Optional[str] = None,
    request: Request = None,
):
    require_role(request, "operator")
    dns_filter, config_store = get_dns_filter()
    updates = {}
    if enabled is not None:
        updates["dns_sinkhole_enabled"] = bool(enabled)
    if redirect_ip:
        updates["dns_sinkhole_redirect_ip"] = sanitize_input(redirect_ip, max_length=64)
    if resolver_enabled is not None:
        updates["dns_resolver_enabled"] = bool(resolver_enabled)
    if resolver_host:
        updates["dns_resolver_host"] = sanitize_input(resolver_host, max_length=128)
    if resolver_port is not None:
        updates["dns_resolver_port"] = max(1, min(int(resolver_port), 65535))
    if upstream_server:
        updates["dns_upstream_server"] = sanitize_input(upstream_server, max_length=128)
    if updates:
        config_store.set_many(updates)
    dns_filter.configure(
        enabled=config_store.get("dns_sinkhole_enabled", False),
        redirect_ip=config_store.get("dns_sinkhole_redirect_ip", "0.0.0.0"),
        resolver_enabled=config_store.get("dns_resolver_enabled", False),
        resolver_host=config_store.get("dns_resolver_host", "127.0.0.1"),
        resolver_port=config_store.get("dns_resolver_port", 5353),
        upstream_server=config_store.get("dns_upstream_server", "8.8.8.8"),
    )
    return {"status": "updated", **dns_filter.get_stats()}


@router.post("/dns/sync")
async def sync_dns_sinkhole(request: Request):
    require_role(request, "operator")
    dns_filter, _ = get_dns_filter()
    return dns_filter.sync_hosts_file()


@router.get("/dns/check")
async def check_dns_domain(domain: str):
    if not validate_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    dns_filter, _ = get_dns_filter()
    return dns_filter.check_domain(domain)


@router.get("/reports/vulnerability")
async def generate_vulnerability_report(db: Session = Depends(get_db)):
    devices = db.query(NetworkDevice).all()
    vulnerabilities = db.query(Vulnerability).all()
    
    critical = [v for v in vulnerabilities if v.severity == 'critical']
    high = [v for v in vulnerabilities if v.severity == 'high']
    medium = [v for v in vulnerabilities if v.severity == 'medium']
    low = [v for v in vulnerabilities if v.severity == 'low']
    
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_devices": len(devices),
            "total_vulnerabilities": len(vulnerabilities),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low)
        },
        "risk_score": min(100, len(critical) * 20 + len(high) * 10 + len(medium) * 5),
        "recommendations": [
            "Patch critical vulnerabilities immediately",
            "Review and update firewall rules",
            "Enable auto-defense for automated protection",
            "Regular network scanning recommended"
        ]
    }
    
    return report


@router.get("/honeypot/services")
async def get_honeypot_services():
    from core.honeypot import honeypot
    return {
        "running": honeypot.get_running_services(),
        "stats": honeypot.get_stats()
    }


@router.post("/honeypot/start")
async def start_honeypot_service(port: int, service: str = "custom", request: Request = None):
    require_role(request, "operator")
    ALLOWED_PORTS = [2121, 2222, 2323, 2443, 2525, 3389, 8081, 8443]
    BLOCKED_PORTS = [1, 20, 53, 67, 68, 69, 123, 161, 389, 636, 993, 995]
    
    if not validate_port(port):
        raise HTTPException(status_code=400, detail="Invalid port number")
    
    if port not in ALLOWED_PORTS:
        if port < 1000 or port > 65535:
            raise HTTPException(status_code=403, detail="Port not allowed for honeypot")
    
    if port in BLOCKED_PORTS:
        raise HTTPException(status_code=403, detail="Port not allowed for honeypot")
    
    service = sanitize_input(service, max_length=50)
    
    from core.honeypot import honeypot
    success = honeypot.start_service(port, service)
    return {"status": "success" if success else "error", "port": port, "service": service}


@router.post("/honeypot/stop")
async def stop_honeypot_service(port: int, request: Request):
    require_role(request, "operator")
    if not validate_port(port):
        raise HTTPException(status_code=400, detail="Invalid port number")
    
    from core.honeypot import honeypot
    success = honeypot.stop_service(port)
    return {"status": "success" if success else "error", "port": port}


@router.get("/honeypot/attacks")
async def get_honeypot_attacks():
    from core.honeypot import honeypot
    return {"attacks": honeypot.get_captured_attacks()}


@router.get("/honeypot/attack/{attack_id}/report")
async def get_attack_report(attack_id: str):
    from core.honeypot import honeypot
    report = honeypot.get_analysis_report(attack_id)
    if report:
        return {"attack_id": attack_id, "report": report}
    return {"error": "Report not found", "attack_id": attack_id}


@router.get("/honeypot/attack/{attack_id}/full")
async def get_full_attack(attack_id: str):
    from core.honeypot import honeypot
    attack = honeypot.get_uncensored_attack(attack_id)
    if attack:
        return {"attack": attack}
    return {"error": "Attack not found", "attack_id": attack_id}


@router.post("/honeypot/stop-all")
async def stop_all_honeypots(request: Request):
    require_role(request, "operator")
    from core.honeypot import honeypot
    success = honeypot.stop_all_services()
    return {"status": "success" if success else "error"}


@router.get("/honeypot/stats")
async def get_honeypot_stats():
    from core.honeypot import honeypot
    return honeypot.get_stats()


@router.get("/plugins")
async def list_plugins():
    from core.plugin_manager import plugin_manager
    return {"plugins": plugin_manager.list_plugins()}


@router.post("/plugins/{name}/enable")
async def enable_plugin(name: str, request: Request):
    require_role(request, "admin")
    from core.plugin_manager import plugin_manager
    success = plugin_manager.enable_plugin(name)
    return {"status": "success" if success else "error", "plugin": name}


@router.post("/plugins/{name}/disable")
async def disable_plugin(name: str, request: Request):
    require_role(request, "admin")
    from core.plugin_manager import plugin_manager
    success = plugin_manager.disable_plugin(name)
    return {"status": "success" if success else "error", "plugin": name}


@router.post("/plugins/{name}/execute")
async def execute_plugin(name: str, request: Request, db: Session = Depends(get_db)):
    require_role(request, "operator")
    from core.plugin_manager import plugin_manager
    result = plugin_manager.execute_plugin(name)
    return {"plugin": name, "result": result}


@router.get("/system/info")
async def get_system_information():
    """Get system information - OS, network, security context"""
    return get_system_info()


@router.get("/system/network")
async def get_network_info():
    """Get network interfaces, gateway, DNS servers"""
    return {
        "interfaces": get_network_interfaces(),
        "default_gateway": get_default_gateway(),
        "dns_servers": get_dns_servers()
    }


@router.get("/system/security")
async def get_security_status():
    """Get security status - admin privileges, safe ports"""
    from core.system_integration import is_running_as_admin, get_safe_ports, is_port_safe
    return {
        "is_admin": is_running_as_admin(),
        "safe_ports": get_safe_ports(),
        "port_checks": {port: is_port_safe(port) for port in [2222, 8081, 443, 80, 53]}
    }


@router.post("/security/failed-login")
async def record_failed_login(ip: str):
    """Record failed login attempt - triggers auto-block if threshold exceeded"""
    from core.security import attack_detector, auto_defense_callback
    
    blocked = attack_detector.record_failed_login(ip)
    
    if blocked and auto_defense_callback:
        result = auto_defense_callback(
            ip,
            trigger_reason="failed_logins",
            risk_score=85,
            details={"failed_login_threshold": attack_detector.failed_login_threshold},
        )
        return {
            "status": "blocked",
            "ip": ip,
            "reason": "Brute force attack detected",
            "playbook": result.get("playbook"),
        }
    
    return {"status": "recorded", "ip": ip, "blocked": blocked}


@router.post("/security/scan-attempt")
async def record_scan_attempt(ip: str, port: int):
    """Record port scan attempt - triggers auto-block if threshold exceeded"""
    from core.security import attack_detector, auto_defense_callback
    
    detected = attack_detector.record_scan_attempt(ip, port)
    
    if detected and auto_defense_callback:
        result = auto_defense_callback(
            ip,
            trigger_reason="port_scan_pattern",
            risk_score=70,
            open_ports=[port],
            details={"port": port, "scan_threshold": attack_detector.scan_threshold},
        )
        return {
            "status": "blocked",
            "ip": ip,
            "reason": "Port scan detected",
            "playbook": result.get("playbook"),
        }
    
    return {"status": "recorded", "ip": ip, "scan_detected": detected}


@router.get("/security/attacks")
async def get_attack_info(ip: str):
    """Get attack info for an IP"""
    from core.security import attack_detector
    return attack_detector.get_attack_info(ip)


@router.get("/security/all-attacks")
async def get_all_attacks():
    """Get all attack data"""
    from core.security import attack_detector
    now = time.time()
    return {
        "failed_logins": {
            ip: len([t for t in times if now - t < 300])
            for ip, times in attack_detector.failed_logins.items()
        },
        "scan_attempts": {
            ip: len([t for t in times if now - t < 300])
            for ip, times in attack_detector.scan_attempts.items()
        }
    }


@router.post("/security/clear-attacks")
async def clear_attack_data(request: Request):
    require_role(request, "operator")
    """Clear attack detection data"""
    from core.security import attack_detector
    attack_detector.clear_expired()
    return {"status": "cleared"}
