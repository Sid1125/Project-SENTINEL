from fastapi import WebSocket, WebSocketDisconnect
from typing import List
import json
import asyncio
import logging

from core.scanner import NetworkScanner
from core.threats import ThreatIntelligence
from ai.nlp import NLPProcessor, LocalLLM
from api.event_stream import register_listener

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def send_message(self, message: dict, websocket: WebSocket = None):
        if websocket:
            await websocket.send_json(message)
        else:
            for connection in self.active_connections:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to send message: {e}")
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Failed to broadcast: {e}")

manager = ConnectionManager()
register_listener(manager.broadcast)
scanner = NetworkScanner()
threat_intel = ThreatIntelligence()
llm = LocalLLM()
nlp = NLPProcessor(llm)

def save_devices_to_db(devices: list):
    """Save discovered devices to database"""
    try:
        from models.database import SessionLocal
        from models.schemas import NetworkDevice
        from datetime import datetime
        
        db = SessionLocal()
        try:
            saved_count = 0
            for dev in devices:
                ip = dev.get('ip_address')
                if not ip:
                    continue
                
                status_val = dev.get('status')
                if isinstance(status_val, dict):
                    status_val = status_val.get('state', 'unknown')
                elif not isinstance(status_val, str):
                    status_val = 'unknown'
                    
                existing = db.query(NetworkDevice).filter_by(ip_address=ip).first()
                if existing:
                    existing.last_seen = datetime.utcnow()
                    if dev.get('mac_address'):
                        existing.mac_address = dev['mac_address']
                    if dev.get('hostname'):
                        existing.hostname = dev['hostname']
                    if dev.get('vendor'):
                        existing.vendor = dev['vendor']
                else:
                    new_device = NetworkDevice(
                        ip_address=ip,
                        mac_address=dev.get('mac_address'),
                        hostname=dev.get('hostname'),
                        vendor=dev.get('vendor'),
                        status=status_val,
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow()
                    )
                    db.add(new_device)
                    saved_count += 1
            
            if saved_count > 0 or len(devices) > 0:
                db.commit()
                logger.info(f"Saved {saved_count} new devices to database")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Failed to save devices to DB: {e}")

def create_threat_alert(device_ip: str, risk_score: float, ports: list):
    """Create alert for detected threats"""
    try:
        from models.database import SessionLocal
        from models.schemas import Alert
        from datetime import datetime
        
        if risk_score < 40:
            return
            
        severity = 'critical' if risk_score >= 70 else 'high'
        
        db = SessionLocal()
        try:
            alert = Alert(
                alert_type='threat_detected',
                severity=severity,
                title=f"High risk device detected: {device_ip}",
                message=f"Device has risk score {risk_score}/100 with {len(ports)} open ports",
                source_ip=device_ip,
                is_resolved=False,
                created_at=datetime.utcnow()
            )
            db.add(alert)
            db.commit()
            logger.info(f"Created threat alert for {device_ip}")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Failed to create alert: {e}")

async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                await handle_websocket_message(websocket, message)
            except json.JSONDecodeError:
                await manager.send_message({"error": "Invalid JSON"}, websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

async def handle_websocket_message(websocket: WebSocket, message: dict):
    msg_type = message.get('type')
    payload = message.get('payload', {})
    
    if msg_type == 'scan_network':
        await manager.send_message({"type": "scan_started", "payload": {"action": "network_scan"}}, websocket)
        
        devices = scanner.arp_scan()
        save_devices_to_db(devices)
        
        await manager.send_message({
            "type": "scan_complete",
            "payload": {"action": "network_scan", "devices": devices, "count": len(devices)}
        }, websocket)
    
    elif msg_type == 'scan_ports':
        target = payload.get('target')
        if not target:
            await manager.send_message({"type": "error", "payload": {"message": "No target specified"}}, websocket)
            return
        
        await manager.send_message({"type": "scan_started", "payload": {"action": "port_scan", "target": target}}, websocket)
        
        ports = scanner.port_scan(target, ports="1-1000")
        analysis = threat_intel.analyze_device(ports)
        
        if analysis.get('risk_score', 0) >= 40:
            create_threat_alert(target, analysis.get('risk_score', 0), ports)
        
        await manager.send_message({
            "type": "scan_complete",
            "payload": {
                "action": "port_scan",
                "target": target,
                "ports": ports,
                "analysis": analysis
            }
        }, websocket)
    
    elif msg_type == 'full_scan':
        target = payload.get('target')
        quick = payload.get('quick', False)
        
        if not target:
            await manager.send_message({"type": "error", "payload": {"message": "No target specified"}}, websocket)
            return
        
        await manager.send_message({"type": "scan_started", "payload": {"action": "full_scan", "target": target}}, websocket)
        
        result = scanner.full_scan(target, quick=quick)
        
        await manager.send_message({
            "type": "scan_complete",
            "payload": {"action": "full_scan", "result": result}
        }, websocket)
    
    elif msg_type == 'nlp_prompt':
        prompt = payload.get('prompt')
        if not prompt:
            await manager.send_message({"type": "error", "payload": {"message": "No prompt provided"}}, websocket)
            return
        
        await manager.send_message({"type": "processing", "payload": {"message": "Processing your request..."}}, websocket)
        
        intent_data = nlp.parse_intent(prompt)
        intent = intent_data.get('intent')
        entities = intent_data.get('entities', {})
        
        result_data = {}
        
        if intent == 'scan_network':
            devices = scanner.arp_scan()
            save_devices_to_db(devices)
            result_data = {'devices': devices}
        elif intent == 'scan_ports' or intent == 'scan_device':
            target = entities.get('ips', [None])[0] if entities.get('ips') else None
            if not target:
                target = entities.get('networks', [None])[0]
            if target:
                ports = scanner.port_scan(target)
                analysis = threat_intel.analyze_device(ports)
                if analysis.get('risk_score', 0) >= 40:
                    create_threat_alert(target, analysis.get('risk_score', 0), ports)
                result_data = {'ports': ports, 'target': target, 'analysis': analysis}
        elif intent == 'get_status':
            result_data = {'message': 'Use REST API for status'}
        
        response_text = nlp.generate_response(intent, result_data)
        
        await manager.send_message({
            "type": "nlp_response",
            "payload": {
                "intent": intent,
                "result": result_data,
                "response": response_text
            }
        }, websocket)
    
    elif msg_type == 'block_device':
        target = payload.get('target')
        if not target:
            await manager.send_message({"type": "error", "payload": {"message": "No target specified"}}, websocket)
            return
        
        try:
            from models.database import SessionLocal
            from models.schemas import NetworkDevice
            db = SessionLocal()
            try:
                device = db.query(NetworkDevice).filter_by(ip_address=target).first()
                if device:
                    device.is_blocked = True
                    db.commit()
                    await manager.send_message({
                        "type": "device_updated",
                        "payload": {"action": "blocked", "ip": target}
                    }, websocket)
                else:
                    await manager.send_message({
                        "type": "error",
                        "payload": {"message": f"Device {target} not found"}
                    }, websocket)
            finally:
                db.close()
        except Exception as e:
            await manager.send_message({
                "type": "error",
                "payload": {"message": str(e)}
            }, websocket)
    
    elif msg_type == 'trust_device':
        target = payload.get('target')
        if not target:
            await manager.send_message({"type": "error", "payload": {"message": "No target specified"}}, websocket)
            return
        
        try:
            from models.database import SessionLocal
            from models.schemas import NetworkDevice
            db = SessionLocal()
            try:
                device = db.query(NetworkDevice).filter_by(ip_address=target).first()
                if device:
                    device.is_trusted = True
                    device.risk_score = 0
                    db.commit()
                    await manager.send_message({
                        "type": "device_updated",
                        "payload": {"action": "trusted", "ip": target}
                    }, websocket)
                else:
                    await manager.send_message({
                        "type": "error",
                        "payload": {"message": f"Device {target} not found"}
                    }, websocket)
            finally:
                db.close()
        except Exception as e:
            await manager.send_message({
                "type": "error",
                "payload": {"message": str(e)}
            }, websocket)
    
    elif msg_type == 'ping':
        await manager.send_message({"type": "pong", "payload": {}}, websocket)
    
    else:
        await manager.send_message({"type": "error", "payload": {"message": f"Unknown message type: {msg_type}"}}, websocket)
