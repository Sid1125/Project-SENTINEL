import os
import sys
from pathlib import Path
from datetime import datetime
import asyncio

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import json

from models.database import init_db, check_db_connection, settings, SessionLocal
from api import routes
from api.event_stream import clear_event_loop, set_event_loop
from api.websocket import websocket_endpoint

from core.logger import ActivityLogger, activity_logger
from core.scanner import NetworkScanner
from core.threats import ThreatIntelligence
from core.auto_scanner import AutoScanner, auto_scanner
from core.traffic_monitor import TrafficMonitor, traffic_monitor
from core.auto_defense import AutoDefenseEngine, init_auto_defense
from core.security import SecurityMiddleware
from core.auth import is_authorized_request, unauthorized_response
from core.honeypot import honeypot
from core.config_store import ConfigStore
from core.event_logger import SecurityEventLogger
from core.system_integration import check_port_conflicts
from ai.nlp import LocalLLM

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

auto_defense = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SENTINEL Backend...")
    set_event_loop(asyncio.get_running_loop())
    
    try:
        init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.warning(f"Database initialization failed: {e}. Running without persistent storage.")
    
    try:
        db_status = check_db_connection()
        if db_status:
            logger.info("Database connection verified")
    except Exception as e:
        logger.warning(f"Database check failed: {e}")
    
    global auto_scanner, traffic_monitor, auto_defense
    
    scanner = NetworkScanner()
    threat_intel = ThreatIntelligence()
    
    auto_scanner = AutoScanner(scanner, SessionLocal, threat_intel, activity_logger)
    traffic_monitor = TrafficMonitor(SessionLocal, threat_intel, activity_logger)
    auto_defense = init_auto_defense(SessionLocal, activity_logger)
    config_store = ConfigStore(SessionLocal)
    event_logger = SecurityEventLogger(SessionLocal)

    traffic_monitor.set_auto_defense(auto_defense)
    
    llm_client = LocalLLM()
    
    def auto_response_from_honeypot(ip: str, trigger_reason: str = "honeypot_attack", **details):
        """Callback to respond to honeypot attacks via playbooks"""
        result = auto_defense.respond_to_trigger(ip, trigger_reason=trigger_reason, details=details)
        if result.get("actions_taken"):
            logger.info(f"Executed honeypot response for {ip} using {result.get('playbook')}")
        return result
    
    def auto_response_from_security(
        ip: str,
        trigger_reason: str = "malicious_request",
        risk_score: float | None = None,
        open_ports=None,
        **details,
    ):
        """Callback to respond to middleware and attack-detector events via playbooks"""
        result = auto_defense.respond_to_trigger(
            ip,
            trigger_reason=trigger_reason,
            risk_score=risk_score,
            open_ports=open_ports or [],
            details=details,
        )
        if result.get("actions_taken"):
            logger.info(f"Executed security response for {ip} using {result.get('playbook')}")
        return result
    
    from core.security import set_auto_defense_callback
    set_auto_defense_callback(auto_response_from_security)
    
    honeypot.set_auto_block_callback(auto_response_from_honeypot)
    honeypot.set_llm_client(llm_client)

    from core.dns_filter import dns_filter

    dns_filter.configure(
        enabled=config_store.get("dns_sinkhole_enabled", False),
        redirect_ip=config_store.get("dns_sinkhole_redirect_ip", "0.0.0.0"),
        resolver_enabled=False,
        resolver_host=config_store.get("dns_resolver_host", "127.0.0.1"),
        resolver_port=config_store.get("dns_resolver_port", 5353),
        upstream_server=config_store.get("dns_upstream_server", "8.8.8.8"),
    )
    dns_filter.replace_blocklist(config_store.get("dns_blocked_domains", []))

    if config_store.get("traffic_autostart", False):
        traffic_monitor.start(interface=config_store.get("traffic_interface", "auto"))

    if config_store.get("dns_resolver_enabled", False):
        resolver_port = int(config_store.get("dns_resolver_port", 5353))
        conflicts = check_port_conflicts([resolver_port])
        if conflicts.get(resolver_port) and not dns_filter.get_stats().get("resolver_running"):
            message = f"DNS resolver autostart skipped because port {resolver_port} is already in use"
            logger.warning(message)
            event_logger.record(
                event_type="dns_resolver_autostart_skipped",
                source="dns_filter",
                title="DNS resolver autostart skipped",
                message=message,
                severity="warning",
                metadata={"resolver_port": resolver_port, "reason": "port_conflict"},
            )
        else:
            dns_filter.configure(
                resolver_enabled=True,
                resolver_host=config_store.get("dns_resolver_host", "127.0.0.1"),
                resolver_port=resolver_port,
                upstream_server=config_store.get("dns_upstream_server", "8.8.8.8"),
            )
            resolver_stats = dns_filter.get_stats()
            if resolver_stats.get("last_resolver_error"):
                event_logger.record(
                    event_type="dns_resolver_autostart_failed",
                    source="dns_filter",
                    title="DNS resolver autostart failed",
                    message=resolver_stats.get("last_resolver_error"),
                    severity="warning",
                    metadata={
                        "resolver_host": resolver_stats.get("resolver_host"),
                        "resolver_port": resolver_stats.get("resolver_port"),
                    },
                )
            elif resolver_stats.get("resolver_running"):
                event_logger.record(
                    event_type="dns_resolver_started",
                    source="dns_filter",
                    title="DNS resolver started",
                    message=f"Resolver listening on {resolver_stats.get('resolver_host')}:{resolver_stats.get('resolver_port')}",
                    metadata={
                        "resolver_host": resolver_stats.get("resolver_host"),
                        "resolver_port": resolver_stats.get("resolver_port"),
                        "upstream_server": resolver_stats.get("upstream_server"),
                    },
                )

    activity_logger.log_system("Sentinel backend started")
    logger.info("Auto scanner, traffic monitor, honeypot, and auto defense initialized")
    
    yield
    
    if auto_scanner and auto_scanner.running:
        auto_scanner.stop()
    if traffic_monitor and traffic_monitor.running:
        traffic_monitor.stop()
    try:
        from core.dns_filter import dns_filter
        dns_filter.stop_resolver()
    except Exception:
        pass
    
    activity_logger.log_system("Sentinel backend shutdown")
    clear_event_loop()
    logger.info("Shutting down SENTINEL Backend...")

app = FastAPI(
    title="SENTINEL API",
    description="Security Engine for Network Threat Intelligence, Education, Logging & Learning",
    version="1.0.0",
    lifespan=lifespan
)

# Restrict CORS - only allow localhost for security
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type"],
)

app.add_middleware(SecurityMiddleware)

app.include_router(routes.router, prefix="/api/v1")
app.websocket("/ws")(websocket_endpoint)


@app.middleware("http")
async def operator_auth_middleware(request, call_next):
    if not is_authorized_request(request):
        return unauthorized_response()
    return await call_next(request)

@app.get("/")
async def root():
    return {
        "name": "Project SENTINEL",
        "version": "1.0.0",
        "status": "online",
        "description": "Security Engine for Network Threat Intelligence, Education, Logging & Learning"
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": check_db_connection() if True else False
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
