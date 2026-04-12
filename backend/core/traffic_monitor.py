import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from api.event_stream import publish_sync
except ModuleNotFoundError:
    from backend.api.event_stream import publish_sync


class TrafficMonitor:
    def __init__(self, db_session, threat_intel, activity_logger):
        self.get_db = db_session
        self.threat_intel = threat_intel
        self.activity_logger = activity_logger
        self.config_store = None
        self.event_logger = None
        if db_session:
            try:
                from core.config_store import ConfigStore
                from core.event_logger import SecurityEventLogger
            except ModuleNotFoundError:
                from backend.core.config_store import ConfigStore
                from backend.core.event_logger import SecurityEventLogger
            self.config_store = ConfigStore(db_session)
            self.event_logger = SecurityEventLogger(db_session)

        self.running = False
        self.mode = "idle"
        self.interface = None
        self.last_error = None
        self.started_at = None

        self.packet_count = 0
        self.byte_count = 0
        self.protocol_counts = defaultdict(int)
        self.traffic_stats = defaultdict(int)
        self.top_talkers = defaultdict(int)
        self.destination_ports = defaultdict(int)
        self.suspicious_activity: List[Dict[str, Any]] = []
        self.scan_windows = defaultdict(deque)
        self.auto_defense = None

        self.lock = threading.Lock()
        self.sniffer = None
        self.scapy = None

        self.suspicious_ports = {23, 135, 139, 445, 3389, 4444, 5554, 8080, 8888}
        self.scan_window_seconds = 60
        self.scan_threshold = 12
        self.max_event_history = 200
        self.max_top_entries = 10
        self.telemetry_publish_interval = 25

        self._load_scapy()

    def _load_scapy(self):
        try:
            from scapy.all import AsyncSniffer, ICMP, IP, IPv6, TCP, UDP, get_if_list

            self.scapy = {
                "AsyncSniffer": AsyncSniffer,
                "IP": IP,
                "IPv6": IPv6,
                "TCP": TCP,
                "UDP": UDP,
                "ICMP": ICMP,
                "get_if_list": get_if_list,
            }
            logger.info("Traffic monitor packet capture backend ready (Scapy)")
        except Exception as exc:
            self.scapy = None
            self.last_error = f"Packet capture backend unavailable: {exc}"
            logger.warning(self.last_error)

    def set_auto_defense(self, defense_engine):
        self.auto_defense = defense_engine

    def get_available_interfaces(self) -> List[str]:
        if not self.scapy:
            return []

        try:
            return self.scapy["get_if_list"]()
        except Exception as exc:
            logger.warning(f"Failed to enumerate interfaces: {exc}")
            return []

    def start(self, interface: Optional[str] = None):
        if self.running:
            return {"status": "already_running", "mode": self.mode, "interface": self.interface}

        if not self.scapy:
            self.mode = "error"
            return {
                "status": "error",
                "mode": self.mode,
                "message": self.last_error or "Packet capture backend unavailable",
            }

        preferred_interface = interface
        if preferred_interface is None and self.config_store:
            preferred_interface = self.config_store.get("traffic_interface", "auto")
        self.interface = None if preferred_interface in (None, "", "auto") else preferred_interface
        self.last_error = None

        try:
            AsyncSniffer = self.scapy["AsyncSniffer"]
            sniff_kwargs = {
                "prn": self._handle_packet,
                "store": False,
            }
            if self.interface:
                sniff_kwargs["iface"] = self.interface

            self.sniffer = AsyncSniffer(**sniff_kwargs)
            self.sniffer.start()
            self.running = True
            self.mode = "live_capture"
            self.started_at = datetime.utcnow().isoformat()
            if self.config_store:
                self.config_store.set("traffic_interface", self.interface or "auto", description="Preferred traffic capture interface")
            if self.event_logger:
                self.event_logger.record(
                    event_type="traffic_monitor_started",
                    source="traffic_monitor",
                    title="Traffic monitor started",
                    message=f"Started live capture on {self.interface or 'auto'}",
                    metadata={"mode": self.mode, "interface": self.interface or "auto"},
                )

            if self.activity_logger:
                self.activity_logger.log_system(
                    f"Traffic monitor started (mode={self.mode}, interface={self.interface or 'auto'})"
                )

            logger.info(
                f"Traffic monitor started with live capture on interface {self.interface or 'auto'}"
            )
            self._publish_stats_snapshot()
            return {"status": "started", "mode": self.mode, "interface": self.interface or "auto"}
        except Exception as exc:
            self.sniffer = None
            self.running = False
            self.mode = "error"
            self.last_error = str(exc)
            logger.error(f"Failed to start traffic monitor: {exc}")
            if self.event_logger:
                self.event_logger.record(
                    event_type="traffic_monitor_start_failed",
                    source="traffic_monitor",
                    title="Traffic monitor failed to start",
                    message=str(exc),
                    severity="warning",
                    metadata={"interface": self.interface or "auto"},
                )
            return {
                "status": "error",
                "mode": self.mode,
                "message": str(exc),
            }

    def stop(self):
        if not self.running:
            return {"status": "already_stopped", "mode": self.mode}

        try:
            if self.sniffer:
                self.sniffer.stop()
        except Exception as exc:
            logger.warning(f"Error stopping sniffer: {exc}")
            self.last_error = str(exc)
        finally:
            self.sniffer = None
            self.running = False
            self.mode = "stopped"

        if self.activity_logger:
            self.activity_logger.log_system("Traffic monitor stopped")
        if self.event_logger:
            self.event_logger.record(
                event_type="traffic_monitor_stopped",
                source="traffic_monitor",
                title="Traffic monitor stopped",
                message="Live capture stopped",
                metadata={"mode": self.mode, "interface": self.interface or "auto"},
            )

        logger.info("Traffic monitor stopped")
        self._publish_stats_snapshot()
        return {"status": "stopped", "mode": self.mode}

    def _handle_packet(self, packet):
        try:
            event = self._extract_packet_event(packet)
            if not event:
                return

            with self.lock:
                self.packet_count += 1
                self.byte_count += event["length"]
                self.protocol_counts[event["protocol"]] += 1
                self.traffic_stats[f"{event['src_ip']}:{event['dst_port']}"] += 1
                self.top_talkers[event["src_ip"]] += 1
                self.destination_ports[str(event["dst_port"])] += 1

            self._detect_suspicious_activity(event)
            if self.packet_count % self.telemetry_publish_interval == 0:
                self._publish_stats_snapshot()
        except Exception as exc:
            logger.debug(f"Packet handling failed: {exc}")

    def _extract_packet_event(self, packet) -> Optional[Dict[str, Any]]:
        IP = self.scapy["IP"]
        IPv6 = self.scapy["IPv6"]
        TCP = self.scapy["TCP"]
        UDP = self.scapy["UDP"]
        ICMP = self.scapy["ICMP"]

        network_layer = None
        if packet.haslayer(IP):
            network_layer = packet[IP]
        elif packet.haslayer(IPv6):
            network_layer = packet[IPv6]
        else:
            return None

        protocol = "OTHER"
        src_port = None
        dst_port = None

        if packet.haslayer(TCP):
            transport = packet[TCP]
            protocol = "TCP"
            src_port = int(getattr(transport, "sport", 0) or 0)
            dst_port = int(getattr(transport, "dport", 0) or 0)
        elif packet.haslayer(UDP):
            transport = packet[UDP]
            protocol = "UDP"
            src_port = int(getattr(transport, "sport", 0) or 0)
            dst_port = int(getattr(transport, "dport", 0) or 0)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            src_port = 0
            dst_port = 0

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": getattr(network_layer, "src", "unknown"),
            "dst_ip": getattr(network_layer, "dst", "unknown"),
            "src_port": src_port or 0,
            "dst_port": dst_port or 0,
            "protocol": protocol,
            "length": int(len(packet)),
        }

    def _detect_suspicious_activity(self, event: Dict[str, Any]):
        suspicious_reasons = []
        src_ip = event["src_ip"]
        dst_port = event["dst_port"]

        if dst_port in self.suspicious_ports:
            suspicious_reasons.append("suspicious_port_detected")

        now = time.time()
        scan_window = self.scan_windows[src_ip]
        scan_window.append((now, dst_port))
        while scan_window and now - scan_window[0][0] > self.scan_window_seconds:
            scan_window.popleft()

        unique_ports = {port for _, port in scan_window if port > 0}
        if len(unique_ports) >= self.scan_threshold:
            suspicious_reasons.append("port_scan_pattern")

        if not suspicious_reasons:
            return

        for reason in suspicious_reasons:
            self._log_suspicious(
                ip=src_ip,
                port=dst_port,
                reason=reason,
                protocol=event["protocol"],
                dst_ip=event["dst_ip"],
            )

    def _log_suspicious(self, ip: str, port: int, reason: str, protocol: str, dst_ip: str):
        entry = {
            "ip": ip,
            "port": port,
            "reason": reason,
            "protocol": protocol,
            "dst_ip": dst_ip,
            "timestamp": datetime.utcnow().isoformat(),
        }

        with self.lock:
            self.suspicious_activity.append(entry)
            if len(self.suspicious_activity) > self.max_event_history:
                self.suspicious_activity = self.suspicious_activity[-self.max_event_history :]

        if self.activity_logger:
            self.activity_logger.log_threat_detected(ip, 50 if reason != "port_scan_pattern" else 70, [port])

        if self.auto_defense and reason in {"suspicious_port_detected", "port_scan_pattern"}:
            risk_score = 60 if reason == "suspicious_port_detected" else 85
            self.auto_defense.evaluate_and_respond(ip, risk_score, [port], trigger_reason=reason)

        logger.warning(f"Suspicious traffic: {ip}:{port} ({protocol}) -> {dst_ip} [{reason}]")

    def _top_items(self, data: Dict[str, int]) -> List[Dict[str, Any]]:
        return [
            {"key": key, "count": count}
            for key, count in sorted(data.items(), key=lambda item: item[1], reverse=True)[: self.max_top_entries]
        ]

    def get_stats(self):
        with self.lock:
            suspicious_tail = list(self.suspicious_activity[-10:])
            protocol_counts = dict(self.protocol_counts)
            top_talkers = self._top_items(dict(self.top_talkers))
            top_ports = self._top_items(dict(self.destination_ports))
            traffic_stats = dict(self.traffic_stats)

        return {
            "running": self.running,
            "mode": self.mode,
            "interface": self.interface or "auto",
            "started_at": self.started_at,
            "last_error": self.last_error,
            "packets_captured": self.packet_count,
            "bytes_captured": self.byte_count,
            "protocol_counts": protocol_counts,
            "traffic_stats": traffic_stats,
            "top_talkers": top_talkers,
            "top_destination_ports": top_ports,
            "suspicious_count": len(self.suspicious_activity),
            "suspicious_activity": suspicious_tail,
            "available_interfaces": self.get_available_interfaces(),
        }

    def get_stats_summary(self):
        return {
            "total_packets": self.packet_count,
            "total_bytes": self.byte_count,
            "total_connections": len(self.traffic_stats),
            "suspicious_events": len(self.suspicious_activity),
            "monitoring": self.running,
            "mode": self.mode,
        }

    def _publish_stats_snapshot(self):
        publish_sync("traffic_stats", self.get_stats())


traffic_monitor = TrafficMonitor(None, None, None)
