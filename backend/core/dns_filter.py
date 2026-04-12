import logging
import platform
import socket
import socketserver
import struct
import threading
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.system_integration import is_running_as_admin
except ModuleNotFoundError:
    from backend.core.system_integration import is_running_as_admin

try:
    from api.event_stream import publish_sync
except ModuleNotFoundError:
    from backend.api.event_stream import publish_sync

logger = logging.getLogger(__name__)


class DNSFilter:
    START_MARKER = "# SENTINEL DNS SINKHOLE START"
    END_MARKER = "# SENTINEL DNS SINKHOLE END"

    def __init__(self):
        self.blocked_domains = set()
        self.custom_blocklist: List[str] = []
        self.enabled = False
        self.redirect_ip = "0.0.0.0"
        self.resolver_enabled = False
        self.resolver_host = "127.0.0.1"
        self.resolver_port = 5353
        self.upstream_server = "8.8.8.8"
        self.last_sync_at: Optional[str] = None
        self.last_error: Optional[str] = None
        self.last_resolver_error: Optional[str] = None
        self.resolver_started_at: Optional[str] = None
        self.query_count = 0
        self.blocked_query_count = 0
        self.forwarded_query_count = 0
        self.server: Optional[socketserver.ThreadingUDPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self._state_lock = threading.Lock()
        self.hosts_path = (
            r"C:\Windows\System32\drivers\etc\hosts"
            if platform.system() == "Windows"
            else "/etc/hosts"
        )

    def configure(
        self,
        *,
        enabled: Optional[bool] = None,
        redirect_ip: Optional[str] = None,
        resolver_enabled: Optional[bool] = None,
        resolver_host: Optional[str] = None,
        resolver_port: Optional[int] = None,
        upstream_server: Optional[str] = None,
    ):
        if enabled is not None:
            self.enabled = bool(enabled)
        if redirect_ip:
            self.redirect_ip = str(redirect_ip).strip() or "0.0.0.0"
        if resolver_enabled is not None:
            self.resolver_enabled = bool(resolver_enabled)
        if resolver_host:
            self.resolver_host = str(resolver_host).strip() or "127.0.0.1"
        if resolver_port:
            self.resolver_port = int(resolver_port)
        if upstream_server:
            self.upstream_server = str(upstream_server).strip() or "8.8.8.8"

        if self.resolver_enabled:
            self.start_resolver()
        else:
            self.stop_resolver()
        self._publish_stats()

    def replace_blocklist(self, domains: List[str]):
        self.blocked_domains = {self._normalize_domain(domain) for domain in domains if self._normalize_domain(domain)}

    def add_blocked_domain(self, domain: str) -> bool:
        domain = self._normalize_domain(domain)
        if not domain:
            return False
        self.blocked_domains.add(domain)
        logger.info(f"Blocked domain: {domain}")
        self._publish_stats()
        return True

    def remove_blocked_domain(self, domain: str) -> bool:
        domain = self._normalize_domain(domain)
        if domain in self.blocked_domains:
            self.blocked_domains.discard(domain)
            logger.info(f"Unblocked domain: {domain}")
            self._publish_stats()
            return True
        return False

    def get_blocked_domains(self) -> List[str]:
        return sorted(self.blocked_domains)

    def load_blocklist(self, domains: List[str]) -> int:
        count = 0
        for domain in domains:
            if self.add_blocked_domain(domain):
                count += 1
        return count

    def load_builtin_blocklists(self) -> int:
        malware_domains = [
            "malware.example.com",
            "phishing.example.com",
            "tracker.example.com",
            "ads.example.com",
        ]
        self.custom_blocklist = malware_domains
        return len(malware_domains)

    def check_domain(self, domain: str) -> Dict[str, Any]:
        domain = self._normalize_domain(domain)
        return {
            "domain": domain,
            "blocked": self._is_blocked_domain(domain),
            "enabled": self.enabled,
            "redirect_ip": self.redirect_ip,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def build_hosts_preview(self) -> str:
        lines = [self.START_MARKER]
        if self.enabled:
            for domain in self.get_blocked_domains():
                lines.append(f"{self.redirect_ip} {domain}")
                lines.append(f"{self.redirect_ip} www.{domain}")
        else:
            lines.append("# Sinkhole disabled")
        lines.append(self.END_MARKER)
        return "\n".join(lines)

    def sync_hosts_file(self) -> Dict[str, Any]:
        hosts_file = Path(self.hosts_path)
        preview = self.build_hosts_preview()

        if not is_running_as_admin():
            self.last_error = "Administrative privileges required to modify the hosts file"
            return {
                "status": "permission_required",
                "applied": False,
                "hosts_path": self.hosts_path,
                "preview": preview,
                "message": self.last_error,
            }

        try:
            existing = hosts_file.read_text(encoding="utf-8") if hosts_file.exists() else ""
            cleaned = self._strip_existing_section(existing)
            if cleaned and not cleaned.endswith("\n"):
                cleaned += "\n"
            hosts_file.write_text(f"{cleaned}{preview}\n", encoding="utf-8")
            self.last_sync_at = datetime.utcnow().isoformat()
            self.last_error = None
            self._publish_stats()
            return {
                "status": "synced",
                "applied": True,
                "hosts_path": self.hosts_path,
                "preview": preview,
                "last_sync_at": self.last_sync_at,
                "message": "Hosts file updated with SENTINEL sinkhole entries",
            }
        except Exception as exc:
            self.last_error = str(exc)
            logger.error(f"Failed to sync DNS sinkhole hosts file: {exc}")
            self._publish_stats()
            return {
                "status": "error",
                "applied": False,
                "hosts_path": self.hosts_path,
                "preview": preview,
                "message": str(exc),
            }

    def start_resolver(self) -> Dict[str, Any]:
        if self.server:
            return {"status": "already_running", **self.get_stats()}

        class DNSUDPHandler(socketserver.BaseRequestHandler):
            def handle(handler_self):
                data, sock = handler_self.request
                response = self.resolve_query(data)
                if response:
                    sock.sendto(response, handler_self.client_address)

        try:
            self.server = socketserver.ThreadingUDPServer((self.resolver_host, self.resolver_port), DNSUDPHandler)
            self.server.daemon_threads = True
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            self.resolver_started_at = datetime.utcnow().isoformat()
            self.last_resolver_error = None
            self._publish_stats()
            return {"status": "started", **self.get_stats()}
        except Exception as exc:
            self.last_resolver_error = str(exc)
            logger.error(f"Failed to start DNS resolver: {exc}")
            self.server = None
            self.server_thread = None
            self._publish_stats()
            return {"status": "error", "message": str(exc), **self.get_stats()}

    def stop_resolver(self) -> Dict[str, Any]:
        if not self.server:
            return {"status": "already_stopped", **self.get_stats()}
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception as exc:
            logger.warning(f"Failed to stop DNS resolver cleanly: {exc}")
        finally:
            self.server = None
            self.server_thread = None
        self._publish_stats()
        return {"status": "stopped", **self.get_stats()}

    def resolve_query(self, data: bytes) -> Optional[bytes]:
        query = self._parse_query(data)
        if not query:
            return None

        with self._state_lock:
            self.query_count += 1

        domain = query["domain"]
        if self.enabled and self._is_blocked_domain(domain):
            with self._state_lock:
                self.blocked_query_count += 1
            if self.query_count <= 3 or self.blocked_query_count % 5 == 0:
                self._publish_stats()
            if query["qtype"] == 28:
                return self._build_ip_response(query["id"], query["question"], self._sinkhole_ipv6())
            if query["qtype"] == 1:
                return self._build_ip_response(query["id"], query["question"], self.redirect_ip)
            if query["qtype"] in {5, 64, 65, 255}:
                return self._build_nxdomain_response(query["id"], query["question"])
            return self._build_nxdomain_response(query["id"], query["question"])

        upstream_response = self._forward_to_upstream(data)
        if upstream_response:
            with self._state_lock:
                self.forwarded_query_count += 1
            if self.query_count <= 3 or self.forwarded_query_count % 10 == 0:
                self._publish_stats()
            return upstream_response

        self._publish_stats()
        return self._build_nxdomain_response(query["id"], query["question"])

    def _parse_query(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 12:
            return None
        query_id = struct.unpack("!H", data[:2])[0]
        offset = 12
        labels = []
        try:
            while offset < len(data):
                length = data[offset]
                offset += 1
                if length == 0:
                    break
                labels.append(data[offset:offset + length].decode("utf-8", errors="ignore"))
                offset += length
            if offset + 4 > len(data):
                return None
            question = data[12:offset + 4]
            qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
            return {
                "id": query_id,
                "domain": ".".join(part.lower() for part in labels),
                "question": question,
                "qtype": qtype,
                "qclass": qclass,
            }
        except Exception:
            return None

    def _build_ip_response(self, query_id: int, question: bytes, ip_address: str) -> bytes:
        header = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
        answer_name = struct.pack("!H", 0xC00C)
        parsed_ip = ipaddress.ip_address(ip_address)
        qtype = 28 if parsed_ip.version == 6 else 1
        answer_type_class = struct.pack("!HHI", qtype, 1, 60)
        rdata = parsed_ip.packed
        rdlength = struct.pack("!H", len(rdata))
        return header + question + answer_name + answer_type_class + rdlength + rdata

    def _build_nxdomain_response(self, query_id: int, question: bytes) -> bytes:
        header = struct.pack("!HHHHHH", query_id, 0x8183, 1, 0, 0, 0)
        return header + question

    def _forward_to_upstream(self, data: bytes) -> Optional[bytes]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2.0)
                sock.sendto(data, (self.upstream_server, 53))
                response, _ = sock.recvfrom(4096)
                return response
        except Exception as exc:
            self.last_resolver_error = str(exc)
            logger.warning(f"DNS upstream forward failed: {exc}")
            self._publish_stats()
            return None

    def get_stats(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "blocked_count": len(self.blocked_domains),
            "custom_count": len(self.custom_blocklist),
            "builtin_count": len(self.custom_blocklist),
            "platform": platform.system(),
            "hosts_path": self.hosts_path,
            "redirect_ip": self.redirect_ip,
            "is_admin": is_running_as_admin(),
            "last_sync_at": self.last_sync_at,
            "last_error": self.last_error,
            "resolver_enabled": self.resolver_enabled,
            "resolver_running": self.server is not None,
            "resolver_host": self.resolver_host,
            "resolver_port": self.resolver_port,
            "upstream_server": self.upstream_server,
            "resolver_started_at": self.resolver_started_at,
            "last_resolver_error": self.last_resolver_error,
            "query_count": self.query_count,
            "blocked_query_count": self.blocked_query_count,
            "forwarded_query_count": self.forwarded_query_count,
            "preview": self.build_hosts_preview(),
        }

    def _normalize_domain(self, domain: str) -> str:
        return str(domain or "").lower().strip().lstrip(".")

    def _is_blocked_domain(self, domain: str) -> bool:
        normalized = self._normalize_domain(domain)
        if not normalized:
            return False
        if normalized in self.blocked_domains:
            return True
        return any(
            normalized.endswith(f".{blocked_domain}")
            for blocked_domain in self.blocked_domains
        )

    def _sinkhole_ipv6(self) -> str:
        try:
            parsed_ip = ipaddress.ip_address(self.redirect_ip)
            if parsed_ip.version == 6:
                return str(parsed_ip)
        except ValueError:
            pass
        return "::"

    def _strip_existing_section(self, content: str) -> str:
        if self.START_MARKER not in content or self.END_MARKER not in content:
            return content.rstrip()
        before, _, remainder = content.partition(self.START_MARKER)
        _, _, after = remainder.partition(self.END_MARKER)
        return f"{before.rstrip()}\n{after.lstrip()}".rstrip()

    def _publish_stats(self):
        publish_sync("dns_stats", self.get_stats())


dns_filter = DNSFilter()
