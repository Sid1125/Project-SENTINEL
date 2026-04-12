import os
import sys
import platform
import logging
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

def get_system_info() -> Dict[str, Any]:
    """Get system information for security context"""
    return {
        'os': platform.system(),
        'os_version': platform.version(),
        'hostname': platform.node(),
        'python_version': sys.version,
        'uid': os.getuid() if hasattr(os, 'getuid') else None,
        'euid': os.geteuid() if hasattr(os, 'geteuid') else None,
        'is_admin': is_running_as_admin(),
    }

def is_running_as_admin() -> bool:
    """Check if running with admin privileges"""
    try:
        if platform.system() == 'Windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def get_network_interfaces() -> List[Dict[str, str]]:
    """Get available network interfaces"""
    interfaces = []
    try:
        if platform.system() == 'Windows':
            import subprocess
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
            # Parse output
            lines = result.stdout.split('\n')
            current_adapter = None
            for line in lines:
                if 'adapter' in line.lower() or 'adapter' in line.lower():
                    current_adapter = line.strip()
                elif 'IPv4' in line and current_adapter:
                    ip = line.split(':')[-1].strip()
                    interfaces.append({'adapter': current_adapter, 'ip': ip})
        else:
            import subprocess
            result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
            # Basic parsing
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        interfaces.append({'name': parts[-1], 'ip': parts[1].split('/')[0]})
    except Exception as e:
        logger.warning(f"Failed to get network interfaces: {e}")
    return interfaces

def get_default_gateway() -> Optional[str]:
    """Get default gateway IP"""
    try:
        if platform.system() == 'Windows':
            import subprocess
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'Default Gateway' in line:
                    ip = line.split(':')[-1].strip()
                    if ip:
                        return ip
        else:
            import subprocess
            result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, timeout=5)
            parts = result.stdout.split()
            if parts and parts[0] == 'default':
                return parts[2]
    except Exception as e:
        logger.warning(f"Failed to get default gateway: {e}")
    return None

def get_dns_servers() -> List[str]:
    """Get configured DNS servers"""
    dns_servers = []
    try:
        if platform.system() == 'Windows':
            import subprocess
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'DNS Server' in line and ':' in line:
                    ip = line.split(':')[-1].strip()
                    if ip and ip not in dns_servers:
                        dns_servers.append(ip)
        else:
            # Try common DNS config locations
            for path in ['/etc/resolv.conf', '/etc/dns.conf']:
                if Path(path).exists():
                    with open(path) as f:
                        for line in f:
                            if line.strip().startswith('nameserver'):
                                ip = line.strip().split()[-1]
                                if ip not in dns_servers:
                                    dns_servers.append(ip)
    except Exception as e:
        logger.warning(f"Failed to get DNS servers: {e}")
    return dns_servers

def get_safe_ports() -> List[int]:
    """Get list of ports that are safe for honeypot mapping"""
    return [
        2222,   # Safe SSH mapping
        2223,   # Safe SSH mapping
        8081,   # Safe HTTP mapping
        8443,   # Safe HTTPS mapping
        2221,   # Safe FTP mapping
        2225,   # Safe SMB mapping
        2025,   # Safe Telnet mapping
        23389,  # Safe RDP mapping
        2025,   # Safe SMTP mapping
    ]

def is_port_safe(port: int) -> bool:
    """Check if port is safe for honeypot or scanning"""
    # Never use these critical ports
    critical_ports = {
        80, 443,     # Normal web traffic
        53,          # DNS
        67, 68,      # DHCP
        123,         # NTP
        161, 162,    # SNMP
    }
    if port in critical_ports:
        return False
    if port < 1024 and not is_running_as_admin():
        return False
    return True

def sanitize_log_path(path: str) -> Path:
    """Sanitize and validate log file paths"""
    # Prevent path traversal
    path = path.replace('..', '').replace('~', '')
    log_dir = Path(__file__).parent.parent / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / Path(path).name

def create_secure_session_id() -> str:
    """Create a secure session identifier"""
    return str(uuid.uuid4()) + '-' + str(uuid.uuid4())

def check_port_conflicts(ports: List[int]) -> Dict[int, str]:
    """Check if ports are already in use"""
    conflicts = {}
    for port in ports:
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex(('127.0.0.1', port))
            s.close()
            if result == 0:
                conflicts[port] = 'in_use'
        except Exception:
            pass
    return conflicts
