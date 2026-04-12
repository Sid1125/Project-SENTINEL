import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

CVE_DATABASE = {
    'ssh': [
        {'cve': 'CVE-2023-48795', 'description': 'OpenSSH regreSSHion vulnerability', 'severity': 'medium', 'cvss': 7.8},
        {'cve': 'CVE-2023-38408', 'description': 'OpenSSH remote code execution', 'severity': 'critical', 'cvss': 9.8},
    ],
    'telnet': [
        {'cve': 'CVE-2020-10199', 'description': 'Telnet service vulnerability', 'severity': 'high', 'cvss': 8.1},
    ],
    'ftp': [
        {'cve': 'CVE-2021-40444', 'description': 'FTP server remote code execution', 'severity': 'critical', 'cvss': 10.0},
        {'cve': 'CVE-2022-24387', 'description': 'FTP brute force vulnerability', 'severity': 'medium', 'cvss': 6.5},
    ],
    'smb': [
        {'cve': 'CVE-2017-0143', 'description': 'EternalBlue SMB vulnerability', 'severity': 'critical', 'cvss': 9.8},
        {'cve': 'CVE-2020-0796', 'description': 'SMBGhost vulnerability', 'severity': 'critical', 'cvss': 10.0},
        {'cve': 'CVE-2022-26904', 'description': 'SMB arbitrary file read', 'severity': 'high', 'cvss': 8.8},
    ],
    'rdp': [
        {'cve': 'CVE-2019-0708', 'description': 'BlueKeep vulnerability', 'severity': 'critical', 'cvss': 9.8},
        {'cve': 'CVE-2020-0618', 'description': 'RDP gateway vulnerability', 'severity': 'high', 'cvss': 8.1},
    ],
    'http': [
        {'cve': 'CVE-2021-44228', 'description': 'Log4Shell vulnerability', 'severity': 'critical', 'cvss': 10.0},
        {'cve': 'CVE-2022-22965', 'description': 'Spring4Shell vulnerability', 'severity': 'critical', 'cvss': 9.8},
    ],
    'mysql': [
        {'cve': 'CVE-2021-25321', 'description': 'MySQL remote code execution', 'severity': 'critical', 'cvss': 9.8},
        {'cve': 'CVE-2022-21416', 'description': 'MySQL authentication bypass', 'severity': 'high', 'cvss': 8.1},
    ],
    'postgresql': [
        {'cve': 'CVE-2024-1597', 'description': 'PostgreSQL SQL injection', 'severity': 'high', 'cvss': 8.8},
    ],
    'redis': [
        {'cve': 'CVE-2021-41099', 'description': 'Redis unauthorized access', 'severity': 'critical', 'cvss': 9.8},
    ],
    'mongodb': [
        {'cve': 'CVE-2023-2033', 'description': 'MongoDB authentication bypass', 'severity': 'high', 'cvss': 8.6},
    ],
    'apache': [
        {'cve': 'CVE-2021-41773', 'description': 'Apache path traversal', 'severity': 'high', 'cvss': 8.2},
        {'cve': 'CVE-2022-28327', 'description': 'Apache mod_dav vulnerability', 'severity': 'medium', 'cvss': 6.5},
    ],
    'nginx': [
        {'cve': 'CVE-2021-23017', 'description': 'Nginx resolver vulnerability', 'severity': 'medium', 'cvss': 6.5},
    ],
    'rpc': [
        {'cve': 'CVE-2022-26904', 'description': 'MSRPC remote code execution', 'severity': 'critical', 'cvss': 9.8},
    ],
    'dns': [
        {'cve': 'CVE-2023-3341', 'description': 'BIND9 buffer overflow', 'severity': 'high', 'cvss': 8.1},
    ],
    'vnc': [
        {'cve': 'CVE-2022-29865', 'description': 'VNC authentication bypass', 'severity': 'high', 'cvss': 8.8},
    ],
}

RISK_PORTS = {
    21: {'service': 'ftp', 'risk': 'high', 'reason': 'Unencrypted file transfer'},
    22: {'service': 'ssh', 'risk': 'medium', 'reason': 'Secure but targeted for brute force'},
    23: {'service': 'telnet', 'risk': 'critical', 'reason': 'Unencrypted remote access'},
    25: {'service': 'smtp', 'risk': 'medium', 'reason': 'Email relay'},
    53: {'service': 'dns', 'risk': 'high', 'reason': 'DNS cache poisoning risk'},
    110: {'service': 'pop3', 'risk': 'medium', 'reason': 'Unencrypted email'},
    135: {'service': 'rpc', 'risk': 'high', 'reason': 'Windows RPC, exploit target'},
    139: {'service': 'netbios', 'risk': 'high', 'reason': 'SMB over NetBIOS'},
    143: {'service': 'imap', 'risk': 'medium', 'reason': 'Unencrypted email'},
    443: {'service': 'https', 'risk': 'low', 'reason': 'Encrypted web (safe if updated)'},
    445: {'service': 'smb', 'risk': 'critical', 'reason': 'Ransomware target, EternalBlue'},
    465: {'service': 'smtps', 'risk': 'low', 'reason': 'Encrypted email'},
    587: {'service': 'smtp', 'risk': 'medium', 'reason': 'Email submission'},
    993: {'service': 'imaps', 'risk': 'low', 'reason': 'Encrypted email'},
    995: {'service': 'pop3s', 'risk': 'low', 'reason': 'Encrypted email'},
    1433: {'service': 'mssql', 'risk': 'high', 'reason': 'Database, common target'},
    1521: {'service': 'oracle', 'risk': 'high', 'reason': 'Oracle database'},
    3306: {'service': 'mysql', 'risk': 'high', 'reason': 'MySQL database'},
    3389: {'service': 'rdp', 'risk': 'critical', 'reason': 'Remote desktop, BlueKeep'},
    5432: {'service': 'postgresql', 'risk': 'high', 'reason': 'PostgreSQL database'},
    5900: {'service': 'vnc', 'risk': 'high', 'reason': 'Unencrypted remote desktop'},
    6379: {'service': 'redis', 'risk': 'critical', 'reason': 'No authentication by default'},
    8080: {'service': 'http-proxy', 'risk': 'high', 'reason': 'Admin interfaces'},
    8443: {'service': 'https-alt', 'risk': 'medium', 'reason': 'Alternative HTTPS'},
    27017: {'service': 'mongodb', 'risk': 'high', 'reason': 'MongoDB database'},
}

@dataclass
class Vulnerability:
    cve: str
    description: str
    severity: str
    cvss: float
    port: int = 0
    service: str = ""

@dataclass
class VulnerabilityScanResult:
    target: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "unknown"
    scan_time: datetime = field(default_factory=datetime.utcnow)
    recommendations: List[str] = field(default_factory=list)

class VulnerabilityScanner:
    def __init__(self):
        self.cve_db = CVE_DATABASE
        self.risk_ports = RISK_PORTS
        
    def scan_for_vulnerabilities(self, target: str, ports: List[Dict]) -> VulnerabilityScanResult:
        """Scan target for known vulnerabilities"""
        
        # Security: Validate target is a valid IP/domain
        from core.security import validate_ip_address, validate_domain
        if not (validate_ip_address(target) or validate_domain(target)):
            raise ValueError(f"Invalid scan target: {target}")
        
        result = VulnerabilityScanResult(target=target)
        
        critical_count = 0
        high_count = 0
        medium_count = 0
        
        for port_info in ports:
            port = port_info.get('port', 0)
            service = port_info.get('service', '').lower()
            state = port_info.get('state', '')
            
            if state != 'open':
                continue
            
            if port in self.risk_ports:
                risk_info = self.risk_ports[port]
                result.recommendations.append(
                    f"Port {port} ({risk_info['service']}): {risk_info['reason']}"
                )
                
                if risk_info['risk'] == 'critical':
                    critical_count += 1
                elif risk_info['risk'] == 'high':
                    high_count += 1
                else:
                    medium_count += 1
            
            if service in self.cve_db:
                for cve in self.cve_db[service]:
                    vuln = Vulnerability(
                        cve=cve['cve'],
                        description=cve['description'],
                        severity=cve['severity'],
                        cvss=cve['cvss'],
                        port=port,
                        service=service
                    )
                    result.vulnerabilities.append(vuln)
                    
                    if cve['severity'] == 'critical':
                        critical_count += 1
                    elif cve['severity'] == 'high':
                        high_count += 1
                    else:
                        medium_count += 1
        
        result.risk_score = (critical_count * 10) + (high_count * 5) + (medium_count * 2)
        result.risk_score = min(result.risk_score, 100)
        
        if result.risk_score >= 70:
            result.risk_level = "critical"
        elif result.risk_score >= 40:
            result.risk_level = "high"
        elif result.risk_score >= 20:
            result.risk_level = "medium"
        elif result.risk_score >= 10:
            result.risk_level = "low"
        else:
            result.risk_level = "minimal"
        
        if critical_count > 0:
            result.recommendations.insert(0, f"CRITICAL: {critical_count} critical vulnerabilities found!")
        if high_count > 0:
            result.recommendations.insert(1, f"HIGH: {high_count} high-risk vulnerabilities found!")
            
        return result
    
    def get_cve_details(self, service: str) -> List[Dict]:
        """Get CVE details for a service"""
        return self.cve_db.get(service.lower(), [])
    
    def get_risk_port_info(self, port: int) -> Optional[Dict]:
        """Get risk information for a specific port"""
        return self.risk_ports.get(port)
    
    def scan_target(self, target: str) -> VulnerabilityScanResult:
        """Quick scan target for vulnerabilities"""
        from core.scanner import NetworkScanner
        scanner = NetworkScanner()
        
        ports = scanner.port_scan(target, ports="1-1000")
        open_ports = [p for p in ports if p.get('state') == 'open']
        
        return self.scan_for_vulnerabilities(target, open_ports)

vuln_scanner = VulnerabilityScanner()
