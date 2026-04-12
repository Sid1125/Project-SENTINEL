import json
import logging
import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import os

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    def __init__(self, db=None):
        self.db = db
        self.cve_cache = {}
        self.blacklist_cache = []
        self.threat_feeds = {
            'common_ports': self._get_common_vulnerable_ports(),
            'suspicious_services': self._get_suspicious_services()
        }
    
    def _get_common_vulnerable_ports(self) -> Dict[int, Dict]:
        return {
            21: {'service': 'FTP', 'risk': 'high', 'reason': 'Unencrypted file transfer, often brute forced'},
            23: {'service': 'Telnet', 'risk': 'critical', 'reason': 'Unencrypted, credentials exposed'},
            25: {'service': 'SMTP', 'risk': 'medium', 'reason': 'Open relay, spam'},
            110: {'service': 'POP3', 'risk': 'medium', 'reason': 'Unencrypted credentials'},
            135: {'service': 'RPC', 'risk': 'high', 'reason': 'Windows RPC, frequent target'},
            139: {'service': 'NetBIOS', 'risk': 'high', 'reason': 'SMB over NetBIOS, internal recon'},
            445: {'service': 'SMB', 'risk': 'critical', 'reason': 'EternalBlue, lateral movement'},
            1433: {'service': 'MSSQL', 'risk': 'high', 'reason': 'Database exposed'},
            1434: {'service': 'MSSQL Browser', 'risk': 'medium', 'reason': 'Info disclosure'},
            3306: {'service': 'MySQL', 'risk': 'high', 'reason': 'Database exposed'},
            3389: {'service': 'RDP', 'risk': 'critical', 'reason': 'BlueKeep, brute force'},
            5432: {'service': 'PostgreSQL', 'risk': 'high', 'reason': 'Database exposed'},
            5900: {'service': 'VNC', 'risk': 'high', 'reason': 'Unencrypted remote desktop'},
            6379: {'service': 'Redis', 'risk': 'high', 'reason': 'No auth by default'},
            8080: {'service': 'HTTP-Proxy', 'risk': 'medium', 'reason': 'Admin interfaces'},
            8443: {'service': 'HTTPS-Alt', 'risk': 'medium', 'reason': 'Admin interfaces'},
            27017: {'service': 'MongoDB', 'risk': 'high', 'reason': 'No auth by default'}
        }
    
    def _get_suspicious_services(self) -> Dict[str, Dict]:
        return {
            'telnet': {'risk': 'critical', 'reason': 'Unencrypted remote access'},
            'ftp': {'risk': 'high', 'reason': 'Unencrypted file transfer'},
            'ssh': {'risk': 'low', 'reason': 'Encrypted but target for brute force'},
            'smb': {'risk': 'high', 'reason': 'Common target for ransomware'},
            'rdp': {'risk': 'critical', 'reason': 'Target for ransomware'},
            'mysql': {'risk': 'medium', 'reason': 'Check for weak passwords'},
            'redis': {'risk': 'high', 'reason': 'Often no authentication'},
            'mongodb': {'risk': 'high', 'reason': 'Often no authentication'}
        }
    
    def analyze_port(self, port: int, service: str = None, version: str = None) -> Dict[str, Any]:
        """Analyze a single port for risk assessment"""
        port_info = self.threat_feeds['common_ports'].get(port, {})
        service_info = self.threat_feeds['suspicious_services'].get(service.lower() if service else '', {})
        
        risk_level = 'low'
        reasons = []
        
        if port_info:
            risk_level = port_info.get('risk', 'low')
            reasons.append(f"Port {port} ({port_info.get('service')}): {port_info.get('reason')}")
        
        if service_info:
            service_risk = service_info.get('risk', 'low')
            if self._risk_to_numeric(service_risk) > self._risk_to_numeric(risk_level):
                risk_level = service_risk
            reasons.append(f"Service {service}: {service_info.get('reason')}")
        
        return {
            'port': port,
            'service': service,
            'version': version,
            'risk_level': risk_level,
            'reasons': reasons,
            'recommendations': self._get_recommendations(risk_level, service)
        }
    
    def _risk_to_numeric(self, risk: str) -> int:
        mapping = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return mapping.get(risk.lower(), 0)
    
    def _get_recommendations(self, risk_level: str, service: str = None) -> List[str]:
        recommendations = []
        
        if risk_level in ['critical', 'high']:
            recommendations.append(f"Consider blocking port" + (f" {service}" if service else ""))
            recommendations.append("Implement network segmentation")
            recommendations.append("Enable firewall rules to restrict access")
        
        if service in ['telnet', 'ftp']:
            recommendations.append("Replace with SSH/SFTP")
        
        if service in ['rdp', 'smb']:
            recommendations.append("Enable MFA if possible")
            recommendations.append("Restrict to VPN or specific IPs")
        
        if not recommendations:
            recommendations.append("Continue monitoring")
        
        return recommendations
    
    def check_blacklist(self, ip: str) -> Optional[Dict]:
        """Check if IP is in blacklist"""
        for entry in self.blacklist_cache:
            if entry.get('ip') == ip and entry.get('active', True):
                return entry
        return None
    
    def analyze_device(self, ports: List[Dict], hostname: str = None, os_guess: str = None) -> Dict[str, Any]:
        """Analyze device for overall risk score"""
        total_risk = 0
        findings = []
        
        for port_entry in ports:
            port = port_entry.get('port')
            service = port_entry.get('service')
            version = port_entry.get('service_version')
            
            analysis = self.analyze_port(port, service, version)
            risk_val = self._risk_to_numeric(analysis['risk_level'])
            total_risk += risk_val
            
            if risk_val >= 2:
                findings.append(analysis)
        
        if hostname and any(x in hostname.lower() for x in ['router', 'gateway', 'printer', 'iot']):
            findings.append({
                'risk_level': 'medium',
                'reasons': [f"Device type: {hostname}"],
                'recommendations': ['Review IoT security', 'Isolate from main network']
            })
            total_risk += 2
        
        risk_score = min(100, total_risk * 10)
        
        if risk_score >= 70:
            risk_category = 'critical'
        elif risk_score >= 40:
            risk_category = 'high'
        elif risk_score >= 20:
            risk_category = 'medium'
        else:
            risk_category = 'low'
        
        return {
            'risk_score': risk_score,
            'risk_category': risk_category,
            'findings': findings,
            'port_count': len(ports),
            'analyzed_at': datetime.utcnow().isoformat()
        }
    
    def get_cve_for_service(self, service: str, version: str = None) -> List[Dict]:
        """Get relevant CVEs for a service (placeholder - would connect to real CVE DB)"""
        known_cves = {
            'ssh': [{'cve': 'CVE-2023-48795', 'description': 'OpenSSH regreSSHion', 'severity': 'medium'}],
            'smb': [{'cve': 'CVE-2017-0143', 'description': 'EternalBlue', 'severity': 'critical'}],
            'rdp': [{'cve': 'CVE-2019-0708', 'description': 'BlueKeep', 'severity': 'critical'}],
            'http': [{'cve': 'CVE-2021-44228', 'description': 'Log4j', 'severity': 'critical'}]
        }
        
        service_key = service.lower() if service else ''
        return known_cves.get(service_key, [])
