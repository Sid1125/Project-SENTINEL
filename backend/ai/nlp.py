import logging
import json
import httpx
from typing import Dict, Any, List, Optional
from models.database import settings

logger = logging.getLogger(__name__)

class LocalLLM:
    def __init__(self, host: str = None, model: str = None):
        self.host = host or settings.llm_host
        self.model = model or settings.llm_model
        self.available = False
        self._check_connection()
    
    def _check_connection(self) -> bool:
        """Check if Ollama is running"""
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self.host}/api/tags")
                if response.status_code == 200:
                    self.available = True
                    logger.info(f"Connected to Ollama at {self.host}")
                    return True
        except Exception as e:
            logger.warning(f"Ollama not available: {e}")
        self.available = False
        return False
    
    def generate(self, prompt: str, system_prompt: str = None, 
                 max_tokens: int = 512, temperature: float = 0.7) -> Optional[str]:
        """Generate response from local LLM"""
        if not self.available:
            logger.warning("LLM not available, falling back to rule-based")
            return None
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }
        
        try:
            with httpx.Client(timeout=120.0) as client:
                response = client.post(
                    f"{self.host}/api/chat",
                    json=payload
                )
                if response.status_code == 200:
                    result = response.json()
                    if 'message' in result:
                        return result.get('message', {}).get('content', '')
                    elif 'response' in result:
                        return result.get('response', '')
        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
        
        return None
    
    def is_available(self) -> bool:
        return self.available


class NLPProcessor:
    def __init__(self, llm: LocalLLM = None):
        self.llm = llm or LocalLLM()
        self.intent_patterns = {
            'scan_network': [
                'scan network', 'scan my network', 'find devices', 
                'discover devices', 'show all devices', 'what devices'
            ],
            'scan_ports': [
                'scan ports', 'port scan', 'check ports', 'open ports',
                'vulnerable ports', 'check for open ports'
            ],
            'scan_device': [
                'scan device', 'scan ip', 'scan host', 'check device',
                'analyze', 'investigate'
            ],
            'threat_check': [
                'threats', 'vulnerabilities', 'risks', 'security check',
                'is secure', 'vulnerable', 'exposed'
            ],
            'block_device': [
                'block', 'ban', 'restrict', 'quarantine', 'isolate'
            ],
            'trust_device': [
                'trust', 'whitelist', 'allow', 'safe'
            ],
            'get_status': [
                'status', 'health', 'dashboard', 'overview', 'summary'
            ],
            'block_device': [
                'block', 'ban', 'restrict', 'quarantine', 'isolate', 'stop'
            ],
            'unblock_device': [
                'unblock', 'unban', 'allow', 'release'
            ],
            'vuln_scan': [
                'vulnerability', 'cve', 'exploit', 'vuln scan', 'security scan'
            ],
            'anomaly_check': [
                'anomaly', 'unusual', 'strange', 'suspicious', 'odd behavior'
            ],
            'auto_defense': [
                'auto defense', 'auto-defend', 'protect', 'defend', 'lockdown'
            ],
            'help': [
                'help', 'commands', 'what can you do', 'list commands'
            ]
        }
    
    def parse_intent(self, user_input: str) -> Dict[str, Any]:
        """Parse user input to determine intent"""
        user_input_lower = user_input.lower()
        
        for intent, patterns in self.intent_patterns.items():
            for pattern in patterns:
                if pattern in user_input_lower:
                    entities = self._extract_entities(user_input)
                    return {
                        'intent': intent,
                        'entities': entities,
                        'raw_input': user_input
                    }
        
        if self.llm.available:
            return self._llm_parse_intent(user_input)
        
        return {
            'intent': 'unknown',
            'entities': {},
            'raw_input': user_input
        }
    
    def _extract_entities(self, text: str) -> Dict[str, Any]:
        """Extract IP addresses and other entities from text"""
        import re
        
        entities = {}
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        if ips:
            entities['ips'] = ips
        
        cidr_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b'
        networks = re.findall(cidr_pattern, text)
        if networks:
            entities['networks'] = networks
        
        mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
        macs = re.findall(mac_pattern, text)
        if macs:
            entities['macs'] = [m[0].replace('-', ':') for m in macs]
        
        port_pattern = r'\bport\s*(\d+)\b'
        ports = re.findall(port_pattern, text, re.IGNORECASE)
        if ports:
            entities['ports'] = [int(p) for p in ports]
        
        return entities
    
    def _llm_parse_intent(self, user_input: str) -> Dict[str, Any]:
        """Use LLM to parse intent"""
        system_prompt = """You are a cybersecurity intent classifier. Parse the user's request and return JSON with:
- intent: one of [scan_network, scan_ports, scan_device, threat_check, block_device, trust_device, get_status, help, unknown]
- entities: extracted IP addresses, networks, ports, MAC addresses
- action: brief description of what to do

Respond only with valid JSON."""

        result = self.llm.generate(user_input, system_prompt=system_prompt)
        
        if result:
            try:
                parsed = json.loads(result)
                return parsed
            except json.JSONDecodeError:
                pass
        
        return {
            'intent': 'unknown',
            'entities': self._extract_entities(user_input),
            'raw_input': user_input
        }
    
    def generate_response(self, intent: str, data: Dict[str, Any]) -> str:
        """Generate human-readable response"""
        if intent == 'scan_network':
            device_count = len(data.get('devices', []))
            return f"Found {device_count} device(s) on your network. " + self._format_device_list(data.get('devices', []))
        
        elif intent == 'scan_ports' or intent == 'scan_device':
            port_count = len(data.get('ports', []))
            target = data.get('target', 'target')
            if port_count > 0:
                ports = [f"{p.get('port')} ({p.get('service', 'unknown')})" for p in data.get('ports', [])[:5]]
                return f"Scanned {target}. Found {port_count} open port(s): {', '.join(ports)}"
            return f"Scanned {target}. No open ports detected."
        
        elif intent == 'threat_check':
            risk = data.get('risk_category', 'unknown')
            score = data.get('risk_score', 0)
            return f"Security assessment: {risk.upper()} risk (score: {score}/100)"
        
        elif intent == 'get_status':
            return self._format_status(data)
        
        elif intent == 'block_device':
            ip = data.get('ip', 'unknown')
            return f"Device {ip} has been blocked. Firewall rule applied."
        
        elif intent == 'unblock_device':
            ip = data.get('ip', 'unknown')
            return f"Device {ip} has been unblocked. Access restored."
        
        elif intent == 'trust_device':
            ip = data.get('ip', 'unknown')
            return f"Device {ip} marked as trusted."
        
        elif intent == 'vuln_scan':
            vuln_count = len(data.get('vulnerabilities', []))
            target = data.get('target', 'target')
            if vuln_count > 0:
                return f"Vulnerability scan on {target} found {vuln_count} issues. Check detailed report for more info."
            return f"Vulnerability scan on {target} completed. No critical issues found."
        
        elif intent == 'anomaly_check':
            anomalies = data.get('anomalies_detected', 0)
            total = data.get('total_devices', 0)
            return f"Analyzed {total} devices. Found {anomalies} with anomalous behavior."
        
        elif intent == 'auto_defense':
            enabled = data.get('enabled', False)
            return f"Auto-defense is {'enabled' if enabled else 'disabled'}."
        
        elif intent == 'help':
            return self._get_help_text()
        
        return "Action completed. Check the dashboard for details."
    
    def _format_device_list(self, devices: List[Dict]) -> str:
        if not devices:
            return "No devices found."
        
        lines = []
        for dev in devices[:5]:
            lines.append(f"• {dev.get('ip_address', 'Unknown')} ({dev.get('vendor', 'Unknown')})")
        
        if len(devices) > 5:
            lines.append(f"... and {len(devices) - 5} more")
        
        return "\n".join(lines)
    
    def _format_status(self, data: Dict) -> str:
        total = data.get('total_devices', 0)
        trusted = data.get('trusted_devices', 0)
        threats = data.get('active_threats', 0)
        
        return f"Status: {total} devices ({trusted} trusted), {threats} active threats"
    
    def _get_help_text(self) -> str:
        return """SENTINEL AI Commands:

Network Operations:
• "Scan my network" - Discover all devices
• "Scan [IP]" - Scan specific device for ports
• "Scan [IP] for vulnerabilities" - Run vuln scan

Security Analysis:
• "Check threats" - Run security analysis
• "Check for anomalies" - AI-based anomaly detection
• "Vulnerability scan on [IP]" - CVE check

Device Management:
• "Block [IP]" - Block device at firewall
• "Unblock [IP]" - Remove block
• "Trust [IP]" - Mark device as trusted
• "Quarantine [IP]" - Isolate device

System Control:
• "Enable auto defense" - Turn on auto-protection
• "Status" - View overall security status
• "Help" - Show this menu"""
