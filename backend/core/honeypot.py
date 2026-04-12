import logging
import socket
import threading
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Callable

logger = logging.getLogger(__name__)

class HoneypotService:
    def __init__(self, attack_log_dir: str | None = None):
        self.running_services: Dict[int, socket.socket] = {}
        self.captured_attacks: List[Dict] = []
        self.lock = threading.Lock()
        
        if attack_log_dir is None:
            attack_log_dir = str(Path(__file__).parent.parent / "honeypot_logs")
        
        self.attack_log_dir = Path(attack_log_dir)
        self.attack_log_dir.mkdir(parents=True, exist_ok=True)
        
        self.analysis_queue: List[Dict] = []
        self.llm_client = None
        self.auto_block_callback: Optional[Callable] = None
    
    def set_auto_block_callback(self, callback: Callable):
        """Set callback for automated response playbooks"""
        self.auto_block_callback = callback
    
    def set_llm_client(self, llm_client):
        """Set LLM client for attack analysis"""
        self.llm_client = llm_client
    
    def start_service(self, port: int, service_name: str) -> bool:
        """Start a honeypot service on specified port"""
        
        # Security: Validate port is safe
        from core.system_integration import is_port_safe
        if not is_port_safe(port):
            logger.error(f"Refusing to start honeypot on unsafe port {port}")
            return False
        
        # Security: Limit max honeypot services to prevent resource exhaustion
        if len(self.running_services) >= 20:
            logger.error("Maximum honeypot services limit reached (20)")
            return False
        
        if port in self.running_services:
            logger.warning(f"Honeypot service already running on port {port}")
            return False
        
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            server.settimeout(1.0)
            
            self.running_services[port] = server
            
            thread = threading.Thread(target=self._accept_connections, args=(port, service_name), daemon=True)
            thread.start()
            
            logger.info(f"Honeypot service started on port {port} ({service_name})")
            return True
        except Exception as e:
            logger.error(f"Failed to start honeypot on port {port}: {e}")
            return False
    
    def stop_service(self, port: int) -> bool:
        """Stop a honeypot service"""
        if port not in self.running_services:
            return False
        
        try:
            server = self.running_services[port]
            try:
                server.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            server.close()
            del self.running_services[port]
            logger.info(f"Honeypot service stopped on port {port}")
            return True
        except Exception as e:
            logger.error(f"Failed to stop honeypot on port {port}: {e}")
            return False
    
    def stop_all_services(self) -> bool:
        """Stop all running honeypot services"""
        ports = list(self.running_services.keys())
        for port in ports:
            self.stop_service(port)
        return True
    
    def _accept_connections(self, port: int, service_name: str):
        """Accept connections and log attack attempts"""
        server = self.running_services.get(port)
        if not server:
            return
        
        while port in self.running_services:
            try:
                client, addr = server.accept()
                thread = threading.Thread(target=self._handle_connection, args=(client, addr, port, service_name), daemon=True)
                thread.start()
            except Exception as e:
                if port not in self.running_services:
                    break
                if "10038" in str(e) or "not a socket" in str(e).lower():
                    break
                continue
    
    def _handle_connection(self, client: socket.socket, addr: tuple, port: int, service_name: str):
        """Handle incoming connection and log attack data"""
        attacker_ip = addr[0]
        
        if not self._is_allowed_attacker(attacker_ip):
            client.close()
            return
        
        logger.warning(f"HONEYPOT: Connection from {attacker_ip}:{addr[1]} to port {port}")
        
        commands = ["Connection established"]
        raw_data = b''
        
        try:
            banner = self._get_banner(service_name)
            if banner:
                client.sendall(banner.encode())
                logger.info(f"Sent {service_name} banner to {attacker_ip}")
            
            client.settimeout(2)
            
            try:
                data = client.recv(1024)
                if data:
                    raw_data = data
                    text = data.decode('utf-8', errors='ignore')
                    lines = [l.strip() for l in text.split('\n') if l.strip()]
                    if lines:
                        commands = lines
            except:
                pass
            
        except Exception as e:
            logger.error(f"Error in honeypot: {e}")
        finally:
            try:
                client.close()
            except:
                pass
        
        attack_id = str(uuid.uuid4())[:8]
        timestamp = datetime.utcnow().isoformat()
        
        attack_data = {
            'attack_id': attack_id,
            'source_ip': attacker_ip,
            'source_port': addr[1],
            'listen_port': port,
            'mimic_port': self._get_mimic_port(service_name),
            'service': service_name,
            'timestamp': timestamp,
            'commands': commands,
            'raw_data': raw_data.hex() if raw_data else '',
            'command_count': len(commands),
        }
        
        self._save_unedited_attack(attack_data)
        self._log_attack_to_file(attack_data)
        
        with self.lock:
            self.captured_attacks.append(attack_data)
            if len(self.captured_attacks) > 1000:
                self.captured_attacks = self.captured_attacks[-500:]
        
        self._analyze_with_llm(attack_data)
        
        logger.warning(f"Capture [{attack_id}]: {attacker_ip} connected to honeypot port {port}")
        
        # Auto-block serious attacks
        self._auto_block_attacker(attack_data)
    
    def _save_unedited_attack(self, attack_data: Dict):
        """Save unedited attack data for forensic analysis"""
        try:
            attack_id = attack_data['attack_id']
            date_dir = self.attack_log_dir / datetime.now().strftime('%Y-%m-%d')
            date_dir.mkdir(parents=True, exist_ok=True)
            
            file_path = date_dir / f"attack_{attack_id}.json"
            
            with open(file_path, 'w') as f:
                json.dump(attack_data, f, indent=2)
            
            logger.info(f"Unedited attack saved: {file_path}")
        except Exception as e:
            logger.error(f"Failed to save unedited attack: {e}")
    
    def _log_attack_to_file(self, attack_data: Dict):
        """Log attack to main log file"""
        try:
            log_file = self.attack_log_dir / "honeypot_attacks.log"
            
            log_entry = {
                'timestamp': attack_data['timestamp'],
                'attack_id': attack_data['attack_id'],
                'source_ip': attack_data['source_ip'],
                'listen_port': attack_data['listen_port'],
                'mimic_port': attack_data['mimic_port'],
                'service': attack_data['service'],
                'command_count': attack_data['command_count'],
            }
            
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to log attack: {e}")
    
    def _analyze_with_llm(self, attack_data: Dict):
        """Send attack data to LLM for analysis"""
        if not self.llm_client:
            logger.warning("No LLM client set, skipping analysis")
            return
        
        if not self.llm_client.is_available():
            logger.info("LLM not available, skipping attack analysis")
            return
        
        try:
            prompt = self._build_analysis_prompt(attack_data)
            logger.info(f"Sending attack {attack_data['attack_id']} to LLM")
            
            import httpx
            payload = {
                "model": "phi:latest",
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity analyst. Analyze honeypot attack data and provide a detailed threat report."},
                    {"role": "user", "content": prompt}
                ],
                "stream": False
            }
            
            with httpx.Client(timeout=120.0) as client:
                response = client.post("http://localhost:11434/api/chat", json=payload)
                if response.status_code == 200:
                    result = response.json()
                    report = result.get('message', {}).get('content', '')
                    if report:
                        self._save_analysis_report(attack_data['attack_id'], report)
                        logger.info(f"Attack analysis completed for {attack_data['attack_id']}")
                    else:
                        logger.warning(f"Empty report from LLM")
        except Exception as e:
            logger.error(f"Failed to analyze attack with LLM: {e}")
    
    def _build_analysis_prompt(self, attack_data: Dict) -> str:
        """Build prompt for LLM analysis"""
        commands_str = '\n'.join(attack_data.get('commands', []))
        
        prompt = f"""Analyze the following honeypot attack:

Attack ID: {attack_data['attack_id']}
Source IP: {attack_data['source_ip']}
Listen Port: {attack_data['listen_port']}
Mimic Port: {attack_data['mimic_port']}
Service: {attack_data['service']}
Timestamp: {attack_data['timestamp']}

Commands/Payloads:
{commands_str}

Provide a threat analysis report including:
1. Attack type classification
2. Severity assessment (low/medium/high/critical)
3. Likely attacker's objective
4. IOCs (Indicators of Compromise)
5. Recommended response

Report:"""
        return prompt
    
    def _save_analysis_report(self, attack_id: str, report: str):
        """Save LLM analysis report"""
        try:
            report_dir = self.attack_log_dir / "analysis_reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            
            report_file = report_dir / f"report_{attack_id}.txt"
            
            with open(report_file, 'w') as f:
                f.write(f"Attack ID: {attack_id}\n")
                f.write(f"Analysis Date: {datetime.now().isoformat()}\n")
                f.write("=" * 50 + "\n\n")
                f.write(report)
            
            logger.info(f"Analysis report saved: {report_file}")
        except Exception as e:
            logger.error(f"Failed to save analysis report: {e}")
    
    def _is_allowed_attacker(self, ip: str) -> bool:
        """Check if attacker IP is allowed - honeypot accepts ANY external IP"""
        # Honeypot is designed to catch attackers, so we accept external IPs
        # But we reject localhost to prevent loopback abuse
        if ip == '127.0.0.1' or ip == 'localhost' or ip == '::1':
            return False
        
        # Reject only obviously spoofed / internal IPs
        # This allows honeypot to function as intended - catching real attacks
        private_prefixes = ['10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                           '172.2', '172.30.', '172.31.', '192.168.', '127.']
        
        for prefix in private_prefixes:
            if ip.startswith(prefix):
                return False
        
        return True
    
    def _contains_relay_attempt(self, cmd: str) -> bool:
        """Detect potential relay/amplification attacks"""
        relay_patterns = [
            'smtp.', 'mail.', 'rcpt to', 'mail from',
            'connect', 'proxy', 'relay',
            'http/1.1 host:',
            'transfer'
        ]
        cmd_lower = cmd.lower()
        return any(pattern in cmd_lower for pattern in relay_patterns)
    
    def _auto_block_attacker(self, attack_data: Dict):
        """Auto-block attackers based on attack severity"""
        if not self.auto_block_callback:
            return
        
        attacker_ip = attack_data.get('source_ip')
        if not attacker_ip:
            return
        
        # Block criteria: serious attacks
        should_block = False
        reason = ""
        
        # Check for dangerous commands
        dangerous_patterns = [
            'rm -rf', 'del /', 'format', 'drop table',
            'exec(', 'eval(', 'system(', 'passthru',
            'wget', 'curl', 'nc -e', '/bin/sh',
            'root', 'admin', 'sudo',
            '--', ';', '|', '&&',
            'union select', '1=1', "' or '",
        ]
        
        commands = attack_data.get('commands', [])
        raw_data = attack_data.get('raw_data', '')
        
        for cmd in commands:
            cmd_lower = cmd.lower()
            for pattern in dangerous_patterns:
                if pattern in cmd_lower:
                    should_block = True
                    reason = f"Dangerous command: {pattern}"
                    break
            if should_block:
                break
        
        # Check for SQL injection attempts
        if not should_block and raw_data:
            raw_lower = raw_data.lower()
            sql_patterns = ['union', 'select', 'insert', 'delete', 'drop', '1=1', "' or '"]
            if any(p in raw_lower for p in sql_patterns):
                should_block = True
                reason = "SQL injection attempt"
        
        # Check for command injection
        if not should_block:
            for cmd in commands:
                if any(c in cmd for c in [';', '|', '&&', '`', '$(']):
                    should_block = True
                    reason = "Command injection attempt"
                    break
        
        if should_block and attacker_ip:
            try:
                logger.warning(f"Auto-blocking attacker: {attacker_ip} - {reason}")
                self.auto_block_callback(
                    attacker_ip,
                    trigger_reason="honeypot_attack",
                    risk_score=95,
                    details={
                        "reason": reason,
                        "service": attack_data.get("service"),
                        "listen_port": attack_data.get("listen_port"),
                        "attack_id": attack_data.get("attack_id"),
                    },
                )
            except Exception as e:
                logger.error(f"Failed to auto-block {attacker_ip}: {e}")
    
    def _get_mimic_port(self, service_name: str) -> int:
        """Map service name to the port it mimics"""
        port_map = {
            'SSH': 22,
            'Telnet': 23,
            'HTTP': 80,
            'HTTPS': 443,
            'SMB': 445,
            'FTP': 21,
            'SMTP': 25,
            'RDP': 3389,
        }
        return port_map.get(service_name, 0)
    
    def _get_banner(self, service_name: str) -> str:
        """Get fake banner for service"""
        banners = {
            'SSH': 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n',
            'Telnet': 'Welcome to Ubuntu 20.04 LTS\r\nlogin: ',
            'HTTP': 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n',
            'FTP': '220 (vsFTPd 3.0.3)\r\n',
            'SMB': '\x00\x00\x00\x00',
        }
        return banners.get(service_name, '')
    
    def get_running_services(self) -> List[int]:
        """Get list of running honeypot ports"""
        return list(self.running_services.keys())
    
    def get_captured_attacks(self, limit: int = 50) -> List[Dict]:
        """Get captured attack data"""
        with self.lock:
            attacks = self.captured_attacks[-limit:]
            for attack in attacks:
                attack['commands'] = '\n'.join(attack.get('commands', []))
            return attacks
    
    def get_uncensored_attack(self, attack_id: str) -> Optional[Dict]:
        """Get full unedited attack data for forensic analysis"""
        try:
            for date_dir in self.attack_log_dir.iterdir():
                if date_dir.is_dir():
                    file_path = date_dir / f"attack_{attack_id}.json"
                    if file_path.exists():
                        with open(file_path, 'r') as f:
                            return json.load(f)
        except Exception as e:
            logger.error(f"Failed to get unedited attack: {e}")
        return None
    
    def get_analysis_report(self, attack_id: str) -> Optional[str]:
        """Get LLM analysis report for an attack"""
        try:
            report_dir = self.attack_log_dir / "analysis_reports"
            report_file = report_dir / f"report_{attack_id}.txt"
            if report_file.exists():
                with open(report_file, 'r') as f:
                    return f.read()
        except Exception as e:
            logger.error(f"Failed to get analysis report: {e}")
        return None
    
    def is_active(self) -> bool:
        """Check if honeypot is active"""
        return len(self.running_services) > 0
    
    def get_stats(self) -> Dict:
        """Get honeypot statistics"""
        with self.lock:
            unique_ips = len(set(a['source_ip'] for a in self.captured_attacks))
            return {
                'services_running': len(self.running_services),
                'total_attacks': len(self.captured_attacks),
                'unique_attackers': unique_ips,
                'active': len(self.running_services) > 0,
                'logs_directory': str(self.attack_log_dir)
            }


honeypot = HoneypotService()
