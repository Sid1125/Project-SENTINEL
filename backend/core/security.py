import time
import hashlib
import logging
from typing import Dict, Optional
from datetime import datetime, timedelta
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

class AttackDetector:
    """Detect various attack patterns"""
    
    def __init__(self):
        self.failed_logins: Dict[str, list] = {}
        self.suspicious_requests: Dict[str, list] = {}
        self.scan_attempts: Dict[str, list] = {}
        
        self.failed_login_threshold = 5
        self.scan_threshold = 10
        self.window_seconds = 300  # 5 minutes
        
        self.dangerous_patterns = [
            r"union\s+select",
            r"1\s*=\s*1",
            r"'\s+or\s+'",
            r"<script",
            r"javascript:",
            r"eval\(",
            r"exec\(",
            r"\.\./",
            r"%27",  # URL-encoded '
        ]
    
    def record_failed_login(self, ip: str):
        """Record failed login attempt"""
        now = time.time()
        if ip not in self.failed_logins:
            self.failed_logins[ip] = []
        
        self.failed_logins[ip] = [
            t for t in self.failed_logins[ip]
            if now - t < self.window_seconds
        ]
        self.failed_logins[ip].append(now)
        
        if len(self.failed_logins[ip]) >= self.failed_login_threshold:
            logger.warning(f"Brute force detected: {ip} - {len(self.failed_logins[ip])} failed attempts")
            return True
        return False
    
    def record_scan_attempt(self, ip: str, port: int):
        """Record port scan attempt"""
        now = time.time()
        key = f"{ip}:{port}"
        
        if ip not in self.scan_attempts:
            self.scan_attempts[ip] = []
        
        self.scan_attempts[ip] = [
            t for t in self.scan_attempts[ip]
            if now - t < self.window_seconds
        ]
        self.scan_attempts[ip].append(now)
        
        if len(self.scan_attempts[ip]) >= self.scan_threshold:
            logger.warning(f"Port scan detected from: {ip}")
            return True
        return False
    
    def check_malicious_request(self, path: str, query: str = "", body: str = "") -> bool:
        """Check for malicious patterns in request"""
        import re
        full_request = f"{path} {query} {body}".lower()
        
        for pattern in self.dangerous_patterns:
            if re.search(pattern, full_request, re.IGNORECASE):
                logger.warning(f"Malicious pattern detected: {pattern}")
                return True
        return False
    
    def get_attack_info(self, ip: str) -> Dict:
        """Get attack info for an IP"""
        now = time.time()
        info = {'ip': ip, 'attacks': []}
        
        if ip in self.failed_logins:
            recent = [t for t in self.failed_logins[ip] if now - t < self.window_seconds]
            if recent:
                info['attacks'].append(f"Failed logins: {len(recent)}")
        
        if ip in self.scan_attempts:
            recent = [t for t in self.scan_attempts[ip] if now - t < self.window_seconds]
            if recent:
                info['attacks'].append(f"Scan attempts: {len(recent)}")
        
        return info
    
    def clear_expired(self):
        """Clean up expired entries"""
        now = time.time()
        
        # Clean failed_logins
        self.failed_logins = {
            k: [t for t in v if now - t < self.window_seconds]
            for k, v in self.failed_logins.items()
        }
        
        # Clean scan_attempts
        self.scan_attempts = {
            k: [t for t in v if now - t < self.window_seconds]
            for k, v in self.scan_attempts.items()
        }


attack_detector = AttackDetector()


class RateLimitConfig:
    def __init__(self):
        self.requests: Dict[str, list] = {}
        self.max_requests = 200
        self.window_seconds = 60
        
        self.scan_rate_limit = 20
        self.scan_window = 300
        
        self.blocklist: Dict[str, datetime] = {}
    
    def is_rate_limited(self, client_id: str) -> bool:
        now = time.time()
        if client_id not in self.requests:
            self.requests[client_id] = []
        
        self.requests[client_id] = [
            t for t in self.requests[client_id] 
            if now - t < self.window_seconds
        ]
        
        if len(self.requests[client_id]) >= self.max_requests:
            return True
        
        self.requests[client_id].append(now)
        return False
    
    def is_scan_rate_limited(self, client_id: str) -> bool:
        now = time.time()
        key = f"scan_{client_id}"
        
        if key not in self.requests:
            self.requests[key] = []
        
        self.requests[key] = [
            t for t in self.requests[key]
            if now - t < self.scan_window
        ]
        
        if len(self.requests[key]) >= self.scan_rate_limit:
            return True
        
        self.requests[key].append(now)
        return False
    
    def block_ip(self, ip: str, duration_minutes: int = 30):
        self.blocklist[ip] = datetime.now() + timedelta(minutes=duration_minutes)
        logger.warning(f"IP {ip} blocked for {duration_minutes} minutes")
    
    def is_blocked(self, ip: str) -> bool:
        if ip in self.blocklist:
            if datetime.now() < self.blocklist[ip]:
                return True
            else:
                del self.blocklist[ip]
        return False
    
    def cleanup(self):
        now = time.time()
        # Limit memory usage - only keep recent entries
        max_keys = 1000
        for key in list(self.requests.keys())[:max_keys]:
            self.requests[key] = [
                t for t in self.requests[key]
                if now - t < self.scan_window
            ]
            if not self.requests[key]:
                del self.requests[key]


rate_limit_config = RateLimitConfig()

# Auto-defense callback (set from main.py)
auto_defense_callback = None


def set_auto_defense_callback(callback):
    """Set callback for playbook-driven security responses"""
    global auto_defense_callback
    auto_defense_callback = callback


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            client_ip = request.client.host if request.client else "unknown"
            
            # Check for malicious patterns
            path = request.url.path
            query = request.url.query or ""
            body = ""
            
            if attack_detector.check_malicious_request(path, query, body):
                logger.warning(f"Blocked malicious request from {client_ip}: {path}")
                if auto_defense_callback:
                    auto_defense_callback(
                        client_ip,
                        trigger_reason="malicious_request",
                        details={"path": path, "query": query},
                    )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Malicious request detected"
                )
            
            # Check rate limit
            if rate_limit_config.is_rate_limited(client_ip):
                if auto_defense_callback:
                    auto_defense_callback(
                        client_ip,
                        trigger_reason="rate_limit_exceeded",
                        details={"path": path},
                    )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. Please slow down."
                )
            
            response = await call_next(request)
            return response
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            response = await call_next(request)
            return response


def validate_ip_address(ip: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    return 1 <= port <= 65535


def validate_domain(domain: str) -> bool:
    import re
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    return bool(re.match(pattern, domain)) and len(domain) <= 253


def sanitize_input(text: str, max_length: int = 500) -> str:
    if not text:
        return ""
    
    text = text[:max_length]
    
    dangerous_patterns = [
        r'<script',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe',
        r'eval\(',
        r'exec\(',
    ]
    
    import re
    for pattern in dangerous_patterns:
        text = re.sub(pattern, '', text, flags=re.IGNORECASE)
    
    return text.strip()


def validate_scan_target(target: str) -> bool:
    import ipaddress
    try:
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            return network.num_addresses <= 1024
        else:
            ipaddress.ip_address(target)
            return True
    except ValueError:
        return validate_domain(target)
