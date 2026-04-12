import logging
import os
from datetime import datetime
from pathlib import Path

class ActivityLogger:
    def __init__(self, log_dir: str | None = None):
        if log_dir is None:
            log_dir = str(Path(__file__).parent.parent / "logs")
        else:
            log_dir = str(Path(log_dir))
        
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        
        self.log_file = log_path / f"sentinel_{datetime.now().strftime('%Y%m%d')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s | %(levelname)s | %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("sentinel")
    
    def log_scan(self, scan_type: str, target: str, devices_found: int):
        self.logger.info(f"SCAN | type={scan_type} | target={target} | devices={devices_found}")
    
    def log_device_discovered(self, ip: str, mac: str | None = None, vendor: str | None = None):
        self.logger.info(f"DEVICE_DISCOVERED | ip={ip} | mac={mac if mac else 'unknown'} | vendor={vendor if vendor else 'unknown'}")
    
    def log_device_trust(self, ip: str, trusted: bool):
        action = "trusted" if trusted else "untrusted"
        self.logger.info(f"DEVICE_TRUST | ip={ip} | action={action}")
    
    def log_device_block(self, ip: str, blocked: bool):
        action = "blocked" if blocked else "unblocked"
        self.logger.info(f"DEVICE_BLOCK | ip={ip} | action={action}")
    
    def log_threat_detected(self, ip: str, risk_score: float, ports: list):
        port_list = ",".join(str(p) for p in ports) if ports else "none"
        self.logger.warning(f"THREAT_DETECTED | ip={ip} | risk_score={risk_score} | ports={port_list}")
    
    def log_port_scan(self, ip: str, open_ports: int):
        self.logger.info(f"PORT_SCAN | ip={ip} | open_ports={open_ports}")
    
    def log_alert(self, alert_type: str, severity: str, message: str):
        self.logger.warning(f"ALERT | type={alert_type} | severity={severity} | message={message}")
    
    def log_system(self, event: str):
        self.logger.info(f"SYSTEM | {event}")
    
    def log_error(self, error: str):
        self.logger.error(f"ERROR | {error}")
    
    def get_logs(self, lines: int = 50):
        try:
            if self.log_file.exists():
                with open(self.log_file, 'r') as f:
                    all_logs = f.readlines()
                    startup_markers = [
                        idx
                        for idx, line in enumerate(all_logs)
                        if "SYSTEM | Sentinel backend started" in line
                    ]
                    if startup_markers:
                        all_logs = all_logs[startup_markers[-1]:]
                    return [l.strip() for l in all_logs[-lines:]]
            return []
        except Exception:
            return []

activity_logger = ActivityLogger()
