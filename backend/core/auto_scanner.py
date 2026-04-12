import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class AutoScanner:
    def __init__(self, scanner, db_session, threat_intel, logger):
        self.scanner = scanner
        self.get_db = db_session
        self.threat_intel = threat_intel
        self.logger = logger
        self.interval_minutes = 30
        self.running = False
        self.task = None
    
    async def start(self):
        """Start auto-scanning"""
        if self.running:
            return
        
        self.running = True
        self.logger.log_system("Auto scanner started")
        logger.info(f"Auto scanner started - scanning every {self.interval_minutes} minutes")
        
        while self.running:
            try:
                await self._perform_scan()
            except Exception as e:
                logger.error(f"Auto scan error: {e}")
            
            await asyncio.sleep(self.interval_minutes * 60)
    
    def stop(self):
        """Stop auto-scanning"""
        self.running = False
        self.logger.log_system("Auto scanner stopped")
        logger.info("Auto scanner stopped")
    
    async def _perform_scan(self):
        """Perform automatic network scan"""
        logger.info("Starting auto scan...")
        
        devices = self.scanner.arp_scan()
        
        db = self.get_db()
        try:
            from models.schemas import NetworkDevice
            
            new_count = 0
            known_ips = set()
            
            existing = db.query(NetworkDevice).all()
            known_ips = {d.ip_address for d in existing}
            
            for dev in devices:
                ip = dev.get('ip_address')
                if not ip:
                    continue
                
                existing_dev = db.query(NetworkDevice).filter_by(ip_address=ip).first()
                if existing_dev:
                    existing_dev.last_seen = datetime.utcnow()
                    if dev.get('mac_address'):
                        existing_dev.mac_address = dev['mac_address']
                    if dev.get('hostname'):
                        existing_dev.hostname = dev['hostname']
                else:
                    new_device = NetworkDevice(
                        ip_address=ip,
                        mac_address=dev.get('mac_address'),
                        hostname=dev.get('hostname'),
                        vendor=dev.get('vendor'),
                        status=dev.get('status', 'unknown'),
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow()
                    )
                    db.add(new_device)
                    new_count += 1
                    self.logger.log_device_discovered(ip, dev.get('mac_address'), dev.get('vendor'))
            
            db.commit()
            
            self.logger.log_scan('auto', self.scanner.local_networks[0] if self.scanner.local_networks else 'unknown', len(devices))
            logger.info(f"Auto scan complete: {len(devices)} devices, {new_count} new")
            
        finally:
            db.close()
    
    def set_interval(self, minutes: int):
        """Set scan interval in minutes"""
        self.interval_minutes = minutes
        self.logger.log_system(f"Auto scan interval set to {minutes} minutes")

auto_scanner = None
