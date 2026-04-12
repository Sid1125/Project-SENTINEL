from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
try:
    from models.database import Base
except ModuleNotFoundError:
    from backend.models.database import Base

class NetworkDevice(Base):
    __tablename__ = "network_devices"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    mac_address = Column(String(17), unique=True, index=True)
    hostname = Column(String(255))
    os_guess = Column(String(255))
    vendor = Column(String(255))
    status = Column(String(20), default='unknown')
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_trusted = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)
    device_info = Column(JSON, default={})
    
    ports = relationship("PortScanResult", back_populates="device")
    vulnerabilities = relationship("Vulnerability", back_populates="device")

class PortScanResult(Base):
    __tablename__ = "port_scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("network_devices.id"))
    port = Column(Integer, nullable=False)
    protocol = Column(String(10))
    service = Column(String(100))
    service_version = Column(String(100))
    state = Column(String(20))
    banner = Column(Text)
    scan_timestamp = Column(DateTime, default=datetime.utcnow)
    
    device = relationship("NetworkDevice", back_populates="ports")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("network_devices.id"))
    cve_id = Column(String(20), index=True)
    title = Column(String(500))
    description = Column(Text)
    severity = Column(String(20))
    cvss_score = Column(Float)
    cve_link = Column(String(500))
    discovered_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default="open")
    
    device = relationship("NetworkDevice", back_populates="vulnerabilities")

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    title = Column(String(500))
    message = Column(Text)
    source_ip = Column(String(45))
    target_ip = Column(String(45))
    raw_data = Column(JSON)
    is_resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

class ScanHistory(Base):
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(50), nullable=False)
    target_range = Column(String(100))
    status = Column(String(20))
    devices_found = Column(Integer)
    vulnerabilities_found = Column(Integer)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    notes = Column(Text)

class BlacklistedIP(Base):
    __tablename__ = "blacklisted_ips"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    source = Column(String(100))
    reason = Column(Text)
    first_seen = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)

class SystemConfig(Base):
    __tablename__ = "system_config"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(Text)
    description = Column(String(500))
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), default="info")
    source = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text)
    target_ip = Column(String(45))
    event_metadata = Column("metadata", JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
