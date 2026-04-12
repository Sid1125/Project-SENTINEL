import nmap
import logging
import socket
import netaddr
from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
import ipaddress
import subprocess
import platform
import os

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self):
        self.nm = None
        self.local_ip = self.get_local_ip()
        self.local_networks = self._get_local_networks()
        self._init_nmap()
    
    def _init_nmap(self):
        """Initialize nmap - only use fallback if nmap truly unavailable"""
        nmap_path = None
        
        for path in [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]:
            if os.path.exists(path):
                nmap_path = path
                break
        
        if nmap_path is None:
            import shutil
            nmap_path = shutil.which("nmap")
        
        if nmap_path is None:
            logger.warning("nmap executable not found")
            self.nm = None
            return
        
        try:
            os.environ['PATH'] = os.environ['PATH'] + r";C:\Program Files (x86)\Nmap;C:\Program Files\Nmap"
            self.nm = nmap.PortScanner()
            logger.info(f"nmap initialized successfully using {nmap_path}")
        except Exception as e:
            logger.warning(f"nmap initialization failed: {e}")
            self.nm = None
    
    def _get_local_networks(self) -> List[str]:
        """Get all local network interfaces"""
        networks = []
        try:
            local_ip = self.get_local_ip()
            if local_ip:
                parts = local_ip.split('.')
                base_ip = '.'.join(parts[:3])
                networks.append(f"{base_ip}.0/24")
                logger.info(f"Detected network: {base_ip}.0/24")
                
                try:
                    hostname = socket.gethostname()
                    local_addrs = socket.gethostbyname_ex(hostname)[2]
                    for addr in local_addrs:
                        if '.' in addr and not addr.startswith('127.'):
                            p = addr.split('.')
                            if len(p) == 4:
                                networks.append(f"{'.'.join(p[:3])}.0/24")
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Could not enumerate interfaces: {e}")
        
        return networks if networks else ["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24"]
    
    def get_local_ip(self) -> Optional[str]:
        """Get primary local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None
    
    def _get_vendor_from_mac(self, mac: str) -> str:
        """Get vendor from MAC address using OUI lookup"""
        if not mac:
            return "Unknown"
        
        oui = mac.replace(':', '').upper()[:6]
        
        oui_database = {
            '000000': 'Xerox', '000002': 'Xerox', '00000C': 'Cisco',
            '005056': 'VMware', '001A2B': 'Cisco', '001122': 'HP',
            '00C0EE': 'Intel', '3C5AB4': 'Google', 'F0DEF9': 'Apple',
            'DC2B2A': 'Apple', '001A4B': 'Dell', '001122': 'Dell',
            '001E52': 'Dell', '0024E8': 'Dell', '34E6D7': 'TP-Link',
            '50C8E5': 'TP-Link', 'A4E8B9': 'Xiaomi', '64B473': 'Samsung',
            'AC5F3E': 'Samsung', 'B4E842': 'Amazon', '68D93C': 'Amazon',
            'F0F0F0': 'Microsoft', '000D3A': 'Microsoft', 'B4D5BD': 'Microsoft',
            '28395E': 'NVIDIA', '0070B0': 'NVIDIA', '001E75': 'Ralink',
            '001EA2': 'Liteon', '0021F6': 'Apple', '002312': 'Apple',
            '002436': 'Apple', '00254B': 'Apple', '0026BB': 'Apple',
            '0026B0': 'Apple', '041252': 'Apple', '0C771A': 'Apple',
            '101C0C': 'Apple', '14C0BB': 'Apple', '183CFD': 'Apple',
            '1C9148': 'Apple', '2099F7': 'Apple', '20A2E4': 'Apple',
            '20C9D0': 'Apple', '24A074': 'Apple', '28CFDA': 'Apple',
            '2C1F23': 'Apple', '2CF05D': 'Apple', '2F6C75': 'Apple',
            '305A3A': 'Apple', '30F77F': 'Apple', '380F4A': 'Apple',
            '3C0754': 'Apple', '40A3CC': 'Apple', '483A4A': 'Apple',
            '48746E': 'Apple', '4C32D6': 'Apple', '50E085': 'Apple',
            '54271E': 'Apple', '5C8D4E': 'Apple', '5CF7E6': 'Apple',
            '60C5AD': 'Apple', '685D43': 'Apple', '688E84': 'Apple',
            '6C4008': 'Apple', '70DEE2': 'Apple', '74E2F5': 'Apple',
            '789ED0': 'Apple', '7C6DF8': 'Apple', '80B03D': 'Apple',
            '846878': 'Apple', '88E9FE': 'Apple', '8C8590': 'Apple',
            '907408': 'Apple', '90B335': 'Apple', '982D68': 'Apple',
            '986599': 'Apple', '98D7A9': 'Apple', 'A45E60': 'Apple',
            'AC3743': 'Apple', 'AC9E17': 'Apple', 'B065BD': 'Apple',
            'B8E856': 'Apple', 'B8FF6F': 'Apple', 'BC3BAD': 'Apple',
            'C06599': 'Apple', 'C82A14': 'Apple', 'C86C87': 'Apple',
            'CC088D': 'Apple', 'D023DB': 'Apple', 'D0A637': 'Apple',
            'D0C5D3': 'Apple', 'D4619D': 'Apple', 'D83062': 'Apple',
            'E0C334': 'Apple', 'E48B7F': 'Apple', 'E80688': 'Apple',
            'E88B35': 'Apple', 'F02475': 'Apple', 'F0DCE2': 'Apple',
            'F81EDF': 'Apple', 'FCFC48': 'Apple', '001DD8': 'Apple',
        }
        
        return oui_database.get(oui, "Unknown")
    
    def arp_scan(self, network: Optional[str] = None) -> List[Dict[str, Any]]:
        """Perform ARP scan to discover devices"""
        if network is None:
            network = self.local_networks[0] if self.local_networks else "192.168.1.0/24"
        
        logger.info(f"Performing ARP scan on {network}")
        devices = []
        
        if self.nm is None:
            logger.warning("nmap not available, no fallback scan will be performed")
            return []
        
        try:
            self.nm.scan(hosts=network, arguments='-sn -PR --max-retries 2 -T4')
            
            for host in self.nm.all_hosts():
                status = self.nm[host].get('status', 'unknown')
                if status != 'down':
                    mac = self.nm[host].get('addresses', {}).get('mac', '')
                    vendor = self.nm[host].get('vendor', {}).get(mac, '')
                    
                    if not vendor and mac:
                        vendor = self._get_vendor_from_mac(mac)
                    
                    hostname = ''
                    hostnames = self.nm[host].get('hostnames', [])
                    if hostnames:
                        hostname = hostnames[0].get('name', '')
                    
                    host_info = {
                        'ip_address': host,
                        'mac_address': mac,
                        'hostname': hostname,
                        'vendor': vendor,
                        'status': status,
                        'last_seen': datetime.utcnow().isoformat()
                    }
                    devices.append(host_info)
                    logger.info(f"Found device: {host} ({vendor})")
            
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
        
        return devices
    
    def _fallback_arp_scan(self, network: str) -> List[Dict[str, Any]]:
        """Fallback ping scan using system ping"""
        devices = []
        try:
            net = network.split('/')[0]
            parts = net.split('.')
            base = '.'.join(parts[:3])
            
            logger.info(f"Fallback scanning {base}.1-254 with ping")
            
            for i in range(1, 255):
                target = f"{base}.{i}"
                try:
                    param = '-n' if platform.system().lower() == 'windows' else '-c'
                    cmd = ['ping', param, '1', '-W', '1', target]
                    result = subprocess.run(cmd, capture_output=True, timeout=1)
                    
                    if result.returncode == 0:
                        hostname = ''
                        try:
                            hostname = socket.gethostbyaddr(target)[0]
                        except:
                            pass
                        
                        devices.append({
                            'ip_address': target,
                            'mac_address': '',
                            'hostname': hostname,
                            'vendor': 'Unknown',
                            'status': 'up',
                            'last_seen': datetime.utcnow().isoformat()
                        })
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Fallback scan failed: {e}")
        
        return devices
    
    def port_scan(self, target: str, ports: str = "1-1000", 
                  service_detection: bool = True) -> List[Dict[str, Any]]:
        """Perform port scan on target"""
        logger.info(f"Port scanning {target} on ports {ports}")
        
        if self.nm is None:
            logger.error("nmap not available, port scan cannot be performed")
            return []
        
        scan_args = f'-p {ports}'
        if service_detection:
            scan_args += ' -sV --version-intensity 5 -T4'
        
        try:
            self.nm.scan(hosts=target, arguments=scan_args)
            
            results = []
            if target in self.nm.all_hosts():
                host_info = self.nm[target]
                
                if 'tcp' in host_info:
                    for port, port_info in host_info['tcp'].items():
                        results.append({
                            'port': port,
                            'protocol': 'tcp',
                            'state': port_info.get('state', ''),
                            'service': port_info.get('name', '') or '',
                            'service_version': port_info.get('version', '') or '',
                            'banner': (port_info.get('product', '') or '') + ' ' + (port_info.get('version', '') or '')
                        })
                
                if 'udp' in host_info:
                    for port, port_info in host_info['udp'].items():
                        results.append({
                            'port': port,
                            'protocol': 'udp',
                            'state': port_info.get('state', ''),
                            'service': port_info.get('name', '') or '',
                            'service_version': port_info.get('version', '') or '',
                            'banner': (port_info.get('product', '') or '') + ' ' + (port_info.get('version', '') or '')
                        })
            
            logger.info(f"Port scan complete: {len(results)} ports found")
            return results
            
        except Exception as e:
            logger.error(f"Port scan failed: {e}")
            return []
    
    def os_detection(self, target: str) -> Optional[Dict[str, Any]]:
        """Attempt OS detection"""
        logger.info(f"Running OS detection on {target}")
        
        if self.nm is None:
            return None
        
        try:
            self.nm.scan(hosts=target, arguments='-O --max-retries 2')
            
            if target in self.nm.all_hosts():
                os_info = self.nm[target].get('osmatch', [])
                if os_info:
                    return {
                        'os_guess': os_info[0].get('name', ''),
                        'accuracy': os_info[0].get('accuracy', 0),
                        'line': os_info[0].get('line', '')
                    }
        except Exception as e:
            logger.error(f"OS detection failed: {e}")
        
        return None
    
    def _fallback_port_scan(self, target: str, ports: str) -> List[Dict[str, Any]]:
        """Fallback port scan using socket"""
        results = []
        try:
            port_range = range(1, 101) if ports == "1-1000" else range(1, 1001)
            
            import socket
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080]
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service = 'unknown'
                    try:
                        service = socket.getservbyport(port)
                    except:
                        pass
                    
                    results.append({
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': service,
                        'service_version': '',
                        'banner': ''
                    })
                    
        except Exception as e:
            logger.error(f"Fallback port scan failed: {e}")
        
        return results
    
    def full_scan(self, target: str, quick: bool = False) -> Dict[str, Any]:
        """Perform comprehensive scan"""
        ports = "1-1000" if quick else "1-65535"
        
        arp_results = self.arp_scan(target)
        
        port_results = self.port_scan(target, ports=ports)
        
        os_info = self.os_detection(target)
        
        return {
            'target': target,
            'devices': arp_results,
            'ports': port_results,
            'os_info': os_info,
            'scan_time': datetime.utcnow()
        }
    
    async def async_scan(self, target: str) -> Dict[str, Any]:
        """Async wrapper for scanning"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.full_scan, target)
