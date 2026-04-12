import socket
import time
import sys

def attack_target(port, service_name, commands):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(('127.0.0.1', port))
        
        time.sleep(0.3)
        
        for cmd in commands:
            s.send(cmd.encode() + b'\n')
            time.sleep(0.2)
        
        s.close()
        print(f"[OK] Attacked {service_name} on port {port}")
        return True
    except Exception as e:
        print(f"[X] Failed to attack {service_name} on port {port}: {e}")
        return False

if __name__ == '__main__':
    attacks = [
        (2222, "SSH", ["user admin", "pass password123"]),
        (2323, "Telnet", ["root"]),
        (8081, "HTTP", ["GET / HTTP/1.1"]),
        (8443, "HTTPS", ["GET / HTTP/1.1"]),
        (2443, "SMB", ["SMB"]),
        (3389, "RDP", [""]),
        (2121, "FTP", ["USER anonymous", "PASS ftp"]),
        (2525, "SMTP", ["HELO test.com"]),
    ]
    
    for port, service, commands in attacks:
        try:
            attack_target(port, service, commands)
        except:
            pass
        time.sleep(0.5)
    
    print("\nDone attacking all honeypots")
