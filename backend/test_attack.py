import socket
import time

def simulate_ssh_attack(host='127.0.0.1', port=2222):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        
        banner = s.recv(1024)
        print(f"[+] Banner: {banner.decode()}")
        
        commands = [
            b'user admin\n',
            b'password 123456\n',
            b'ls -la\n',
            b'cat /etc/passwd\n',
            b'exit\n'
        ]
        
        for cmd in commands:
            s.send(cmd)
            time.sleep(0.2)
            try:
                resp = s.recv(2048)
                if resp:
                    print(f"[<] {resp.decode('utf-8', errors='ignore')[:100]}")
            except:
                pass
        
        s.close()
        print("[+] Attack simulation complete")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == '__main__':
    print("Simulating SSH attack on honeypot port 2222...")
    simulate_ssh_attack()
