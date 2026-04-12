import socket
import time

def attack_once():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('127.0.0.1', 2222))
        
        time.sleep(0.5)
        
        s.send(b'user admin\n')
        time.sleep(0.3)
        
        s.send(b'pass hack123\n')
        time.sleep(0.3)
        
        s.close()
        print("Sent attack commands")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    attack_once()
