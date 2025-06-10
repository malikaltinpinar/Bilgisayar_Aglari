# scapy_test.py
from scapy.all import *

def send_custom_packet(src_ip, dst_ip, data):
    ip = IP(src=src_ip, dst=dst_ip, ttl=64)
    packet = ip / Raw(load=data)
    send(packet)
    print("[+] Özel IP paketi gönderildi.")

if __name__ == "__main__":
    send_custom_packet("127.0.0.1", "127.0.0.1", b"Test Data")
