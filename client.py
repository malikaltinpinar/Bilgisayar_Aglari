# client.py
import socket
import time
from common import *

def run_client():
    SERVER_IP = '127.0.0.1'
    SERVER_PORT = 5001

    time.sleep(2)  # Sunucunun hazır olması için bekle

    # Sunucu anahtarını oku
    with open("server_public.pem", "rb") as f:
        public_key = f.read()

    # Gönderilecek dosyayı oku
    with open("file_to_send", "rb") as f:
        file_data = f.read()

    # SHA-256 hash + veri birleştir
    file_hash = sha256_hash(file_data).encode()
    full_data = file_hash + file_data

    # AES ile şifrele
    aes_key = generate_aes_key()
    nonce, ciphertext, tag = encrypt_aes(full_data, aes_key)

    # AES anahtarını RSA ile şifrele
    encrypted_key = encrypt_rsa(aes_key, public_key)

    # Sunucuya gönder
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    client_socket.send(encrypted_key)
    client_socket.sendall(nonce + tag + ciphertext)
    print("[+] Dosya gönderildi.")
    client_socket.close()

if __name__ == "__main__":
    run_client()
