# server.py
import socket
from common import *

def recv_exact(sock, length):
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            raise ConnectionError("Bağlantı beklenmedik şekilde kesildi.")
        data += packet
    return data

def run_server():
    SERVER_IP = '127.0.0.1'
    SERVER_PORT = 5001

    # RSA anahtar çifti üret
    private_key, public_key = generate_rsa_keys()
    with open("server_public.pem", "wb") as f:
        f.write(public_key)

    # Sunucu başlat
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(1)
    print(f"[+] Sunucu dinleniyor: {SERVER_IP}:{SERVER_PORT}")

    conn, addr = server_socket.accept()
    print(f"[+] Bağlantı alındı: {addr}")

    # Şifrelenmiş AES anahtarını al
    encrypted_aes_key = recv_exact(conn, 256)
    aes_key = decrypt_rsa(encrypted_aes_key, private_key)

    # Dosya verisini al
    data = conn.recv(4096)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    plaintext = decrypt_aes(nonce, ciphertext, tag, aes_key)

    hash_received = plaintext[:64]
    file_data = plaintext[64:]

    # Bütünlük doğrulama
    if hash_received.decode() == sha256_hash(file_data):
        print("[✅] Dosya bütünlüğü doğrulandı.")
        with open("received_file", "wb") as f:
            f.write(file_data)
    else:
        print("[❌] Bütünlük hatası!")

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    run_server()
