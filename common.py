# common.py
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

# SHA-256 karması
def sha256_hash(data):
    return hashlib.sha256(data).hexdigest()

# AES anahtar üretimi
def generate_aes_key():
    return os.urandom(16)  # 128-bit anahtar

# AES ile şifreleme
def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag

# AES ile çözme
def decrypt_aes(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# RSA anahtar çifti üretimi
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

# RSA ile şifreleme
def encrypt_rsa(data, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(data)

# RSA ile çözme
def decrypt_rsa(ciphertext, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(ciphertext)
# common.py

def fragment(data: bytes, chunk_size: int = 1024) -> list[bytes]:
    """
    Veriyi belirtilen parça boyutlarında böler.
    """
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

def reassemble(chunks: list[bytes]) -> bytes:
    """
    Parçaları birleştirip tek veri haline getirir.
    """
    return b''.join(chunks)
