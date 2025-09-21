import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class CryptoManager:
    def __init__(self):
        self.backend = default_backend()
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def encrypt_data(self, data: str, password: str) -> str:
        salt = os.urandom(16)
        iv = os.urandom(12)
        key = self.derive_key(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        
        encrypted_data = salt + iv + encryptor.tag + ciphertext
        return base64.b64encode(encrypted_data).decode()
    
    def decrypt_data(self, encrypted_data: str, password: str) -> str:
        data = base64.b64decode(encrypted_data.encode())
        salt, iv, tag, ciphertext = data[:16], data[16:28], data[28:44], data[44:]
        
        key = self.derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()