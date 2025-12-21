"""
Encryption/decryption operations using AES-256-GCM.
"""

import secrets
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_SIZE = 12  # 96 bits, recommended for GCM


@dataclass
class EncryptedData:
    """Container for encrypted data with nonce."""
    nonce: bytes      # 12 bytes
    ciphertext: bytes # variable length, includes auth tag
    
    def to_bytes(self) -> bytes:
        """Serialize for storage."""
        return self.nonce + self.ciphertext
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'EncryptedData':
        """Deserialize from storage."""
        if len(data) < NONCE_SIZE + 16:  # minimum: nonce + auth tag
            raise DecryptionError("Data too short")
        return cls(
            nonce=data[:NONCE_SIZE],
            ciphertext=data[NONCE_SIZE:]
        )


class Cipher:
    """
    AES-256-GCM encryption/decryption.
    
    GCM provides:
    - Confidentiality (encryption)
    - Integrity (authentication tag)
    """
    
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        self._aesgcm = AESGCM(key)
    
    def encrypt(self, plaintext: bytes) -> EncryptedData:
        """Encrypt data with a fresh random nonce."""
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data=None)
        return EncryptedData(nonce=nonce, ciphertext=ciphertext)
    
    def decrypt(self, encrypted: EncryptedData) -> bytes:
        """Decrypt data. Raises DecryptionError on failure."""
        try:
            return self._aesgcm.decrypt(
                encrypted.nonce, 
                encrypted.ciphertext, 
                associated_data=None
            )
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}")


class DecryptionError(Exception):
    """Raised when decryption fails (wrong key or tampered data)."""
    pass


# Convenience functions

def encrypt_string(key: bytes, text: str) -> bytes:
    """Encrypt a string, return bytes for storage."""
    cipher = Cipher(key)
    encrypted = cipher.encrypt(text.encode('utf-8'))
    return encrypted.to_bytes()


def decrypt_string(key: bytes, data: bytes) -> str:
    """Decrypt bytes back to string."""
    cipher = Cipher(key)
    encrypted = EncryptedData.from_bytes(data)
    plaintext = cipher.decrypt(encrypted)
    return plaintext.decode('utf-8')


def decrypt_to_bytearray(key: bytes, data: bytes) -> bytearray:
    """
    Decrypt to bytearray for sensitive data (passwords).
    Allows secure wiping after use.
    """
    cipher = Cipher(key)
    encrypted = EncryptedData.from_bytes(data)
    plaintext = cipher.decrypt(encrypted)
    return bytearray(plaintext)
