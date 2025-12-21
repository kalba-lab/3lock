"""
Cryptographic primitives for 3Lock.
"""

from .key_provider import KeyProvider, DerivedKeys, KeyDerivationError
from .password_provider import PasswordProvider, benchmark_argon2
from .cipher import (
    Cipher, 
    EncryptedData, 
    DecryptionError,
    encrypt_string, 
    decrypt_string, 
    decrypt_to_bytearray
)

__all__ = [
    'KeyProvider',
    'DerivedKeys', 
    'KeyDerivationError',
    'PasswordProvider',
    'benchmark_argon2',
    'Cipher',
    'EncryptedData',
    'DecryptionError',
    'encrypt_string',
    'decrypt_string',
    'decrypt_to_bytearray',
]
