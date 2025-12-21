"""
YubiKey-based key provider (placeholder for future implementation).
"""

from .key_provider import KeyProvider, DerivedKeys, KeyDerivationError


class YubikeyProvider(KeyProvider):
    """
    Derives encryption keys using YubiKey HMAC-SHA1 challenge-response.
    
    TODO: Implement when YubiKey hardware is available.
    
    Required libraries:
    - yubikey-manager (ykman)
    - python-yubico
    """
    
    def __init__(self, password: str | None = None):
        self._password = bytearray(password.encode('utf-8')) if password else None
        raise NotImplementedError(
            "YubiKey support not yet implemented. "
            "Use PasswordProvider for now."
        )
    
    def derive_keys(self, salt: bytes) -> DerivedKeys:
        raise NotImplementedError()
    
    def clear(self) -> None:
        if self._password:
            for i in range(len(self._password)):
                self._password[i] = 0
            self._password.clear()
    
    @property
    def provider_type(self) -> str:
        return "yubikey"
