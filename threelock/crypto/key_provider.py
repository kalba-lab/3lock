"""
Abstract interface for key providers.
Designed for extension: password now, YubiKey later.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class DerivedKeys:
    """Container for derived encryption keys."""
    titles_key: bytes   # 32 bytes, for encrypting topic titles
    content_key: bytes  # 32 bytes, for encrypting notes and passwords
    
    def clear(self) -> None:
        """Securely wipe keys from memory."""
        if self.titles_key:
            ba = bytearray(self.titles_key)
            for i in range(len(ba)):
                ba[i] = 0
            self.titles_key = bytes(ba)
        
        if self.content_key:
            ba = bytearray(self.content_key)
            for i in range(len(ba)):
                ba[i] = 0
            self.content_key = bytes(ba)


class KeyProvider(ABC):
    """
    Abstract base for key derivation strategies.
    
    Implementations:
    - PasswordProvider: derives keys from user password
    - YubikeyProvider: (future) derives keys using hardware token
    """
    
    @abstractmethod
    def derive_keys(self, salt: bytes) -> DerivedKeys:
        """
        Derive encryption keys from user credentials.
        
        Args:
            salt: Random bytes stored with the vault
            
        Returns:
            DerivedKeys with titles_key and content_key
            
        Raises:
            KeyDerivationError: If key derivation fails
        """
        pass
    
    @abstractmethod
    def clear(self) -> None:
        """Clear any sensitive data held by the provider."""
        pass
    
    @property
    @abstractmethod
    def provider_type(self) -> str:
        """Identifier for serialization (e.g., 'password', 'yubikey')."""
        pass


class KeyDerivationError(Exception):
    """Raised when key derivation fails."""
    pass
