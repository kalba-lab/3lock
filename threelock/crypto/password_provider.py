"""
Password-based key provider using Argon2.
"""

from argon2.low_level import hash_secret_raw, Type
from hashlib import sha256
import hmac

from .key_provider import KeyProvider, DerivedKeys, KeyDerivationError


class PasswordProvider(KeyProvider):
    """
    Derives encryption keys from a user password using Argon2id.
    
    Security parameters tuned for ~1 second derivation time.
    Run benchmark_argon2() on your machine to calibrate.
    """
    
    # Default Argon2 parameters - adjust after benchmarking - IMPORTANT! 
    DEFAULT_TIME_COST = 6
    DEFAULT_MEMORY_COST = 1048576  # 1 GB
    DEFAULT_PARALLELISM = 4
    DEFAULT_HASH_LEN = 32
    
    def __init__(
        self,
        password: str,
        time_cost: int = DEFAULT_TIME_COST,
        memory_cost: int = DEFAULT_MEMORY_COST,
        parallelism: int = DEFAULT_PARALLELISM
    ):
        self._password = bytearray(password.encode('utf-8'))
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self._derived_keys: DerivedKeys | None = None
    
    def derive_keys(self, salt: bytes) -> DerivedKeys:
        """
        Derive titles_key and content_key from password.
        
        Chain: password + salt → Argon2 → master_key → HKDF → two keys
        """
        if not self._password:
            raise KeyDerivationError("Password has been cleared")
        
        try:
            # Step 1: Argon2id to get master key
            master_key = hash_secret_raw(
                secret=bytes(self._password),
                salt=salt,
                time_cost=self.time_cost,
                memory_cost=self.memory_cost,
                parallelism=self.parallelism,
                hash_len=self.DEFAULT_HASH_LEN,
                type=Type.ID
            )
            
            # Step 2: HKDF-like derivation for separate keys
            titles_key = self._hkdf_expand(master_key, b"3lock-titles-v1")
            content_key = self._hkdf_expand(master_key, b"3lock-content-v1")
            
            # Wipe master key
            master_ba = bytearray(master_key)
            for i in range(len(master_ba)):
                master_ba[i] = 0
            
            self._derived_keys = DerivedKeys(
                titles_key=titles_key,
                content_key=content_key
            )
            
            return self._derived_keys
            
        except Exception as e:
            raise KeyDerivationError(f"Key derivation failed: {e}")
    
    def _hkdf_expand(self, key: bytes, info: bytes) -> bytes:
        """Simple HKDF-Expand using HMAC-SHA256."""
        return hmac.new(key, info + b'\x01', sha256).digest()
    
    def clear(self) -> None:
        """Securely wipe password and derived keys."""
        if self._password:
            for i in range(len(self._password)):
                self._password[i] = 0
            self._password.clear()
        
        if self._derived_keys:
            self._derived_keys.clear()
            self._derived_keys = None
    
    @property
    def provider_type(self) -> str:
        return "password"
    
    def get_kdf_params(self) -> dict:
        """Return KDF parameters for storage in vault header."""
        return {
            "algorithm": "argon2id",
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "hash_len": self.DEFAULT_HASH_LEN
        }


def benchmark_argon2(target_seconds: float = 1.0) -> dict:
    """
    Find Argon2 parameters that take approximately target_seconds.
    Run this on your machine to calibrate.
    
    Usage:
        from threelock.crypto import benchmark_argon2
        params = benchmark_argon2(1.0)
        print(params)
    """
    import time
    
    test_password = b"benchmark_test_password"
    test_salt = b"0123456789abcdef"
    
    time_cost = 2
    memory_cost = 65536  # 64 MB
    
    while True:
        start = time.perf_counter()
        hash_secret_raw(
            secret=test_password,
            salt=test_salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
        elapsed = time.perf_counter() - start
        
        print(f"time_cost={time_cost}, memory_cost={memory_cost}: {elapsed:.3f}s")
        
        if elapsed >= target_seconds:
            return {
                "time_cost": time_cost,
                "memory_cost": memory_cost,
                "parallelism": 4,
                "elapsed": elapsed
            }
        
        if time_cost < 10:
            time_cost += 1
        else:
            memory_cost *= 2
            time_cost = 2
        
        if memory_cost > 1048576:  # 1 GB max
            break
    
    return {"error": "Could not reach target time"}


if __name__ == "__main__":
    print("Benchmarking Argon2 for ~1 second derivation time...")
    result = benchmark_argon2(1.0)
    print(f"\nRecommended parameters: {result}")
