"""
Test crypto module functionality.
"""

import secrets
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from threelock.crypto import (
    PasswordProvider, 
    encrypt_string, 
    decrypt_string,
    decrypt_to_bytearray,
    DecryptionError
)


def test_full_flow():
    """Test complete encryption/decryption flow."""
    
    print("=== 3Lock Crypto Test ===\n")
    
    # 1. Setup
    password = "my_secure_password_123"
    salt = secrets.token_bytes(16)
    
    print(f"Salt (hex): {salt.hex()}")
    
    # 2. Derive keys
    print("\nDeriving keys...")
    import time
    start = time.perf_counter()
    
    provider = PasswordProvider(password)
    keys = provider.derive_keys(salt)
    
    elapsed = time.perf_counter() - start
    print(f"Key derivation took: {elapsed:.2f} seconds")
    
    # 3. Encrypt some data
    title = "My Bank Account"
    note = "Login: user@example.com\nWebsite: bank.com"
    password_secret = "super_secret_password_42!"
    
    print(f"\n--- Encrypting ---")
    
    encrypted_title = encrypt_string(keys.titles_key, title)
    encrypted_note = encrypt_string(keys.content_key, note)
    encrypted_password = encrypt_string(keys.content_key, password_secret)
    
    print(f"Encrypted title: {len(encrypted_title)} bytes")
    print(f"Encrypted note: {len(encrypted_note)} bytes")
    print(f"Encrypted password: {len(encrypted_password)} bytes")
    
    # 4. Decrypt
    print(f"\n--- Decrypting ---")
    
    decrypted_title = decrypt_string(keys.titles_key, encrypted_title)
    decrypted_note = decrypt_string(keys.content_key, encrypted_note)
    
    # For password - use bytearray
    decrypted_password_ba = decrypt_to_bytearray(keys.content_key, encrypted_password)
    decrypted_password = decrypted_password_ba.decode('utf-8')
    
    print(f"Title: {decrypted_title}")
    print(f"Note: {decrypted_note}")
    print(f"Password: {decrypted_password}")
    
    # Wipe password
    for i in range(len(decrypted_password_ba)):
        decrypted_password_ba[i] = 0
    
    # 5. Test wrong key
    print(f"\n--- Testing wrong key ---")
    wrong_provider = PasswordProvider("wrong_password")
    wrong_keys = wrong_provider.derive_keys(salt)
    
    try:
        decrypt_string(wrong_keys.titles_key, encrypted_title)
        print("ERROR: Should have failed!")
        return 1
    except DecryptionError:
        print("Correctly rejected wrong key")
    
    # 6. Cleanup
    provider.clear()
    keys.clear()
    wrong_provider.clear()
    
    # 7. Verify
    assert decrypted_title == title
    assert decrypted_note == note
    assert decrypted_password == password_secret
    
    print("\n=== All tests passed! ===")
    return 0


if __name__ == "__main__":
    sys.exit(test_full_flow())
