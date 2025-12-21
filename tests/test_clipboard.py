"""
Test secure clipboard functionality.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from threelock.clipboard import SecureClipboard, get_clipboard


def test_clipboard():
    """Test clipboard with auto-clear."""
    
    print("=== 3Lock Clipboard Test ===\n")
    
    # 1. Basic copy/paste
    print("--- Basic copy/paste ---")
    clipboard = get_clipboard()
    
    test_data = b"test_password_123"
    clipboard.copy(test_data)
    
    result = clipboard.get()
    print(f"Copied: {test_data}")
    print(f"Got back: {result}")
    assert result == test_data, "Copy/paste mismatch!"
    print("OK")
    
    # 2. Clear
    print("\n--- Clear ---")
    clipboard.clear()
    result = clipboard.get()
    print(f"After clear: {result!r}")
    assert result == b"", "Clipboard not cleared!"
    print("OK")
    
    # 3. SecureClipboard with auto-clear
    print("\n--- SecureClipboard auto-clear (3 sec) ---")
    secure = SecureClipboard(clear_after=3)
    
    password = bytearray(b"secret_password")
    secure.copy_password(password)
    
    # Wipe source
    for i in range(len(password)):
        password[i] = 0
    
    print("Password copied, waiting...")
    
    # Check immediately
    result = clipboard.get()
    print(f"Immediately: {result}")
    assert result == b"secret_password", "Password not copied!"
    
    # Wait for auto-clear
    print("Waiting 4 seconds for auto-clear...")
    time.sleep(4)
    
    result = clipboard.get()
    print(f"After 4 sec: {result!r}")
    assert result == b"", "Auto-clear failed!"
    print("OK")
    
    # 4. Manual clear cancels timer
    print("\n--- Manual clear cancels timer ---")
    password = bytearray(b"another_secret")
    secure.copy_password(password)
    for i in range(len(password)):
        password[i] = 0
    
    print("Copied, clearing manually...")
    secure.clear()
    
    result = clipboard.get()
    print(f"After manual clear: {result!r}")
    assert result == b"", "Manual clear failed!"
    print("OK")
    
    print("\n=== All clipboard tests passed! ===")
    return 0


if __name__ == "__main__":
    sys.exit(test_clipboard())
