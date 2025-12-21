"""
Test vault functionality.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from threelock.storage import Vault, VaultError, WrongPasswordError


def test_vault():
    """Test complete vault workflow."""
    
    print("=== 3Lock Vault Test ===\n")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_path = Path(tmpdir) / "test.3lock"
        password = "test_password_123"
        
        # 1. Create new vault
        print("--- Creating new vault ---")
        vault = Vault.create(vault_path, password)
        print(f"Vault created: {vault_path}")
        print(f"Topics: {len(vault.list_topics())}")
        
        # 2. Add topics
        print("\n--- Adding topics ---")
        t1 = vault.add_topic(
            title="Gmail",
            note="Email: user@gmail.com\nRecovery: phone",
            password="gmail_secret_123"
        )
        print(f"Added: {t1.title} (id: {t1.id[:8]}...)")
        
        t2 = vault.add_topic(
            title="Bank Account",
            note="Account: 1234567890\nRouting: 987654321",
            password="bank_password_456"
        )
        print(f"Added: {t2.title} (id: {t2.id[:8]}...)")
        
        # 3. Save vault
        print("\n--- Saving vault ---")
        vault.save()
        print("Saved to disk")
        
        # 4. Lock and reopen
        print("\n--- Lock and reopen ---")
        vault.lock()
        print("Vault locked")
        
        vault = Vault.open(vault_path, password)
        print(f"Vault reopened, topics: {len(vault.list_topics())}")
        
        # 5. List topics
        print("\n--- List topics (titles only) ---")
        for topic in vault.list_topics():
            print(f"  - {topic.title}")
        
        # 6. Get note (lazy decryption)
        print("\n--- Get note (lazy decryption) ---")
        note = vault.get_note(t1.id)
        print(f"Note for '{t1.title}':")
        print(f"  {note}")
        
        # 7. Get password as bytearray
        print("\n--- Get password (secure) ---")
        pwd_bytes = vault.get_password_bytes(t1.id)
        print(f"Password bytes: {pwd_bytes}")
        # Wipe
        for i in range(len(pwd_bytes)):
            pwd_bytes[i] = 0
        print(f"After wipe: {pwd_bytes}")
        
        # 8. Update topic
        print("\n--- Update topic ---")
        vault.update_topic(t1.id, note="Updated note content")
        vault.save()
        print(f"Updated note: {vault.get_note(t1.id)}")
        
        # 9. Delete topic
        print("\n--- Delete topic ---")
        vault.delete_topic(t2.id)
        vault.save()
        print(f"Topics after delete: {len(vault.list_topics())}")
        
        # 10. Test wrong password
        print("\n--- Test wrong password ---")
        vault.lock()
        try:
            Vault.open(vault_path, "wrong_password")
            print("ERROR: Should have failed!")
            return 1
        except WrongPasswordError:
            print("Correctly rejected wrong password")
        
        # 11. Verify file contents
        print("\n--- Verify file structure ---")
        with open(vault_path) as f:
            import json
            data = json.load(f)
        print(f"Version: {data['version']}")
        print(f"KDF algorithm: {data['kdf']['algorithm']}")
        print(f"Topics in file: {len(data['topics'])}")
        print(f"First topic title (encrypted): {data['topics'][0]['title'][:40]}...")
        
        print("\n=== All vault tests passed! ===")
        return 0


if __name__ == "__main__":
    sys.exit(test_vault())
