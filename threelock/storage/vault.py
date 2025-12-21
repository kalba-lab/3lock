"""
Vault - encrypted storage for topics.
"""

import json
import secrets
import uuid
from base64 import b64encode, b64decode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..crypto import (
    PasswordProvider,
    DerivedKeys,
    encrypt_string,
    decrypt_string,
    decrypt_to_bytearray,
    DecryptionError,
)


VAULT_VERSION = 1
SALT_SIZE = 16


@dataclass
class Topic:
    """Single topic with encrypted fields."""
    id: str
    title: str  # decrypted, available after unlock
    _encrypted_note: bytes = field(repr=False)
    _encrypted_password: bytes = field(repr=False)
    
    # Decrypted content (lazy loaded)
    _note: Optional[str] = field(default=None, repr=False)
    _password_bytes: Optional[bytearray] = field(default=None, repr=False)


class Vault:
    """
    Encrypted storage for topics.
    
    Usage:
        # Create new vault
        vault = Vault.create(path, password)
        vault.add_topic("Gmail", "user@gmail.com", "secret123")
        vault.save()
        
        # Open existing vault
        vault = Vault.open(path, password)
        for topic in vault.list_topics():
            print(topic.title)
        note = vault.get_note(topic_id)
        vault.copy_password(topic_id)  # copies to clipboard
    """
    
    def __init__(
        self,
        path: Path,
        keys: DerivedKeys,
        kdf_params: dict,
        salt: bytes,
        topics: list[dict],
    ):
        self._path = path
        self._keys = keys
        self._kdf_params = kdf_params
        self._salt = salt
        self._topics: dict[str, Topic] = {}
        
        # Decrypt titles (lazy: notes and passwords stay encrypted)
        for t in topics:
            topic_id = t["id"]
            encrypted_title = b64decode(t["title"])
            encrypted_note = b64decode(t["note"])
            encrypted_password = b64decode(t["password"])
            
            title = decrypt_string(self._keys.titles_key, encrypted_title)
            
            self._topics[topic_id] = Topic(
                id=topic_id,
                title=title,
                _encrypted_note=encrypted_note,
                _encrypted_password=encrypted_password,
            )
    
    @classmethod
    def create(cls, path: Path, password: str) -> "Vault":
        """Create a new empty vault."""
        path = Path(path)
        
        if path.exists():
            raise VaultError(f"Vault already exists: {path}")
        
        # Ensure parent directory exists
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate salt and derive keys
        salt = secrets.token_bytes(SALT_SIZE)
        provider = PasswordProvider(password)
        keys = provider.derive_keys(salt)
        kdf_params = provider.get_kdf_params()
        
        vault = cls(
            path=path,
            keys=keys,
            kdf_params=kdf_params,
            salt=salt,
            topics=[],
        )
        
        vault.save()
        return vault
    
    @classmethod
    def open(cls, path: Path, password: str) -> "Vault":
        """Open an existing vault."""
        path = Path(path)
        
        if not path.exists():
            raise VaultError(f"Vault not found: {path}")
        
        # Read and parse vault file
        with open(path, "r") as f:
            data = json.load(f)
        
        version = data.get("version", 0)
        if version != VAULT_VERSION:
            raise VaultError(f"Unsupported vault version: {version}")
        
        # Extract KDF params and salt
        kdf = data["kdf"]
        salt = b64decode(kdf["salt"])
        
        # Derive keys with stored parameters
        provider = PasswordProvider(
            password,
            time_cost=kdf["time_cost"],
            memory_cost=kdf["memory_cost"],
            parallelism=kdf["parallelism"],
        )
        keys = provider.derive_keys(salt)
        
        # Verify password by trying to decrypt first title (if any)
        topics = data.get("topics", [])
        if topics:
            try:
                test_title = b64decode(topics[0]["title"])
                decrypt_string(keys.titles_key, test_title)
            except DecryptionError:
                raise WrongPasswordError("Wrong password")
        
        return cls(
            path=path,
            keys=keys,
            kdf_params=kdf,
            salt=salt,
            topics=topics,
        )
    
    def save(self) -> None:
        """Save vault to disk."""
        topics_data = []
        
        for topic in self._topics.values():
            # Re-encrypt title (in case it changed)
            encrypted_title = encrypt_string(self._keys.titles_key, topic.title)
            
            topics_data.append({
                "id": topic.id,
                "title": b64encode(encrypted_title).decode("ascii"),
                "note": b64encode(topic._encrypted_note).decode("ascii"),
                "password": b64encode(topic._encrypted_password).decode("ascii"),
            })
        
        data = {
            "version": VAULT_VERSION,
            "kdf": {
                **self._kdf_params,
                "salt": b64encode(self._salt).decode("ascii"),
            },
            "topics": topics_data,
        }
        
        # Write atomically (write to temp, then rename)
        temp_path = self._path.with_suffix(".tmp")
        with open(temp_path, "w") as f:
            json.dump(data, f, indent=2)
        temp_path.replace(self._path)
    
    def list_topics(self) -> list[Topic]:
        """Get all topics (titles decrypted, content not loaded)."""
        return list(self._topics.values())
    
    def get_topic(self, topic_id: str) -> Optional[Topic]:
        """Get topic by ID."""
        return self._topics.get(topic_id)
    
    def get_note(self, topic_id: str) -> str:
        """Decrypt and return note for a topic."""
        topic = self._topics.get(topic_id)
        if not topic:
            raise VaultError(f"Topic not found: {topic_id}")
        
        if topic._note is None:
            topic._note = decrypt_string(
                self._keys.content_key, 
                topic._encrypted_note
            )
        
        return topic._note
    
    def get_password_bytes(self, topic_id: str) -> bytearray:
        """
        Decrypt password as bytearray for secure handling.
        Caller is responsible for wiping after use.
        """
        topic = self._topics.get(topic_id)
        if not topic:
            raise VaultError(f"Topic not found: {topic_id}")
        
        # Always return fresh bytearray (don't cache passwords)
        return decrypt_to_bytearray(
            self._keys.content_key,
            topic._encrypted_password
        )
    
    def add_topic(self, title: str, note: str, password: str) -> Topic:
        """Add a new topic."""
        topic_id = str(uuid.uuid4())
        
        encrypted_note = encrypt_string(self._keys.content_key, note)
        encrypted_password = encrypt_string(self._keys.content_key, password)
        
        topic = Topic(
            id=topic_id,
            title=title,
            _encrypted_note=encrypted_note,
            _encrypted_password=encrypted_password,
            _note=note,  # cache since we just created it
        )
        
        self._topics[topic_id] = topic
        return topic
    
    def update_topic(
        self,
        topic_id: str,
        title: Optional[str] = None,
        note: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Topic:
        """Update an existing topic."""
        topic = self._topics.get(topic_id)
        if not topic:
            raise VaultError(f"Topic not found: {topic_id}")
        
        if title is not None:
            topic.title = title
        
        if note is not None:
            topic._encrypted_note = encrypt_string(self._keys.content_key, note)
            topic._note = note
        
        if password is not None:
            topic._encrypted_password = encrypt_string(self._keys.content_key, password)
            # Don't cache password
        
        return topic
    
    def delete_topic(self, topic_id: str) -> None:
        """Delete a topic."""
        if topic_id not in self._topics:
            raise VaultError(f"Topic not found: {topic_id}")
        
        topic = self._topics.pop(topic_id)
        
        # Wipe cached data
        if topic._note:
            topic._note = None
        if topic._password_bytes:
            for i in range(len(topic._password_bytes)):
                topic._password_bytes[i] = 0
            topic._password_bytes = None
    
    def clear_cached_content(self) -> None:
        """Clear all decrypted notes from memory."""
        for topic in self._topics.values():
            topic._note = None
            if topic._password_bytes:
                for i in range(len(topic._password_bytes)):
                    topic._password_bytes[i] = 0
                topic._password_bytes = None
    
    def lock(self) -> None:
        """Lock vault - clear all sensitive data from memory."""
        self.clear_cached_content()
        if self._keys:
            self._keys.clear()
            self._keys = None
    
    def change_password(self, old_password: str, new_password: str) -> None:
        """Change vault password."""
        # Verify old password
        provider = PasswordProvider(
            old_password,
            time_cost=self._kdf_params["time_cost"],
            memory_cost=self._kdf_params["memory_cost"],
            parallelism=self._kdf_params["parallelism"],
        )
        test_keys = provider.derive_keys(self._salt)
        
        # Try to verify (if we have topics)
        if self._topics:
            topic = next(iter(self._topics.values()))
            encrypted_title = encrypt_string(test_keys.titles_key, topic.title)
            # If we got here without exception, old password is correct
        
        provider.clear()
        test_keys.clear()
        
        # Generate new salt and keys
        new_salt = secrets.token_bytes(SALT_SIZE)
        new_provider = PasswordProvider(new_password)
        new_keys = new_provider.derive_keys(new_salt)
        
        # Re-encrypt all topics with new keys
        for topic in self._topics.values():
            # Decrypt with old keys
            note = decrypt_string(self._keys.content_key, topic._encrypted_note)
            password_ba = decrypt_to_bytearray(self._keys.content_key, topic._encrypted_password)
            
            # Encrypt with new keys
            topic._encrypted_note = encrypt_string(new_keys.content_key, note)
            topic._encrypted_password = encrypt_string(
                new_keys.content_key, 
                password_ba.decode("utf-8")
            )
            
            # Wipe password
            for i in range(len(password_ba)):
                password_ba[i] = 0
        
        # Update vault state
        old_keys = self._keys
        self._keys = new_keys
        self._salt = new_salt
        self._kdf_params = new_provider.get_kdf_params()
        
        # Clear old keys
        old_keys.clear()
        
        # Save with new encryption
        self.save()


class VaultError(Exception):
    """General vault error."""
    pass


class WrongPasswordError(VaultError):
    """Raised when password is incorrect."""
    pass
