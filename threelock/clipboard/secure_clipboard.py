"""
Secure clipboard with auto-clear functionality.
"""

import subprocess
import sys
import threading
from abc import ABC, abstractmethod
from typing import Optional


class Clipboard(ABC):
    """Abstract clipboard interface."""
    
    @abstractmethod
    def copy(self, data: bytes) -> None:
        """Copy bytes to clipboard."""
        pass
    
    @abstractmethod
    def clear(self) -> None:
        """Clear clipboard contents."""
        pass
    
    @abstractmethod
    def get(self) -> Optional[bytes]:
        """Get clipboard contents (for testing)."""
        pass


class MacOSClipboard(Clipboard):
    """macOS clipboard using pbcopy/pbpaste."""
    
    def copy(self, data: bytes) -> None:
        process = subprocess.Popen(
            ["pbcopy"],
            stdin=subprocess.PIPE,
            env={"LANG": "en_US.UTF-8"}
        )
        process.communicate(input=data)
        if process.returncode != 0:
            raise ClipboardError("Failed to copy to clipboard")
    
    def clear(self) -> None:
        self.copy(b"")
    
    def get(self) -> Optional[bytes]:
        try:
            result = subprocess.run(
                ["pbpaste"],
                capture_output=True,
                env={"LANG": "en_US.UTF-8"}
            )
            return result.stdout if result.returncode == 0 else None
        except Exception:
            return None


class LinuxClipboard(Clipboard):
    """Linux clipboard - placeholder for future implementation."""
    
    def copy(self, data: bytes) -> None:
        # TODO: xclip, xsel, or wl-copy
        raise NotImplementedError("Linux clipboard not yet implemented")
    
    def clear(self) -> None:
        raise NotImplementedError("Linux clipboard not yet implemented")
    
    def get(self) -> Optional[bytes]:
        raise NotImplementedError("Linux clipboard not yet implemented")


class WindowsClipboard(Clipboard):
    """Windows clipboard - placeholder for future implementation."""
    
    def copy(self, data: bytes) -> None:
        # TODO: win32clipboard or ctypes
        raise NotImplementedError("Windows clipboard not yet implemented")
    
    def clear(self) -> None:
        raise NotImplementedError("Windows clipboard not yet implemented")
    
    def get(self) -> Optional[bytes]:
        raise NotImplementedError("Windows clipboard not yet implemented")


class ClipboardError(Exception):
    """Clipboard operation failed."""
    pass


def get_clipboard() -> Clipboard:
    """Get platform-appropriate clipboard implementation."""
    if sys.platform == "darwin":
        return MacOSClipboard()
    elif sys.platform.startswith("linux"):
        return LinuxClipboard()
    elif sys.platform == "win32":
        return WindowsClipboard()
    else:
        raise ClipboardError(f"Unsupported platform: {sys.platform}")


class SecureClipboard:
    """
    Clipboard wrapper with auto-clear functionality.
    
    Usage:
        clipboard = SecureClipboard(clear_after=30)
        clipboard.copy_password(password_bytes)
        # Password is cleared from clipboard after 30 seconds
    """
    
    def __init__(self, clear_after: int = 30):
        self._clipboard = get_clipboard()
        self._clear_after = clear_after
        self._clear_timer: Optional[threading.Timer] = None
    
    def copy_password(self, password: bytearray) -> None:
        """
        Copy password to clipboard with auto-clear.
        Caller is responsible for wiping password bytearray after.
        """
        self._cancel_timer()
        self._clipboard.copy(bytes(password))
        
        if self._clear_after > 0:
            self._clear_timer = threading.Timer(
                self._clear_after,
                self._auto_clear
            )
            self._clear_timer.daemon = True
            self._clear_timer.start()
    
    def copy_text(self, text: str) -> None:
        """Copy plain text (no auto-clear)."""
        self._cancel_timer()
        self._clipboard.copy(text.encode("utf-8"))
    
    def clear(self) -> None:
        """Clear clipboard immediately."""
        self._cancel_timer()
        self._clipboard.clear()
    
    def _auto_clear(self) -> None:
        try:
            self._clipboard.clear()
        except Exception:
            pass
        self._clear_timer = None
    
    def _cancel_timer(self) -> None:
        if self._clear_timer:
            self._clear_timer.cancel()
            self._clear_timer = None
    
    @property
    def clear_after(self) -> int:
        return self._clear_after
    
    @clear_after.setter
    def clear_after(self, seconds: int) -> None:
        self._clear_after = max(0, seconds)
