"""Clipboard module for 3Lock."""

from .secure_clipboard import (
    SecureClipboard,
    Clipboard,
    ClipboardError,
    get_clipboard,
)

__all__ = ["SecureClipboard", "Clipboard", "ClipboardError", "get_clipboard"]
