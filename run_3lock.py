#!/usr/bin/env python3
"""Entry point for 3Lock application."""

from threelock.ui import run_gui
from pathlib import Path
import sys

if __name__ == "__main__":
    vault_path = Path.home() / ".3lock" / "vault.3lock"
    timeout = 5
    
    # Parse simple args
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("--vault", "-v") and i + 1 < len(args):
            vault_path = Path(args[i + 1])
            i += 2
        elif args[i] in ("--timeout", "-t") and i + 1 < len(args):
            timeout = int(args[i + 1])
            i += 2
        else:
            i += 1
    
    sys.exit(run_gui(vault_path, timeout))