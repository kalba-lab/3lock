"""
3Lock entry point.
"""

import argparse
import sys
from pathlib import Path

from .ui import run_gui


def main():
    parser = argparse.ArgumentParser(
        prog="3lock",
        description="Minimalist local password manager"
    )
    parser.add_argument(
        "--vault", "-v",
        type=Path,
        default=Path.home() / ".3lock" / "vault.3lock",
        help="Path to vault file"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=5,
        help="Session timeout in minutes (default: 5)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0"
    )
    
    args = parser.parse_args()
    
    return run_gui(args.vault, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
