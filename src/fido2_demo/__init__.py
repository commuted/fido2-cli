"""
FIDO2 CLI - Shell-based FIDO2/WebAuthn utility for testing and learning.
"""

__version__ = "0.1.1"

from .cli import (
    main,
    get_device,
    load_credentials,
    save_credentials,
    check_resident_key_support,
    DEFAULT_RP_ID,
    DEFAULT_CREDENTIALS_FILE,
    PIN_MAX_ATTEMPTS,
)

__all__ = [
    "main",
    "get_device",
    "load_credentials",
    "save_credentials",
    "check_resident_key_support",
    "DEFAULT_RP_ID",
    "DEFAULT_CREDENTIALS_FILE",
    "PIN_MAX_ATTEMPTS",
]
