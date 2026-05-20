#!/usr/bin/env python3
"""
Door Lock Example using FIDO2 implicit authentication

Simulates a physical access control system where the door unlocks when
a FIDO2 key is detected (implicit level — UP/UV flags not enforced).

Usage:
  python door_lock.py register <username>    # Register a key for this user
  python door_lock.py unlock <username>      # Unlock door for this user
  python door_lock.py list                   # List registered users
"""

import argparse
import sys
from pathlib import Path

# Try the installed package first; fall back to the local source tree.
try:
    import fido2_demo.cli as _cli
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
    import fido2_demo.cli as _cli

from fido2_demo.cli import (
    get_device,
    load_credentials,
    register_credential,
    authenticate,
)
from fido2.client import Fido2Client, DefaultClientDataCollector
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

DOOR_LOCK_RP_ID = "door-lock.example.com"
DOOR_LOCK_ORIGIN = f"https://{DOOR_LOCK_RP_ID}"
DOOR_LOCK_CREDENTIALS_FILE = Path(__file__).parent / "door_credentials.json"

# Point the fido2_demo module at our door-lock RP and credentials store.
_cli.RP_ID = DOOR_LOCK_RP_ID
_cli.CREDENTIALS_FILE = DOOR_LOCK_CREDENTIALS_FILE


def _build_client_server(device):
    rp = PublicKeyCredentialRpEntity(id=DOOR_LOCK_RP_ID, name="Door Lock")
    server = Fido2Server(rp)
    client = Fido2Client(
        device,
        DefaultClientDataCollector(DOOR_LOCK_ORIGIN),
        user_interaction=_cli.CliInteraction(),
    )
    return client, server


def register_user(username):
    """Register a FIDO2 key for door access."""
    print(f"\nRegistering {username} for door access...")
    device = get_device()
    if not device:
        return False

    client, server = _build_client_server(device)
    register_credential(
        client, server, device,
        username=username,
        display_name=username,
        key_name="Door Key",
        discoverable=False,
        min_level="implicit",
    )
    return True


def unlock_door(username):
    """Authenticate with a registered key and unlock the door."""
    print(f"\nAttempting to unlock door for {username}...")
    device = get_device()
    if not device:
        return False

    client, server = _build_client_server(device)
    print("\nBring your security key near the reader...")
    authenticate(client, server, username=username, min_level="implicit")
    return True


def list_users():
    """List all registered door-access users."""
    credentials = load_credentials()
    if not credentials:
        print("\nNo users registered for door access.")
        return

    print("\nRegistered door access users:")
    print("-" * 30)
    for username, user_data in credentials.items():
        key_count = len(user_data["credentials"])
        print(f"  {username} ({key_count} key{'s' if key_count != 1 else ''})")


def main():
    parser = argparse.ArgumentParser(
        description="Door Lock Example using FIDO2 implicit authentication",
        prog="door_lock",
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    reg_parser = subparsers.add_parser("register", help="Register a user for door access")
    reg_parser.add_argument("username", help="Username to register")

    unlock_parser = subparsers.add_parser("unlock", help="Unlock door for a user")
    unlock_parser.add_argument("username", help="Username to authenticate")

    subparsers.add_parser("list", help="List registered users")

    args = parser.parse_args()

    if args.command == "register":
        register_user(args.username)
    elif args.command == "unlock":
        unlock_door(args.username)
    elif args.command == "list":
        list_users()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
