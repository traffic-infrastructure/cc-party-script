#!/usr/bin/env python3
"""
Party CLI - Canton Party management command-line tool
"""
import asyncio
import argparse
import sys
import os
import json

# Add project root directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.canton_service import create_canton_service_with_debug
from app.config import settings

# Global variable to store canton_service instance
canton_service = None


async def cmd_create(name: str = None, output: str = None):
    """Create a new Party"""
    try:
        result = await canton_service.create_party(display_name=name)

        print("=" * 70)
        print("✓ Party Created Successfully!")
        print("=" * 70)
        print(f"Party ID:               {result['partyId']}")
        print(f"Party Hint:             {result['partyHint']}")
        print(f"Display Name:           {result.get('displayName', 'N/A')}")
        print(f"Public Key Fingerprint: {result['publicKeyFingerprint']}")
        print(f"Synchronizer:           {result['synchronizer']}")
        print(f"User ID:                {result['userId']}")
        print("=" * 70)
        print(f"\n🔐 Private Key Seed (Base64):\n{result['privateKeySeedBase64']}")
        print(f"\n📄 Public Key DER (Base64):\n{result['publicKeyDerBase64']}")
        print(f"\n📄 Public Key Raw (Base64):\n{result['publicKeyRawBase64']}")
        print("\n" + "=" * 70)
        print("⚠️  IMPORTANT: Please save your private key securely!")
        print("=" * 70)
        print("\nTo activate this party, add the following to your .env file:")
        print(f"CANTON_PARTY_ID={result['partyId']}")
        print("\nThen restart any running processes or shells that cached environment variables.")

        # Save credentials to file
        parties_dir = "./parties"
        os.makedirs(parties_dir, exist_ok=True)

        filename = output or f"{parties_dir}/{result['partyId']}.json"

        with open(filename, "w") as f:
            json.dump(result, f, indent=2)

        print(f"\n✓ Credentials saved to: {filename}")

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


async def cmd_list():
    """List all Parties"""
    try:
        parties = await canton_service.list_parties()

        print("=== Parties ===")
        for party in parties:
            print(f"Party ID: {party['partyId']}")
            print(f"  Display Name: {party.get('displayName', 'N/A')}")
            print()

    except NotImplementedError as e:
        print(f"Error: {e}")
        print("List parties API is not yet implemented for the Ledger API")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def cmd_load(filename: str):
    """Load Party credentials from a file"""
    try:
        with open(filename, "r") as f:
            credentials = json.load(f)

        print("=== Party Credentials Loaded ===")
        print(f"Party ID: {credentials.get('partyId')}")
        print(f"Display Name: {credentials.get('displayName', 'N/A')}")
        print()
        print("To use this party, update your .env file:")
        print(f"CANTON_PARTY_ID={credentials.get('partyId')}")
        print("# And configure the private key securely")

    except FileNotFoundError:
        print(f"Error: File not found: {filename}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON file: {filename}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def main(argv=None):
    """Entry point. Supports passing a custom argument list for debugging or reuse.

    Examples:
        main(["create", "-n", "DebugParty"])  # Direct invocation from code

    If argv is not provided, the default behavior uses sys.argv.
    """
    global canton_service

    parser = argparse.ArgumentParser(
        description="Party CLI - Canton Party management command-line tool"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode to log all HTTP requests and responses",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # create command
    create_parser = subparsers.add_parser("create", help="Create a new Party")
    create_parser.add_argument("-n", "--name", help="Party display name")
    create_parser.add_argument("-o", "--output", help="Output file path")

    # list command
    subparsers.add_parser("list", help="List all Parties")

    # info command
    info_parser = subparsers.add_parser("info", help="View Party details")
    info_parser.add_argument(
        "party_id",
        nargs="?",
        help="Party ID (optional, defaults to the one in configuration)",
    )

    # load command
    load_parser = subparsers.add_parser("load", help="Load Party credentials from file")
    load_parser.add_argument("filename", help="Path to credentials file")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Create canton_service instance based on debug flag
    canton_service = create_canton_service_with_debug(debug_mode=args.debug)

    if args.debug:
        print("\n🔍 Debug mode enabled — all HTTP requests and responses will be logged\n")

    # Execute command
    if args.command == "create":
        asyncio.run(cmd_create(args.name, args.output))
    elif args.command == "list":
        asyncio.run(cmd_list())
    elif args.command == "load":
        cmd_load(args.filename)


if __name__ == "__main__":
    # Normal mode: read arguments from command line
    main()

    # Debug mode: directly create a party with debug enabled
    # Uncomment the line below to test party creation
    # main(["--debug", "create", "-n", "notojbk", "--save"])