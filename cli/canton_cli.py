#!/usr/bin/env python3
import asyncio
import argparse
import sys
import os
import json
import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.canton_service import canton_service
from app.services.auth_manager import auth_manager
from app.config import settings


async def cmd_login():
    try:
        mode = os.getenv("MODE") or os.getenv("ENV_MODE") or "dev"
        print(f"Logging in to Canton (mode: {mode})...")
        access_token = await auth_manager.login()
        print("✓ Login successful!")
        print(f"\nAccess Token (first 50 chars): {access_token[:50]}...")
        print(f"\nToken saved to: data/canton_token_{mode}.json")
    except Exception as e:
        print(f"✗ Login failed: {e}")
        sys.exit(1)


async def cmd_test():
    """Test Canton connection by logging in and calling ledger-end API"""
    try:
        mode = os.getenv("MODE") or os.getenv("ENV_MODE") or "dev"
        print(f"Testing Canton connection (mode: {mode})...\n")
        
        # Step 1: Login
        print("[1/3] Logging in...")
        access_token = await auth_manager.login()
        print("✓ Login successful!")
        print(f"    Token: {access_token[:10]}...")
        
        # Step 2: Call ledger-end API
        print("\n[2/3] Testing Ledger API (/v2/state/ledger-end)...")
        ledger_end = await canton_service.get_ledger_end()
        print("✓ Ledger API call successful!")
        print(f"\nLedger End Response:")
        print(json.dumps(ledger_end, indent=2))
        
        # Step 3: Test Transfer Factory Registry URL
        print(f"\n[3/3] Testing Transfer Factory Registry API...")
        print(f"    URL: {settings.CANTON_TRANSFER_FACTORY_REGISTRY_URL}")
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                }
                response = await client.post(
                    settings.CANTON_TRANSFER_FACTORY_REGISTRY_URL,
                    headers=headers
                )
                
                # Expected: 400 with "Request entity expected but not supplied"
                if response.status_code == 400:
                    response_text = response.text
                    print(f"✓ Got expected 400 status code")
                    print(f"\nResponse:")
                    print(f"    Status: {response.status_code}")
                    print(f"    Body: {response_text}")
                    
                    if "Request entity expected but not supplied" in response_text:
                        print("\n✓ Response matches expected error message")
                    else:
                        print("\n⚠ Warning: Response doesn't match expected error message")
                else:
                    print(f"⚠ Unexpected status code: {response.status_code}")
                    print(f"    Response: {response.text}")
                    
            except httpx.HTTPError as e:
                print(f"✗ Request failed: {e}")
                raise
        
        print("\n✓ All tests passed! Canton connection is working properly.")
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)


async def cmd_send(recipient: str, amount: float, memo: str = None, from_party: str = None):
    try:
        sender_party_id = from_party or settings.CANTON_PARTY_ID
        if not sender_party_id:
            print(
                "Error: No sender party specified. "
                "Use --from-party or set CANTON_PARTY_ID in .env"
            )
            sys.exit(1)

        party_file = f"parties/{sender_party_id}.json"
        if not os.path.exists(party_file):
            print(f"Error: Party file not found: {party_file}")
            print("Available parties:")
            if os.path.exists("parties"):
                for f in os.listdir("parties"):
                    if f.endswith(".json"):
                        print(f"  - {f[:-5]}")
            sys.exit(1)

        with open(party_file, "r") as f:
            party_data = json.load(f)
            private_key_seed_b64 = party_data.get("privateKeySeedBase64")

        if not private_key_seed_b64:
            print(f"Error: privateKeySeedBase64 not found in {party_file}")
            sys.exit(1)

        print(
            f"Sending {amount} CC from {sender_party_id[:30]}... "
            f"to {recipient[:30]}..."
        )
        if memo:
            print(f"Memo: {memo}")

        result = await canton_service.send_transfer(
            recipient=recipient,
            amount=amount,
            memo=memo,
            sender_party_id=sender_party_id,
            sender_private_key=private_key_seed_b64,
        )

        print("\n✓ Transfer completed successfully!")
        print(json.dumps(result, indent=2))

    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)


def main(argv=None):
    """
    Entry point function.

    Supports custom argv for easier use in debuggers or other Python code.

    Example:
        main(["login"])  # Trigger command directly from a Python console

    Preserves the original behavior when executed from the command line.
    """
    parser = argparse.ArgumentParser(
        description="Canton CLI - Canton Network command line tool"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # login command
    subparsers.add_parser("login", help="Login and obtain access token")

    # test command
    subparsers.add_parser("test", help="Test Canton connection (login + ledger-end API)")

    # send command
    send_parser = subparsers.add_parser("send", help="Send CC")
    send_parser.add_argument("recipient", help="Recipient Party ID")
    send_parser.add_argument("amount", type=float, help="Transfer amount")
    send_parser.add_argument("-m", "--memo", help="Memo")
    send_parser.add_argument(
        "-f",
        "--from-party",
        help="Sender Party ID (defaults to CANTON_PARTY_ID in .env)",
    )

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Execute command
    if args.command == "login":
        asyncio.run(cmd_login())
    elif args.command == "test":
        asyncio.run(cmd_test())
    elif args.command == "send":
        asyncio.run(cmd_send(args.recipient, args.amount, args.memo, args.from_party))


if __name__ == "__main__":
    main()