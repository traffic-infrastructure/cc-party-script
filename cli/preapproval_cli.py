#!/usr/bin/env python3
"""
Pre-Approval CLI - Canton TransferPreapproval management command-line tool

Core logic:
actAs and receiver are the same party (self pre-approval, allowing the provider to transfer to yourself)

Usage:
  # Create a pre-approval (only party hint required)
  python -m cli.preapproval_cli create my-party

  # With debug mode enabled
  python -m cli.preapproval_cli create my-party --debug

  # Prepare transaction only (do not execute)
  python -m cli.preapproval_cli prepare my-party

  # Specify a custom provider
  python -m cli.preapproval_cli create my-party -p "CustomProvider::1220xyz..."
"""
import asyncio
import argparse
import sys
import os
import json
import uuid
import glob

# Add project root directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.canton_service import create_canton_service_with_debug
from app.config import settings

# Global variable to store canton_service instance
canton_service = None


def list_available_parties():
    """List all locally available parties"""
    parties_dir = "./parties"
    if not os.path.exists(parties_dir):
        print(f"   No parties directory found: {parties_dir}")
        return

    pattern = os.path.join(parties_dir, "*.json")
    files = glob.glob(pattern)

    if not files:
        print(f"   No party files found in {parties_dir}")
        return

    for filepath in files:
        try:
            party_data = canton_service.load_party_from_file(filepath)
            hint = party_data.get("partyHint", "N/A")
            party_id = party_data.get("partyId", "N/A")
            print(f"   - {hint} ({os.path.basename(filepath)})")
            print(f"     Party ID: {party_id[:50]}...")
        except Exception as e:
            print(f"   - {os.path.basename(filepath)} (invalid: {e})")


async def cmd_create(
    party_hint: str,
    provider: str = None,
    synchronizer: str = None
):
    """Create and execute a TransferPreapproval (full workflow)

    Logic:
    actAs and receiver are the same party (self pre-approval)
    """
    try:
        # Default checks
        if not provider:
            print("❌ Error: --provider is required")
            sys.exit(1)

        if not synchronizer:
            synchronizer = settings.CANTON_SYNCHRONIZER_ID

        # Locate local party file by party_hint
        print(f"🔍 Looking for party with hint: {party_hint}")
        party_file = canton_service.find_party_file_by_hint(party_hint)
        if not party_file:
            print(f"❌ Error: No party found with hint '{party_hint}'")
            print(f"\n📋 Available parties in ./parties/:")
            list_available_parties()
            sys.exit(1)
        print(f"✓ Found party file: {party_file}")

        # Load party credentials
        party_data = canton_service.load_party_from_file(party_file)

        party_id = party_data["partyId"]
        private_key_seed = party_data["privateKeySeedBase64"]

        # Receiver is the same party (self)
        receiver = party_id

        print("\n" + "=" * 70)
        print("Creating TransferPreapproval")
        print("=" * 70)
        print(f"Receiver:     {receiver}")
        print(f"Provider:     {provider}")
        print(f"Act As:       {party_id}")
        print(f"Synchronizer: {synchronizer}")
        print("=" * 70 + "\n")

        # Generate unique IDs
        command_id = f"cmd-preapproval-{uuid.uuid4().hex[:16]}"
        submission_id = f"subm-preapproval-{uuid.uuid4().hex[:16]}"

        # Step 1: Prepare
        print("Step 1/3: Preparing transaction...")
        prepare_result = await canton_service.prepare_transfer_preapproval(
            command_id=command_id,
            act_as_party_id=party_id,
            synchronizer_id=synchronizer,
            provider_party_id=provider,
            receiver_party_id=receiver,
        )

        prepared_transaction = prepare_result["preparedTransaction"]
        prepared_transaction_hash = prepare_result["preparedTransactionHash"]

        print(f"✓ Transaction prepared")
        print(f"  Hash: {prepared_transaction_hash[:40]}...")

        # Step 2: Get user ID
        print("\nStep 2/3: Getting user ID from JWT token...")
        user_id = await canton_service._get_user_id_from_token()
        print(f"✓ User ID: {user_id}")

        # Step 3: Execute
        print("\nStep 3/3: Signing and executing transaction...")
        execute_result = await canton_service.execute_signed_transaction_and_wait(
            prepared_transaction=prepared_transaction,
            prepared_transaction_hash=prepared_transaction_hash,
            party_id=party_id,
            private_key_seed_base64=private_key_seed,
            submission_id=submission_id,
            user_id=user_id,
        )

        # Extract execution results
        transaction = execute_result.get("transaction", {})
        events = transaction.get("events", [])

        print("\n" + "=" * 70)
        print("✓ TransferPreapproval Created Successfully!")
        print("=" * 70)

        # Find created contract
        contract_id = None
        for event in events:
            if "CreatedEvent" in event:
                created = event["CreatedEvent"]
                contract_id = created.get("contractId")
                template_id = created.get("templateId")
                print(f"Contract ID:  {contract_id}")
                print(f"Template ID:  {template_id}")

                create_arg = created.get("createArgument", {})
                print(f"Receiver:     {create_arg.get('receiver')}")
                print(f"Provider:     {create_arg.get('provider')}")

        print(f"Update ID:    {transaction.get('updateId')}")
        print(f"Command ID:   {transaction.get('commandId')}")
        print(f"Offset:       {transaction.get('offset')}")
        print("=" * 70)

        # Save result
        result = {
            "contractId": contract_id,
            "updateId": transaction.get("updateId"),
            "commandId": transaction.get("commandId"),
            "offset": transaction.get("offset"),
            "receiver": receiver,
            "provider": provider,
            "actAs": party_id,
            "createdAt": transaction.get("effectiveAt"),
        }

        output_file = f"./preapprovals/preapproval-{contract_id[:16] if contract_id else 'unknown'}.json"
        os.makedirs("./preapprovals", exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2)

        print(f"\n✓ Pre-approval details saved to: {output_file}")

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


async def cmd_prepare_only(
    party_hint: str,
    provider: str = None,
    synchronizer: str = None,
    output: str = None
):
    """Prepare a transaction only (no execution)

    Logic:
    actAs and receiver are the same party (self pre-approval)
    """
    try:
        if not provider:
            print("❌ Error: --provider is required")
            sys.exit(1)

        if not synchronizer:
            synchronizer = settings.CANTON_SYNCHRONIZER_ID

        # Locate local party file by party_hint
        print(f"🔍 Looking for party with hint: {party_hint}")
        party_file = canton_service.find_party_file_by_hint(party_hint)
        if not party_file:
            print(f"❌ Error: No party found with hint '{party_hint}'")
            print(f"\n📋 Available parties:")
            list_available_parties()
            sys.exit(1)
        print(f"✓ Found party file: {party_file}")

        # Load party data
        party_data = canton_service.load_party_from_file(party_file)
        party_id = party_data["partyId"]

        # Receiver is the same party (self)
        receiver = party_id

        command_id = f"cmd-preapproval-{uuid.uuid4().hex[:16]}"

        print("Preparing TransferPreapproval transaction...")
        prepare_result = await canton_service.prepare_transfer_preapproval(
            command_id=command_id,
            act_as_party_id=party_id,
            synchronizer_id=synchronizer,
            provider_party_id=provider,
            receiver_party_id=receiver,
        )

        print("\n" + "=" * 70)
        print("✓ Transaction Prepared")
        print("=" * 70)
        print(f"Prepared Transaction Hash: {prepare_result['preparedTransactionHash']}")
        print(f"Command ID: {command_id}")

        # Save prepared transaction
        if not output:
            output = f"./preapprovals/prepared-{command_id}.json"

        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output, "w") as f:
            json.dump(prepare_result, f, indent=2)

        print(f"\n✓ Prepared transaction saved to: {output}")
        print("\nYou can execute it later with:")
        print("  python -m cli.preapproval_cli execute --prepared-file <file>")

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main(argv=None):
    """Entry point"""
    global canton_service

    parser = argparse.ArgumentParser(
        description="Pre-Approval CLI - Canton TransferPreapproval management tool"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # create command
    create_parser = subparsers.add_parser(
        "create",
        help="Create a TransferPreapproval (self pre-approval)"
    )
    create_parser.add_argument(
        "party_hint",
        help="Party hint (loaded from local party files)"
    )
    create_parser.add_argument(
        "-p", "--provider",
        required=True,
        help="Provider Party ID (required)"
    )
    create_parser.add_argument(
        "-s", "--synchronizer",
        help="Synchronizer ID (defaults to global-domain)"
    )
    create_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode to log all HTTP requests and responses"
    )

    # prepare-only command
    prepare_parser = subparsers.add_parser(
        "prepare",
        help="Prepare transaction only (do not execute)"
    )
    prepare_parser.add_argument(
        "party_hint",
        help="Party hint (loaded from local party files)"
    )
    prepare_parser.add_argument(
        "-p", "--provider",
        required=True,
        help="Provider Party ID (required)"
    )
    prepare_parser.add_argument(
        "-s", "--synchronizer",
        help="Synchronizer ID (defaults to global-domain)"
    )
    prepare_parser.add_argument(
        "-o", "--output",
        help="Output file path"
    )
    prepare_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode to log all HTTP requests and responses"
    )

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Create canton_service instance based on debug flag
    debug_mode = getattr(args, "debug", False)
    canton_service = create_canton_service_with_debug(debug_mode=debug_mode)

    if debug_mode:
        print("\n🔍 Debug mode enabled — all HTTP requests and responses will be logged\n")

    # Execute command
    if args.command == "create":
        asyncio.run(cmd_create(
            party_hint=args.party_hint,
            provider=args.provider,
            synchronizer=args.synchronizer,
        ))
    elif args.command == "prepare":
        asyncio.run(cmd_prepare_only(
            party_hint=args.party_hint,
            provider=args.provider,
            synchronizer=args.synchronizer,
            output=args.output,
        ))


if __name__ == "__main__":
    main()