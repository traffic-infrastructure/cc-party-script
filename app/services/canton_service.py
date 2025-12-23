"""
Canton Service - Canton Network Service Layer
Part 1: Basic HTTP Request Encapsulation (Single curl integration)
"""
from typing import List, Dict, Optional, Any
from app.config import settings
from app.services.auth_manager import auth_manager
from app.services.key_generator import key_generator
import httpx
import logging
import base64
import json
import jwt
from nacl import signing
from nacl import exceptions as nacl_exceptions
from decimal import Decimal
import math
import asyncio
logger = logging.getLogger(__name__)


class CantonService:
    """Canton Network Service Layer - Basic HTTP Requests"""
    
    def __init__(self, debug_mode: bool = False):
        self.dry_run = getattr(settings, "CANTON_DRY_RUN", False)
        # Load different API endpoints from config
        self.ledger_api_url = settings.CANTON_LEDGER_API_URL
        # Debug mode: log all HTTP requests and responses
        self.debug_mode = debug_mode
        
    async def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication request headers"""
        access_token = await auth_manager.get_access_token()
        return {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
    
    def _log_http_request(self, method: str, url: str, headers: Dict[str, str], payload: Any = None):
        """Log HTTP request details (only in debug mode)"""
        if not self.debug_mode:
            return
        
        print("\n" + "=" * 80)
        print(f"🔵 HTTP REQUEST: {method} {url}")
        print("=" * 80)
        print("Headers:")
        for key, value in headers.items():
            # Hide sensitive token information
            if key.lower() == "authorization" and value.startswith("Bearer "):
                token = value[7:]
                print(f"  {key}: Bearer {token[:20]}...{token[-10:] if len(token) > 30 else ''}")
            else:
                print(f"  {key}: {value}")
        
        if payload:
            print("\nPayload:")
            if isinstance(payload, dict):
                print(json.dumps(payload, indent=2, ensure_ascii=False))
            else:
                print(payload)
        print("=" * 80)
    
    def _log_http_response(self, method: str, url: str, status_code: int, response_data: Any = None, error: str = None):
        """Log HTTP response details (only in debug mode)"""
        if not self.debug_mode:
            return
        
        print("\n" + "=" * 80)
        if error:
            print(f"🔴 HTTP RESPONSE ERROR: {method} {url}")
        else:
            print(f"🟢 HTTP RESPONSE: {method} {url}")
        print("=" * 80)
        print(f"Status Code: {status_code}")
        
        if error:
            print(f"\nError: {error}")
            # When status >= 400, ensure we print raw response body
            if response_data and isinstance(response_data, (str, bytes)):
                print("\nResponse Body:")
                try:
                    # Attempt pretty-print if JSON string
                    if isinstance(response_data, bytes):
                        response_text = response_data.decode("utf-8", errors="replace")
                    else:
                        response_text = response_data
                    parsed = json.loads(response_text)
                    print(json.dumps(parsed, indent=2, ensure_ascii=False))
                except Exception:
                    print(response_data)
        elif response_data:
            print("\nResponse Data:")
            if isinstance(response_data, dict) or isinstance(response_data, list):
                print(json.dumps(response_data, indent=2, ensure_ascii=False))
            else:
                print(response_data)
        print("=" * 80 + "\n")

    # ========== PARTY ONBOARDING ==========
    async def get_connected_synchronizers(self) -> Dict[str, Any]:
        """GET /state/connected-synchronizers"""
        url = f"{self.ledger_api_url}/state/connected-synchronizers"
        try:
            headers = await self._get_auth_headers()
            self._log_http_request("GET", url, headers)
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.get(url, headers=headers)
                r.raise_for_status()
                data = r.json()
                
                self._log_http_response("GET", url, r.status_code, data)
                return data
        except httpx.HTTPError as e:
            self._log_http_response("GET", url, getattr(e.response, 'status_code', 0) if hasattr(e, 'response') else 0, error=str(e))
            logger.error(f"Failed to get connected synchronizers: {e}")
            raise Exception(f"Failed to get connected synchronizers: {e}")

    async def generate_topology(
        self,
        synchronizer: str,
        party_hint: str,
        public_key_der_base64: str,
    ) -> Dict[str, Any]:
        """POST /parties/external/generate-topology"""
        url = f"{self.ledger_api_url}/parties/external/generate-topology"
        payload = {
            "synchronizer": synchronizer,
            "partyHint": party_hint,
            "publicKey": {
                "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
                "keyData": public_key_der_base64,
                "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519",
            },
            "otherConfirmingParticipantUids": [],
        }
        try:
            headers = await self._get_auth_headers()
            self._log_http_request("POST", url, headers, payload)
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(url, json=payload, headers=headers)
                r.raise_for_status()
                data = r.json()
                
                self._log_http_response("POST", url, r.status_code, data)
                return data
        except httpx.HTTPError as e:
            self._log_http_response("POST", url, getattr(e.response, 'status_code', 0) if hasattr(e, 'response') else 0, error=str(e))
            logger.error(f"Failed to generate topology: {e}")
            raise Exception(f"Failed to generate topology: {e}")

    @staticmethod
    def sign_multi_hash_ed25519(private_key_seed_base64: str, multi_hash_base64: str) -> str:
        """Sign multi-hash using Ed25519 via PyNaCl (private key seed in base64)."""
        try:
            seed = base64.b64decode(private_key_seed_base64)
            signer = signing.SigningKey(seed)
            msg = base64.b64decode(multi_hash_base64)
            signature = signer.sign(msg).signature
            return base64.b64encode(signature).decode()
        except (nacl_exceptions.CryptoError, ValueError) as e:
            raise Exception(f"Failed to sign multi-hash: {e}")

    async def allocate_external_party(
        self,
        synchronizer: str,
        onboarding_transactions: List[str],
        signature_base64: str,
        signed_by_fingerprint: str,
    ) -> Dict[str, Any]:
        """POST /parties/external/allocate"""
        url = f"{self.ledger_api_url}/parties/external/allocate"
        payload = {
            "synchronizer": synchronizer,
            "onboardingTransactions": [{"transaction": t} for t in onboarding_transactions],
            "multiHashSignatures": [
                {
                    "format": "SIGNATURE_FORMAT_CONCAT",
                    "signature": signature_base64,
                    "signedBy": signed_by_fingerprint,
                    "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519",
                }
            ],
        }
        try:
            headers = await self._get_auth_headers()
            self._log_http_request("POST", url, headers, payload)
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(url, json=payload, headers=headers)
                r.raise_for_status()
                data = r.json()
                
                self._log_http_response("POST", url, r.status_code, data)
                return data
        except httpx.HTTPError as e:
            self._log_http_response("POST", url, getattr(e.response, 'status_code', 0) if hasattr(e, 'response') else 0, error=str(e))
            logger.error(f"Failed to allocate external party: {e}")
            raise Exception(f"Failed to allocate external party: {e}")

    async def grant_user_can_act_as(self, user_id: str, party_id: str) -> Dict[str, Any]:
        """POST /users/{userId}/rights to grant CanActAs for party"""
        url = f"{self.ledger_api_url}/users/{user_id}/rights"
        payload = {
            "userId": user_id,
            "identityProviderId": "",
            "rights": [
                {
                    "kind": {
                        "CanActAs": {
                            "value": {"party": party_id}
                        }
                    }
                }
            ],
        }
        try:
            headers = await self._get_auth_headers()
            self._log_http_request("POST", url, headers, payload)
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(url, json=payload, headers=headers)
                r.raise_for_status()
                data = r.json()
                
                self._log_http_response("POST", url, r.status_code, data)
                return data
        except httpx.HTTPError as e:
            self._log_http_response("POST", url, getattr(e.response, 'status_code', 0) if hasattr(e, 'response') else 0, error=str(e))
            logger.error(f"Failed to grant user rights: {e}")
            raise Exception(f"Failed to grant user rights: {e}")

    async def get_transfer_factory_registry(
        self,
        from_party_id: str,
        receiver_party_id: str,
        amount: str,
        input_holding_cids: List[str],
        requested_at: str,
        execute_before: str,
        memo: str = ""
    ) -> Dict[str, Any]:
        """
        Get Transfer Factory Registry - contains complete transfer parameters
        
        POST to transfer-factory endpoint to get factory ID and disclosed contracts
        
        Args:
            from_party_id: Sender party ID
            receiver_party_id: Receiver party ID
            amount: Transfer amount string (e.g., "1000.0")
            input_holding_cids: Selected holding CIDs
            requested_at: ISO timestamp (e.g., "2025-12-03T12:45:00Z")
            execute_before: Expiration timestamp (e.g., "2025-12-04T12:45:00Z")
            memo: Transfer memo
            
        Returns:
            {
                "factoryId": "009f00e5bf...",
                "transferKind": "direct",
                "choiceContext": {
                    "choiceContextData": {...},
                    "disclosedContracts": [...]
                }
            }
        """
        url = settings.CANTON_TRANSFER_FACTORY_REGISTRY_URL
        
        # Build meta values (if memo exists)
        meta_values = {}
        if memo:
            meta_values["splice.lfdecentralizedtrust.org/reason"] = memo
        
        # Correct payload format - contains complete transfer parameters
        payload = {
            "choiceArguments": {
                "expectedAdmin": settings.DSO_ADMIN_ID,
                "transfer": {
                    "sender": from_party_id,
                    "receiver": receiver_party_id,
                    "amount": amount,
                    "instrumentId": {
                        "admin": settings.DSO_ADMIN_ID,
                        "id": "Amulet"
                    },
                    "requestedAt": requested_at,
                    "executeBefore": execute_before,
                    "inputHoldingCids": input_holding_cids,
                    "meta": {"values": meta_values}
                },
                "extraArgs": {
                    "context": {"values": {}},
                    "meta": {"values": {}}
                }
            }
        }
        
        try:
            headers = await self._get_auth_headers()
            self._log_http_request("POST", url, headers, payload)
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(url, json=payload, headers=headers)
                
                # Log response before raising error
                if r.status_code != 200:
                    try:
                        error_data = r.json()
                    except:
                        error_data = r.text
                    self._log_http_response("POST", url, r.status_code, error_data)
                    logger.error(f"❌ Transfer factory registry returned {r.status_code}: {error_data}")
                
                r.raise_for_status()
                data = r.json()
                
                self._log_http_response("POST", url, r.status_code, data)
                return data
                
        except httpx.HTTPError as e:
            # Enhanced error logging with response body
            error_detail = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_body = e.response.json()
                    error_detail = f"{e}\nResponse body: {json.dumps(error_body, indent=2)}"
                except:
                    error_body = e.response.text
                    error_detail = f"{e}\nResponse body: {error_body}"
                self._log_http_response("POST", url, e.response.status_code, error_body)
            else:
                self._log_http_response("POST", url, 0, error=str(e))
            
            logger.error(f"Failed to get transfer factory registry: {error_detail}")
            raise Exception(f"Failed to get transfer factory registry: {error_detail}")

    def select_holding_cids_utxo(
        self,
        contracts: List[Dict[str, Any]],
        required_amount: float
    ) -> tuple[List[str], float]:
        """
        UTXO logic: Select sufficient holding CIDs
        
        Select CIDs from contracts such that sum(initialAmount) >= required_amount
        
        Args:
            contracts: Contract list returned from get_active_contracts
            required_amount: Required transfer amount
            
        Returns:
            (selected_cids, total_selected_amount)
        """
        selected_cids = []
        total_selected = 0.0
        
        for contract in contracts:
            try:
                # Parse contract structure
                contract_entry = contract.get("contractEntry", {})
                js_contract = contract_entry.get("JsActiveContract", {})
                created_event = js_contract.get("createdEvent", {})
                
                # Get contractId
                contract_id = created_event.get("contractId")
                
                # Get amount.initialAmount
                interfaceViews = created_event.get("interfaceViews", {})
                if interfaceViews:
                    view_value = interfaceViews[0].get("viewValue", {})
                    amount_obj = view_value.get("amount", "0.0")
                else:
                    amount_obj = "0.0"
                
                contract_amount = float(amount_obj)
                
                if contract_id and contract_amount > 0:
                    selected_cids.append(contract_id)
                    total_selected += contract_amount
                    
                    logger.info(f"Selected CID: {contract_id[:32]}... amount: {contract_amount}, cumulative: {total_selected}")
                    
                    # UTXO logic: stop once total >= required amount
                    if total_selected >= required_amount:
                        break
                        
            except Exception as e:
                logger.warning(f"Failed to parse contract: {e}")
                continue
        
        return selected_cids, total_selected

    # ========== PRE-APPROVAL FLOW ==========
    async def prepare_transfer_preapproval(
        self,
        command_id: str,
        act_as_party_id: str,
        synchronizer_id: str,
        provider_party_id: str,
        receiver_party_id: str,
        expected_dso: str = settings.DSO_ADMIN_ID,
    ) -> Dict[str, Any]:
        """POST to prepare TransferPreapprovalProposal (endpoint provided by ledger API contract submission)"""
        url = f"{self.ledger_api_url}/interactive-submission/prepare"
        # Extract user id from JWT token
        user_id = await self._get_user_id_from_token()
        payload = {
            "commandId": command_id,
            "actAs": [act_as_party_id],
            "userId": user_id,
            "readAs": [act_as_party_id],
            "verboseHashing": True,
            "synchronizerId": synchronizer_id,
            "packageIdSelectionPreference": [],
            "disclosedContracts": [],
            "commands": [
                {
                    "CreateCommand": {
                        "templateId": "#splice-wallet:Splice.Wallet.TransferPreapproval:TransferPreapprovalProposal",
                        "createArguments": {
                            "receiver": receiver_party_id,
                            "provider": provider_party_id,
                            "expectedDso": expected_dso,
                        },
                    }
                }
            ],
        }
        try:
            headers = await self._get_auth_headers()
            self._log_http_request("POST", url, headers, payload)
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(url, json=payload, headers=headers)
                r.raise_for_status()
                data = r.json()
                print("RSP:",data)
                self._log_http_response("POST", url, r.status_code, data)
                return data
        except httpx.HTTPError as e:
            body = None
            status = 0
            if hasattr(e, 'response') and e.response is not None:
                status = e.response.status_code
                try:
                    body = e.response.text
                except Exception:
                    body = None
            self._log_http_response("POST", url, status, response_data=body, error=str(e))
            logger.error(f"Failed to prepare preapproval: {e}")
            raise Exception(f"Failed to prepare preapproval: {e}")
    
    async def execute_signed_transaction_and_wait(
        self,
        prepared_transaction: str,
        prepared_transaction_hash: str,
        party_id: str,
        private_key_seed_base64: str,
        submission_id: str,
        user_id: str,
    ) -> Dict[str, Any]:
        """
        Generic method: Sign and execute any prepared transaction
        
        Applicable to all Canton transactions that require signed execution, including:
        - TransferPreapprovalProposal
        - Token Transfer
        - Other Daml contract operations
        
        Args:
            prepared_transaction: Base64 encoded prepared transaction from prepare step
            prepared_transaction_hash: Hash of prepared transaction to sign
            party_id: Full party ID (e.g., "manual-test::1220...")
            private_key_seed_base64: Private key seed for signing
            submission_id: Unique submission ID
            user_id: User ID from JWT token
            
        Returns:
            Transaction result with events and contract IDs
        """
        url = f"{self.ledger_api_url}/interactive-submission/execute"
        
        # Sign the prepared transaction hash
        hash_bytes = base64.b64decode(prepared_transaction_hash)
        signature = key_generator.sign_data(private_key_seed_base64, hash_bytes)
        
        # Extract fingerprint from party_id (part after ::)
        fingerprint = party_id.split("::")[-1]
        
        payload = {
            "preparedTransaction": prepared_transaction,
            "partySignatures": {
                "signatures": [
                    {
                        "party": party_id,
                        "signatures": [
                            {
                                "format": "SIGNATURE_FORMAT_RAW",
                                "signature": signature,
                                "signedBy": fingerprint,
                                "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519",
                            }
                        ],
                    }
                ]
            },
            "deduplicationPeriod": {"Empty": {}},
            "submissionId": submission_id,
            "userId": user_id,
            "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V2",
        }
        
        try:
            headers = await self._get_auth_headers()
            self._log_http_request("POST", url, headers, payload)
            
            async with httpx.AsyncClient(timeout=60.0) as client:
                r = await client.post(url, json=payload, headers=headers)
                r.raise_for_status()
                data = r.json()
                
                self._log_http_response("POST", url, r.status_code, data)
                return data
        except httpx.HTTPError as e:
            self._log_http_response("POST", url, getattr(e.response, 'status_code', 0) if hasattr(e, 'response') else 0, error=str(e))
            logger.error(f"Failed to execute preapproval: {e}")
            raise Exception(f"Failed to execute preapproval: {e}")
    

    # ========== TRANSFER FLOW ==========
    async def get_ledger_end(self) -> Dict[str, Any]:
        """GET /state/ledger-end -> {"offset": int}"""
        url = f"{self.ledger_api_url}/state/ledger-end"
        try:
            headers = await self._get_auth_headers()
            self._log_http_request("GET", url, headers)
            async with httpx.AsyncClient(timeout=15.0) as client:
                r = await client.get(url, headers=headers)
                r.raise_for_status()
                data = r.json()
                self._log_http_response("GET", url, r.status_code, data)
                return data
        except httpx.HTTPError as e:
            self._log_http_response("GET", url, getattr(e.response, 'status_code', 0) if hasattr(e, 'response') else 0, error=str(e))
            logger.error(f"Failed to get ledger end: {e}")
            raise Exception(f"Failed to get ledger end: {e}")

    async def get_active_contracts(
        self,
        party_id: str,
        active_at_offset: int,
        interface_id: str = "#splice-api-token-holding-v1:Splice.Api.Token.HoldingV1:Holding",
        verbose: bool = True,
        limit: int = 200,
    ) -> Any:
        """POST /state/active-contracts with interface filter for holdings"""
        # Allow caller to specify pagination limit (default 20)
        try:
            lim = int(limit)
        except Exception:
            lim = 20
        if lim <= 0:
            lim = 20
        url = f"{self.ledger_api_url}/state/active-contracts?limit={lim}"
        payload = {
            "verbose": verbose,
            "activeAtOffset": active_at_offset,
            "filter": {
                "filtersByParty": {
                    party_id: {
                        "cumulative": [
                            {
                                "identifierFilter": {
                                    "InterfaceFilter": {
                                        "value": {
                                            "includeInterfaceView": True,
                                            "includeCreatedEventBlob": False,
                                            "interfaceId": interface_id,
                                        }
                                    }
                                }
                            }
                        ]
                    }
                }
            },
        }
        try:
            headers = await self._get_auth_headers()
            self._log_http_request("POST", url, headers, payload)
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(url, json=payload, headers=headers)
                r.raise_for_status()
                data = r.json()
                self._log_http_response("POST", url, r.status_code, data)
                return data
        except httpx.HTTPError as e:
            self._log_http_response("POST", url, getattr(e.response, 'status_code', 0) if hasattr(e, 'response') else 0, error=str(e))
            logger.error(f"Failed to get active contracts: {e}")
            raise Exception(f"Failed to get active contracts: {e}")

    async def get_updates(
        self,
        begin_exclusive: int,
        party_id: str,
        include_transactions: bool = True,
        verbose_events: bool = False,
        transaction_shape: str = "TRANSACTION_SHAPE_ACS_DELTA",
    ) -> Any:
        """
        POST /updates to stream updates since an offset for a given party.

        Args:
            begin_exclusive: Starting offset (exclusive), typically ledger-end captured before submit
            party_id: Filters by this party
            include_transactions: Whether to include transactions
            verbose_events: Event verbosity
            transaction_shape: Transaction shape (default ACS delta)

        Returns: updates list (as returned by ledger)
        """
        url = f"{self.ledger_api_url}/updates"
        if include_transactions:
            update_format = {
                "includeTransactions": {
                    "transactionShape": transaction_shape,
                    "eventFormat": {
                        "verbose": verbose_events,
                        "filtersByParty": {party_id: {}}
                    }
                }
            }
        else:
            update_format = {"empty": {}}

        payload = {
            "beginExclusive": begin_exclusive,
            "updateFormat": update_format,
        }
        try:
            headers = await self._get_auth_headers()
            self._log_http_request("POST", url, headers, payload)
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(url, json=payload, headers=headers)
                r.raise_for_status()
                data = r.json()
                self._log_http_response("POST", url, r.status_code, data)
                return data
        except httpx.HTTPError as e:
            self._log_http_response("POST", url, getattr(e.response, 'status_code', 0) if hasattr(e, 'response') else 0, error=str(e))
            logger.error(f"Failed to get updates: {e}")
            raise Exception(f"Failed to get updates: {e}")

    async def prepare_transfer(
        self,
        command_id: str,
        act_as_party_id: str,
        synchronizer_id: str,
        transfer_factory_cid: str,
        expected_admin: str,
        sender: str,
        receiver: str,
        amount: str,
        instrument_admin: str,
        instrument_id: str,
        requested_at_iso: str,
        execute_before_iso: str,
        input_holding_cids: list,
        extra_context_contracts: Dict[str, str],
        disclosed_contracts: list,
    ) -> Dict[str, Any]:
        """Prepare token transfer transaction via ExerciseCommand on TransferFactory."""
        url = f"{self.ledger_api_url}/interactive-submission/prepare"
        user_id = await self._get_user_id_from_token()
        choice_arg = {
            "expectedAdmin": expected_admin,
            "transfer": {
                "sender": sender,
                "receiver": receiver,
                "amount": amount,
                "instrumentId": {"admin": instrument_admin, "id": instrument_id},
                "requestedAt": requested_at_iso,
                "executeBefore": execute_before_iso,
                "inputHoldingCids": input_holding_cids,
                "meta": {"values": {}},
            },
            "extraArgs": {
                "context": {"values": {k: {"tag": "AV_ContractId", "value": v} for k, v in extra_context_contracts.items()}},
                "meta": {"values": {}},
            },
        }
        payload = {
            "commandId": command_id,
            "actAs": [act_as_party_id],
            "userId": user_id,
            "readAs": [act_as_party_id],
            "synchronizerId": synchronizer_id,
            "verboseHashing": True,
            "packageIdSelectionPreference": [],
            "commands": [
                {
                    "ExerciseCommand": {
                        "templateId": "#splice-api-token-transfer-instruction-v1:Splice.Api.Token.TransferInstructionV1:TransferFactory",
                        "contractId": transfer_factory_cid,
                        "consuming": False,
                        "choice": "TransferFactory_Transfer",
                        "choiceArgument": choice_arg,
                    }
                }
            ],
            "disclosedContracts": disclosed_contracts,
        }
        try:
            headers = await self._get_auth_headers()
            self._log_http_request("POST", url, headers, payload)
            async with httpx.AsyncClient(timeout=45.0) as client:
                r = await client.post(url, json=payload, headers=headers)
                r.raise_for_status()
                data = r.json()
                self._log_http_response("POST", url, r.status_code, data)
                return data
        except httpx.HTTPError as e:
            status = getattr(e.response, 'status_code', 0) if hasattr(e, 'response') else 0
            body = None
            if hasattr(e, 'response') and e.response is not None:
                try:
                    body = e.response.text
                except Exception:
                    body = None
            self._log_http_response("POST", url, status, response_data=body, error=str(e))
            logger.error(f"Failed to prepare transfer: {e}")
            raise Exception(f"Failed to prepare transfer: {e}")

    async def find_input_holding_cids(
        self,
        party_id: str,
        required_amount: str,
        instrument_admin: str,
        instrument_id: str,
        active_at_offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Find input holding CIDs for a given party and instrument to cover required_amount.
        Returns selected CIDs and total available in selection.
        """
        # Determine offset
        if active_at_offset is None:
            end = await self.get_ledger_end()
            active_at_offset = int(end.get("offset", 0))

        # Fetch holdings via interface views
        result = await self.get_active_contracts(
            party_id=party_id,
            active_at_offset=active_at_offset,
            interface_id="#splice-api-token-holding-v1:Splice.Api.Token.HoldingV1:Holding",
            verbose=True,
        )

        # Parse holdings
        holdings = []
        try:
            for entry in result if isinstance(result, list) else []:
                js = entry.get("contractEntry", {}).get("JsActiveContract", {})
                created = js.get("createdEvent", {})
                cid = created.get("contractId")
                for view in created.get("interfaceViews", []):
                    view_val = view.get("viewValue", {})
                    instr = view_val.get("instrumentId", {})
                    if (
                        instr.get("admin") == instrument_admin
                        and instr.get("id") == instrument_id
                    ):
                        amt_str = view_val.get("amount")
                        if amt_str and cid:
                            holdings.append({"cid": cid, "amount": Decimal(amt_str)})
        except Exception as e:
            logger.error(f"Failed to parse holdings: {e}")
            raise Exception(f"Failed to parse holdings: {e}")

        # Greedy select largest amounts to cover required_amount
        target = Decimal(required_amount)
        selected = []
        total = Decimal("0")
        for h in sorted(holdings, key=lambda x: x["amount"], reverse=True):
            if total >= target:
                break
            selected.append(h["cid"])
            total += h["amount"]

        return {"selectedCids": selected, "selectedTotal": str(total), "target": str(target), "offset": active_at_offset}

    async def list_holdings(
        self,
        party_id: str,
        limit: int = 200,
        active_at_offset: Optional[int] = None,
        instrument_admin: str = settings.DSO_ADMIN_ID,
        instrument_id: str = "Amulet",
    ) -> List[Dict[str, Any]]:
        """
        List holdings (cid, amount) for a party with configurable limit.
        """
        if active_at_offset is None:
            end = await self.get_ledger_end()
            active_at_offset = int(end.get("offset", 0))

        result = await self.get_active_contracts(
            party_id=party_id,
            active_at_offset=active_at_offset,
            interface_id="#splice-api-token-holding-v1:Splice.Api.Token.HoldingV1:Holding",
            verbose=True,
            limit=limit,
        )

        holdings: List[Dict[str, Any]] = []
        try:
            for entry in result if isinstance(result, list) else []:
                js = entry.get("contractEntry", {}).get("JsActiveContract", {})
                created = js.get("createdEvent", {})
                cid = created.get("contractId")
                for view in created.get("interfaceViews", []):
                    view_val = view.get("viewValue", {})
                    instr = view_val.get("instrumentId", {})
                    if instr.get("admin") == instrument_admin and instr.get("id") == instrument_id:
                        amt_str = view_val.get("amount")
                        if amt_str and cid:
                            holdings.append({"cid": cid, "amount": float(amt_str)})
        except Exception as e:
            logger.error(f"Failed to parse holdings: {e}")
            raise Exception(f"Failed to parse holdings: {e}")

        return holdings

    async def merge_holdings(
        self,
        from_party_id: str,
        to_party_id: str,
        sender_private_key: str,
        pick_count: int = 90,
        memo: str = "",
    ) -> Dict[str, Any]:
        """
        Merge UTXO-like holdings by sending a transfer using the first `pick_count` holdings as inputs.
        If from == to, this consolidates holdings into fewer outputs per ledger rules.
        """
        # Step 1: offset
        ledger_end = await self.get_ledger_end()
        offset = ledger_end.get("offset")

        # Step 2: list holdings and pick first N
        holdings = await self.list_holdings(from_party_id, limit=max(pick_count, 20), active_at_offset=offset)
        if not holdings:
            raise Exception("No holdings available to merge")
        selected = holdings[:pick_count]
        selected_cids = [h["cid"] for h in selected]
        total_amount = sum(h["amount"] for h in selected)
        total_amount = math.floor(total_amount * 1000) / 1000
        # Timestamps
        from datetime import datetime, timedelta
        now = datetime.utcnow()
        requested_at = now.isoformat() + "Z"
        execute_before = (now + timedelta(days=1)).isoformat() + "Z"

        # Registry
        factory_response = await self.get_transfer_factory_registry(
            from_party_id=from_party_id,
            receiver_party_id=to_party_id,
            amount=str(total_amount),
            input_holding_cids=selected_cids,
            requested_at=requested_at,
            execute_before=execute_before,
            memo=memo or "",
        )

        factory_id = factory_response.get("factoryId")
        choice_context = factory_response.get("choiceContext", {})
        disclosed_contracts = choice_context.get("disclosedContracts", [])
        choice_context_data = choice_context.get("choiceContextData", {})

        # Prepare
        import secrets as random_secrets
        command_id = f"merge-{random_secrets.token_hex(8)}"
        synchronizer_id = settings.CANTON_SYNCHRONIZER_ID
        meta_values = {}
        if memo:
            meta_values["splice.lfdecentralizedtrust.org/reason"] = memo

        url = f"{self.ledger_api_url}/interactive-submission/prepare"
        # Extract user id from JWT token
        user_id_for_prepare = await self._get_user_id_from_token()
        payload = {
            "commandId": command_id,
            "actAs": [from_party_id],
            "userId": user_id_for_prepare,
            "readAs": [from_party_id],
            "verboseHashing": True,
            "synchronizerId": synchronizer_id,
            "packageIdSelectionPreference": [],
            "commands": [
                {
                    "ExerciseCommand": {
                        "templateId": "#splice-api-token-transfer-instruction-v1:Splice.Api.Token.TransferInstructionV1:TransferFactory",
                        "contractId": factory_id,
                        "consuming": False,
                        "choice": "TransferFactory_Transfer",
                        "choiceArgument": {
                            "expectedAdmin": settings.DSO_ADMIN_ID,
                            "transfer": {
                                "sender": from_party_id,
                                "receiver": to_party_id,
                                "amount": str(total_amount),
                                "instrumentId": {
                                    "admin": settings.DSO_ADMIN_ID,
                                    "id": "Amulet",
                                },
                                "requestedAt": requested_at,
                                "executeBefore": execute_before,
                                "inputHoldingCids": selected_cids,
                                "meta": {"values": meta_values},
                            },
                            "extraArgs": {
                                "context": choice_context_data,
                                "meta": {"values": {}},
                            },
                        },
                    }
                }
            ],
            "disclosedContracts": disclosed_contracts,
        }

        headers = await self._get_auth_headers()
        self._log_http_request("POST", url, headers, payload)
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            # Enhanced error logging: print JSON/text body on non-2xx
            if resp.status_code >= 400:
                try:
                    err_body = resp.json()
                except Exception:
                    err_body = resp.text
                self._log_http_response("POST", url, resp.status_code, err_body)
            resp.raise_for_status()
            prepared_tx = resp.json()
        self._log_http_response("POST", url, resp.status_code, prepared_tx)

        prepared_transaction = prepared_tx.get("preparedTransaction")
        prepared_hash = prepared_tx.get("preparedTransactionHash")
        hashing_scheme_version = prepared_tx.get("hashingSchemeVersion", "HASHING_SCHEME_VERSION_V2")

        # Sign
        import base64
        from nacl.signing import SigningKey
        hash_bytes = base64.b64decode(prepared_hash)
        private_key_seed = base64.b64decode(sender_private_key)
        signing_key = SigningKey(private_key_seed)
        signature_b64 = base64.b64encode(signing_key.sign(hash_bytes).signature).decode("utf-8")

        # Execute
        submission_id = f"subm-{random_secrets.token_hex(4)}"
        user_id = await self._get_user_id_from_token()
        exec_payload = {
            "preparedTransaction": prepared_transaction,
            "partySignatures": {
                "signatures": [
                    {
                        "party": from_party_id,
                        "signatures": [
                            {
                                "format": "SIGNATURE_FORMAT_RAW",
                                "signature": signature_b64,
                                "signedBy": from_party_id.split("::")[-1],
                                "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519",
                            }
                        ],
                    }
                ]
            },
            "deduplicationPeriod": {"Empty": {}},
            "submissionId": submission_id,
            "userId": user_id,
            "hashingSchemeVersion": hashing_scheme_version,
        }
        exec_url = f"{self.ledger_api_url}/interactive-submission/execute"
        self._log_http_request("POST", exec_url, headers, exec_payload)
        async with httpx.AsyncClient(timeout=60.0) as client:
            exec_resp = await client.post(exec_url, json=exec_payload, headers=headers)
            if exec_resp.status_code >= 400:
                try:
                    err_body2 = exec_resp.json()
                except Exception:
                    err_body2 = exec_resp.text
                self._log_http_response("POST", exec_url, exec_resp.status_code, err_body2)
            exec_resp.raise_for_status()
            result = exec_resp.json()
        self._log_http_response("POST", exec_url, exec_resp.status_code, result)

        return {
            "amount": total_amount,
            "from": from_party_id,
            "to": to_party_id,
            "memo": memo,
            "submissionId": submission_id,
            "executionResult": result,
            "selectedHoldingCount": len(selected_cids),
        }
    
    async def send_transfer(
        self,
        recipient: str,
        amount: float,
        memo: Optional[str] = None,
        sender_party_id: Optional[str] = None,
        sender_private_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send Canton transfer - Complete 6-step transfer flow
        
        Complete flow (based on canton_transfer_new.py implementation):
        1. GET ledger-end to get offset
        2. POST active-contracts to query holdings and UTXO select CIDs
        3. POST transfer-factory to get factory and disclosed contracts
        4. POST prepare to prepare transfer transaction
        5. Ed25519 signing
        6. POST executeAndWaitForTransaction to execute transaction
        
        Args:
            recipient: Receiver Party ID
            amount: Transfer amount
            memo: Memo information
            sender_party_id: Sender Party ID (optional, defaults to CANTON_PARTY_ID from config)
            sender_private_key: Sender private key seed base64 (required for signing)
        
        Returns:
            {
                "txHash": str,
                "amount": float,
                "from": str,
                "to": str,
                "memo": str,
                "commandId": str,
                "submissionId": str,
                "executionResult": dict
            }
        """
        import uuid
        import secrets as random_secrets
        from datetime import datetime, timedelta
        
        # Determine sender
        from_party = sender_party_id
        if not from_party:
            raise Exception("Sender Party ID missing. Either provide sender_party_id or set CANTON_PARTY_ID in .env")
        
        if not sender_private_key:
            raise Exception("sender_private_key is required for signing the transaction")
        
        logger.info(f"🚀 Starting Canton transfer: {amount} CC from {from_party[:20]}... to {recipient[:20]}...")
        if memo:
            logger.info(f"   Memo: {memo}")
        
        try:
            # Step 1: Get ledger-end offset
            logger.info("📍 Step 1: Getting ledger-end offset...")
            ledger_end = await self.get_ledger_end()
            offset = ledger_end.get("offset")
            logger.info(f"   ✅ Offset: {offset}")
            
            # Step 2: Query active contracts and select CIDs using UTXO logic
            logger.info("📦 Step 2: Querying active contracts...")
            active_contracts = await self.get_active_contracts(from_party, offset)
            
            selected_cids, total_selected = self.select_holding_cids_utxo(active_contracts, amount)
            
            if total_selected < amount:
                raise ValueError(f"Insufficient balance: need {amount}, found {total_selected}")
            
            logger.info(f"   ✅ Selected {len(selected_cids)} CIDs, total: {total_selected} CC")
            
            # Calculate timestamps
            now = datetime.utcnow()
            requested_at = now.isoformat() + "Z"
            execute_before = (now + timedelta(days=1)).isoformat() + "Z"
            
            # Step 3: Get transfer factory registry
            logger.info("🏭 Step 3: Getting transfer factory registry...")
            factory_response = await self.get_transfer_factory_registry(
                from_party_id=from_party,
                receiver_party_id=recipient,
                amount=str(amount),
                input_holding_cids=selected_cids,
                requested_at=requested_at,
                execute_before=execute_before,
                memo=memo or ""
            )
            
            factory_id = factory_response.get("factoryId")
            choice_context = factory_response.get("choiceContext", {})
            disclosed_contracts = choice_context.get("disclosedContracts", [])
            choice_context_data = choice_context.get("choiceContextData", {})
            
            logger.info(f"   ✅ Factory ID: {factory_id[:32]}...")
            logger.info(f"   ✅ Disclosed contracts: {len(disclosed_contracts)}")
            
            # Synchronizer ID (default to global-domain)
            synchronizer_id = settings.CANTON_SYNCHRONIZER_ID
            logger.info("⚙️  Step 4: Preparing transfer transaction...")
            command_id = f"transfer-{random_secrets.token_hex(8)}"
            
            # Build meta values
            meta_values = {}
            if memo:
                meta_values["splice.lfdecentralizedtrust.org/reason"] = memo
            
            # Prepare transaction payload
            # Extract user id from JWT token
            user_id_for_prepare = await self._get_user_id_from_token()
            url = f"{self.ledger_api_url}/interactive-submission/prepare"
            payload = {
                "commandId": command_id,
                "actAs": [from_party],
                "userId": user_id_for_prepare,
                "readAs": [from_party],
                "verboseHashing": True,
                "synchronizerId": synchronizer_id,
                "packageIdSelectionPreference": [],
                "commands": [
                    {
                        "ExerciseCommand": {
                            "templateId": "#splice-api-token-transfer-instruction-v1:Splice.Api.Token.TransferInstructionV1:TransferFactory",
                            "contractId": factory_id,
                            "consuming": False,
                            "choice": "TransferFactory_Transfer",
                            "choiceArgument": {
                                "expectedAdmin": settings.DSO_ADMIN_ID,
                                "transfer": {
                                    "sender": from_party,
                                    "receiver": recipient,
                                    "amount": str(amount),
                                    "instrumentId": {
                                        "admin": settings.DSO_ADMIN_ID,
                                        "id": "Amulet"
                                    },
                                    "requestedAt": requested_at,
                                    "executeBefore": execute_before,
                                    "inputHoldingCids": selected_cids,
                                    "meta": {"values": meta_values}
                                },
                                "extraArgs": {
                                    "context": choice_context_data,
                                    "meta": {"values": {}}
                                }
                            }
                        }
                    }
                ],
                "disclosedContracts": disclosed_contracts
            }
            
            headers = await self._get_auth_headers()
            self._log_http_request("POST", url, headers, payload)
            
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                prepared_tx = response.json()
                self._log_http_response("POST", url, response.status_code, prepared_tx)
            
            prepared_transaction = prepared_tx.get("preparedTransaction")
            prepared_hash = prepared_tx.get("preparedTransactionHash")
            hashing_scheme_version = prepared_tx.get("hashingSchemeVersion", "HASHING_SCHEME_VERSION_V2")
            
            logger.info(f"   ✅ Transaction prepared, hash: {prepared_hash[:32]}...")
            
            # Step 5: Sign transaction with Ed25519
            logger.info("✍️  Step 5: Signing transaction with Ed25519...")
            hash_bytes = base64.b64decode(prepared_hash)
            private_key_seed = base64.b64decode(sender_private_key)
            
            from nacl.signing import SigningKey
            signing_key = SigningKey(private_key_seed)
            signed = signing_key.sign(hash_bytes)
            signature_b64 = base64.b64encode(signed.signature).decode('utf-8')
            
            logger.info(f"   ✅ Signature: {signature_b64[:32]}...")
            
            # Extract public key fingerprint
            public_key_fingerprint = from_party.split("::")[-1]
            
            # Step 6: Execute and wait for transaction
            logger.info("🚀 Step 6: Executing transaction...")
            submission_id = f"subm-{random_secrets.token_hex(4)}"
            
            # Get user_id (no fallback allowed)
            user_id = await self._get_user_id_from_token()
            
            exec_payload = {
                "preparedTransaction": prepared_transaction,
                "partySignatures": {
                    "signatures": [
                        {
                            "party": from_party,
                            "signatures": [
                                {
                                    "format": "SIGNATURE_FORMAT_RAW",
                                    "signature": signature_b64,
                                    "signedBy": public_key_fingerprint,
                                    "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
                                }
                            ]
                        }
                    ]
                },
                "deduplicationPeriod": {"Empty": {}},
                "submissionId": submission_id,
                "userId": user_id,
                "hashingSchemeVersion": hashing_scheme_version
            }
            
            exec_url = f"{self.ledger_api_url}/interactive-submission/execute"
            self._log_http_request("POST", exec_url, headers, exec_payload)
            
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(exec_url, json=exec_payload, headers=headers)
                response.raise_for_status()
                result = response.json()
                self._log_http_response("POST", exec_url, response.status_code, result)
            
            # Poll updates to retrieve updateId for this command
            # Begin exclusive should be the ledger end captured earlier in Step 1
            await asyncio.sleep(0.5)
            max_attempts = 60  # ~30s total at 0.5s interval
            update_id: Optional[str] = None
            for _ in range(max_attempts):
                try:
                    updates = await self.get_updates(begin_exclusive=offset, party_id=from_party)
                    # Expecting a list; guard for dict too
                    items = updates if isinstance(updates, list) else [updates]
                    for item in items:
                        tx_val = item.get("update", {}).get("Transaction", {}).get("value", {})
                        if not tx_val:
                            continue
                        if tx_val.get("commandId") == command_id:
                            update_id = tx_val.get("updateId")
                            break
                    if update_id:
                        break
                except Exception as _poll_err:
                    logger.debug(f"updates polling error: {_poll_err}")
                await asyncio.sleep(0.5)

            if not update_id:
                logger.warning("No matching updateId found within polling window")

            logger.info("✅ Transfer completed successfully!")
            
            # Build return result
            return {
                "amount": amount,
                "from": from_party,
                "to": recipient,
                "memo": memo,
                "commandId": command_id,
                "submissionId": submission_id,
                "executionResult": result,
                "updateId": update_id,
            }
            
        except Exception as e:
            logger.error(f"❌OLD Transfer failed: {str(e)}")
            raise
    

    
    async def create_party(
        self,
        display_name: Optional[str] = None,
        synchronizer: str = settings.CANTON_SYNCHRONIZER_ID
    ) -> Dict[str, Any]:
        """
        Create new Party - Complete flow
        
        Flow:
        1. Generate Ed25519 key pair
        2. Call /parties/external/generate-topology to generate topology
        3. Sign multiHash
        4. Call /parties/external/allocate to allocate Party
        5. Get user_id from JWT token
        6. Call /users/{userId}/rights to grant CanActAs permission
        
        Args:
            display_name: Party display name (used as partyHint)
            synchronizer: Canton synchronizer ID
            
        Returns:
            {
                "partyId": "manual-test::1220...",
                "partyHint": "manual-test",
                "publicKeyFingerprint": "1220...",
                "privateKeySeedBase64": "...",
                "publicKeyDerBase64": "...",
                "publicKeyRawBase64": "...",
                "displayName": "manual-test"
            }
        """
        try:
            party_hint = display_name or "auto-party"
            
            # Step 0: Check if party hint is duplicate
            logger.info(f"Step 0: Checking for duplicate party hint: {party_hint}")
            if self.check_party_hint_duplicate(party_hint):
                existing_file = self.find_party_file_by_hint(party_hint)
                raise Exception(
                    f"Party hint '{party_hint}' already exists!\n"
                    f"Found existing party file: {existing_file}\n"
                    f"Please use a different name or load the existing party."
                )
            
            logger.info(f"Starting party creation process with hint: {party_hint}")
            
            # Step 1: Generate Ed25519 key pair
            logger.info("Step 1: Generating Ed25519 key pair...")
            keypair = key_generator.generate_ed25519_keypair()
            private_key_seed = keypair["private_key_seed_base64"]
            public_key_der = keypair["public_key_der_base64"]
            public_key_raw = keypair["public_key_raw_base64"]
            
            logger.info(f"Generated keys - Public key (DER): {public_key_der[:20]}...")
            
            # Step 2: Generate topology
            logger.info(f"Step 2: Generating topology for party hint: {party_hint}")
            
            topology_result = await self.generate_topology(
                synchronizer=synchronizer,
                party_hint=party_hint,
                public_key_der_base64=public_key_der
            )
            
            party_id = topology_result["partyId"]
            public_key_fingerprint = topology_result["publicKeyFingerprint"]
            topology_transactions = topology_result["topologyTransactions"]
            multi_hash = topology_result["multiHash"]
            
            logger.info(f"Topology generated - Party ID: {party_id}")
            logger.info(f"Public key fingerprint: {public_key_fingerprint}")
            
            # Step 3: Sign multiHash
            logger.info("Step 3: Signing multiHash...")
            multi_hash_bytes = base64.b64decode(multi_hash)
            signature = key_generator.sign_data(private_key_seed, multi_hash_bytes)
            
            logger.info(f"MultiHash signed - Signature: {signature[:20]}...")
            
            # Step 4: Allocate Party
            logger.info("Step 4: Allocating external party...")
            allocate_result = await self.allocate_external_party(
                synchronizer=synchronizer,
                onboarding_transactions=topology_transactions,
                signature_base64=signature,
                signed_by_fingerprint=public_key_fingerprint
            )
            
            final_party_id = allocate_result["partyId"]
            logger.info(f"Party allocated successfully: {final_party_id}")
            
            # Step 5: Get user_id and grant permissions
            logger.info("Step 5: Granting user rights...")
            user_id = await self._get_user_id_from_token()
            logger.info(f"Got user ID from JWT token: {user_id}")
            
            await self.grant_user_can_act_as(user_id=user_id, party_id=final_party_id)
            logger.info(f"User {user_id} granted CanActAs permission for party {final_party_id}")
            
            # Return complete information
            result = {
                "partyId": final_party_id,
                "partyHint": party_hint,
                "publicKeyFingerprint": public_key_fingerprint,
                "privateKeySeedBase64": private_key_seed,
                "publicKeyDerBase64": public_key_der,
                "publicKeyRawBase64": public_key_raw,
                "displayName": party_hint,
                "synchronizer": synchronizer,
                "userId": user_id
            }
            
            logger.info("✓ Party creation completed successfully!")
            return result
            
        except Exception as e:
            logger.error(f"Failed to create party: {e}", exc_info=True)
            raise Exception(f"Party creation failed: {e}")
    
    async def _get_user_id_from_token(self) -> str:
        """
        Extract user_id from JWT token
        Canton's JWT token contains sub field, which is user_id
        """
        try:
            access_token = await auth_manager.get_access_token()
            
            # Decode JWT (without verifying signature, since we only need to read payload)
            decoded = jwt.decode(access_token, options={"verify_signature": False})
            
            # user_id is usually in 'sub' field
            user_id = decoded.get("sub")
            if not user_id:
                raise Exception("No 'sub' field found in JWT token")
            
            logger.info(f"Extracted user_id from JWT: {user_id}")
            return user_id
            
        except Exception as e:
            logger.error(f"Failed to extract user_id from token: {e}")
            raise Exception(f"Failed to get user ID from token: {e}")
    
    @staticmethod
    def find_party_file_by_hint(party_hint: str, parties_dir: str = "./parties") -> Optional[str]:
        """
        Find party file locally by party hint
        
        Args:
            party_hint: Party hint (e.g., "my-party")
            parties_dir: Party files directory
            
        Returns:
            Party file path, or None if not found
        """
        import os
        import glob
        
        if not os.path.exists(parties_dir):
            return None
        
        # Find all JSON files
        pattern = os.path.join(parties_dir, "*.json")
        for filepath in glob.glob(pattern):
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
                    # Check partyHint or displayName field
                    if data.get("partyHint") == party_hint or data.get("displayName") == party_hint:
                        return filepath
            except Exception:
                continue
        
        return None
    
    @staticmethod
    def load_party_from_file(filepath: str) -> Dict[str, Any]:
        """
        Load Party information from file
        
        Args:
            filepath: Party file path
            
        Returns:
            Party data dictionary
        """
        try:
            with open(filepath, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            raise Exception(f"Party file not found: {filepath}")
        except json.JSONDecodeError:
            raise Exception(f"Invalid JSON in party file: {filepath}")
    
    @staticmethod
    def check_party_hint_duplicate(party_hint: str, parties_dir: str = "./parties") -> bool:
        """
        Check if party hint already exists
        
        Args:
            party_hint: Party hint to check
            parties_dir: Party files directory
            
        Returns:
            True if duplicate exists, False otherwise
        """
        return CantonService.find_party_file_by_hint(party_hint, parties_dir) is not None
    
    async def list_parties(self) -> List[Dict[str, Any]]:
        """
        List all Parties - Using Ledger API
        
        Note: This method needs to be implemented according to actual Canton Ledger API
        Currently throws not implemented exception
        
        Return example:
        [
            {
                "partyId": "cc1xxxxx",
                "displayName": "Party 1"
            }
        ]
        """
        logger.info("Listing all parties")
        logger.warning("List parties not yet implemented for new Ledger API")
        raise NotImplementedError("List parties API needs to be implemented using Ledger API")
    
  


# Global singleton - automatically determine whether to enable debug based on command line arguments
import sys
import os
_debug_mode = (
    'debug' in sys.argv or 
    '--debug' in sys.argv or 
    any('debug' in str(arg).lower() for arg in sys.argv) or
    os.getenv('DEBUG', '').lower() in ('1', 'true', 'yes')
)
canton_service = CantonService(debug_mode=_debug_mode)
if _debug_mode:
    logger.info(f"🐛 Canton Service initialized with DEBUG MODE ENABLED")


def create_canton_service_with_debug(debug_mode: bool = False) -> CantonService:
    """Create Canton Service instance with specified debug mode"""
    return CantonService(debug_mode=debug_mode)