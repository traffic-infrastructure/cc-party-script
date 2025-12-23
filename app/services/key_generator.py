"""
Ed25519 Key Generation Utility
Generates Ed25519 key pairs compatible with Canton Network requirements
"""
import base64
from nacl import signing
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class KeyGenerator:
    """Ed25519 key pair generator using PyNaCl"""
    
    @staticmethod
    def generate_ed25519_keypair() -> Dict[str, Any]:
        """
        Generate an Ed25519 key pair compatible with Canton Network.
        
        Returns:
            Dictionary containing:
            - private_key_seed_base64: The 32-byte seed for private key (base64 encoded)
            - public_key_der_base64: DER X.509 SubjectPublicKeyInfo format (base64 encoded)
            - public_key_raw_base64: Raw 32-byte public key (base64 encoded)
        
        The DER format is compatible with openssl output:
        openssl genpkey -algorithm ed25519 -outform DER -out private_key.der
        openssl pkey -in private_key.der -pubout -outform DER -out public_key.der
        """
        try:
            # Generate signing key (this gives us a 32-byte seed)
            signing_key = signing.SigningKey.generate()
            verify_key = signing_key.verify_key
            
            # Get the raw 32-byte seed for the private key
            private_key_seed = bytes(signing_key)  # 32 bytes
            
            # Get the raw 32-byte public key
            public_key_raw = bytes(verify_key)  # 32 bytes
            
            # Create DER X.509 SubjectPublicKeyInfo format for Ed25519 public key
            # This matches the output of: openssl pkey -pubout -outform DER
            # Reference: RFC 8410 - Algorithm Identifiers for Ed25519
            public_key_der = KeyGenerator._create_ed25519_spki_der(public_key_raw)
            
            result = {
                "private_key_seed_base64": base64.b64encode(private_key_seed).decode('utf-8'),
                "public_key_der_base64": base64.b64encode(public_key_der).decode('utf-8'),
                "public_key_raw_base64": base64.b64encode(public_key_raw).decode('utf-8'),
            }
            
            logger.info("Successfully generated Ed25519 key pair")
            return result
            
        except Exception as e:
            logger.error(f"Failed to generate Ed25519 key pair: {e}")
            raise Exception(f"Ed25519 key generation failed: {e}")
    
    @staticmethod
    def _create_ed25519_spki_der(public_key_raw: bytes) -> bytes:
        """
        Create DER X.509 SubjectPublicKeyInfo format for Ed25519 public key.
        
        Structure (44 bytes total):
        - SEQUENCE (42 bytes)
          - SEQUENCE (5 bytes) - Algorithm Identifier
            - OID for Ed25519: 1.3.101.112 (curveEd25519)
          - BIT STRING (33 bytes)
            - 32 bytes of public key data
        
        DER encoding breakdown:
        30 2a                    -- SEQUENCE (42 bytes)
           30 05                 -- SEQUENCE (5 bytes) 
              06 03 2b 65 70     -- OID 1.3.101.112 (id-Ed25519)
           03 21                 -- BIT STRING (33 bytes)
              00                 -- no unused bits
              [32 bytes key]     -- public key data
        """
        if len(public_key_raw) != 32:
            raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(public_key_raw)}")
        
        # OID for Ed25519: 1.3.101.112
        oid_ed25519 = bytes([0x06, 0x03, 0x2b, 0x65, 0x70])
        
        # Algorithm Identifier SEQUENCE
        algorithm_identifier = bytes([0x30, 0x05]) + oid_ed25519
        
        # BIT STRING containing the public key (with 0x00 prefix for "no unused bits")
        bit_string = bytes([0x03, 0x21, 0x00]) + public_key_raw
        
        # SubjectPublicKeyInfo SEQUENCE
        spki = bytes([0x30, 0x2a]) + algorithm_identifier + bit_string
        
        return spki
    
    @staticmethod
    def sign_data(private_key_seed_base64: str, data: bytes) -> str:
        """
        Sign data using Ed25519 private key.
        
        Args:
            private_key_seed_base64: Base64-encoded 32-byte seed
            data: Data to sign
            
        Returns:
            Base64-encoded signature (64 bytes)
        """
        try:
            seed = base64.b64decode(private_key_seed_base64)
            signing_key = signing.SigningKey(seed)
            signature = signing_key.sign(data).signature
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to sign data: {e}")
            raise Exception(f"Signature generation failed: {e}")
    
    @staticmethod
    def verify_signature(public_key_raw_base64: str, data: bytes, signature_base64: str) -> bool:
        """
        Verify a signature using Ed25519 public key.
        
        Args:
            public_key_raw_base64: Base64-encoded 32-byte public key
            data: Original data that was signed
            signature_base64: Base64-encoded signature
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key_bytes = base64.b64decode(public_key_raw_base64)
            verify_key = signing.VerifyKey(public_key_bytes)
            signature_bytes = base64.b64decode(signature_base64)
            
            # This will raise an exception if verification fails
            verify_key.verify(data, signature_bytes)
            return True
        except Exception as e:
            logger.warning(f"Signature verification failed: {e}")
            return False


# Singleton instance
key_generator = KeyGenerator()
