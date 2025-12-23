"""
Key Store - Manage Ed25519 keys and signatures stored in JSON files under secrets/
"""
import json
from pathlib import Path
from typing import Dict, Optional
import base64
from nacl import signing

SECRETS_DIR = Path("secrets")
SECRETS_DIR.mkdir(parents=True, exist_ok=True)


def save_key(name: str, seed_base64: str, public_key_base64: Optional[str] = None) -> Path:
    """Save an Ed25519 key seed and optional public key to secrets/<name>.json"""
    data: Dict[str, str] = {"name": name, "seed_base64": seed_base64}
    if public_key_base64:
        data["public_key_base64"] = public_key_base64
    path = SECRETS_DIR / f"{name}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def load_key(name: str) -> Dict[str, str]:
    """Load key info from secrets/<name>.json"""
    path = SECRETS_DIR / f"{name}.json"
    with open(path, "r") as f:
        return json.load(f)


def generate_ed25519(name: str) -> Dict[str, str]:
    """Generate an Ed25519 keypair and save to secrets, return info."""
    signer = signing.SigningKey.generate()
    seed = signer._seed
    seed_b64 = base64.b64encode(seed).decode()
    verify_key = signer.verify_key
    pub_b64 = base64.b64encode(verify_key.encode()).decode()
    save_key(name, seed_b64, pub_b64)
    return {"name": name, "seed_base64": seed_b64, "public_key_base64": pub_b64}


def sign_bytes_with_seed(seed_base64: str, message: bytes) -> str:
    signer = signing.SigningKey(base64.b64decode(seed_base64))
    signature = signer.sign(message).signature
    return base64.b64encode(signature).decode()


def sign_base64_with_seed(seed_base64: str, message_base64: str) -> str:
    return sign_bytes_with_seed(seed_base64, base64.b64decode(message_base64))
