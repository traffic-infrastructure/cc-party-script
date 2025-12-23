"""
Canton Authentication Manager - JWT Token Management
Handles token acquisition, storage, and refresh
"""
import json
import os
import time
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import httpx
import logging
from app.config import settings

logger = logging.getLogger(__name__)


class AuthManager:
    """Canton Authentication Manager"""
    
    def __init__(self):
        self.auth_url = settings.CANTON_AUTH_URL
        self.client_id = settings.CANTON_CLIENT_ID
        self.client_secret = settings.CANTON_CLIENT_SECRET
        self.audience = settings.CANTON_AUDIENCE
        self.scope = settings.CANTON_SCOPE
        
        # Token storage file - based on MODE (dev/main)
        mode = os.getenv("MODE") or os.getenv("ENV_MODE") or "dev"
        token_filename = f"canton_token_{mode}.json"
        self.token_file = Path(f"data/{token_filename}")
        self.token_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Token cache
        self._access_token: Optional[str] = None
        self._expires_at: Optional[float] = None
        
        # Load existing token
        self._load_token()
    
    def _load_token(self):
        """Load token from file"""
        if self.token_file.exists():
            try:
                with open(self.token_file, 'r') as f:
                    data = json.load(f)
                    self._access_token = data.get('access_token')
                    self._expires_at = data.get('expires_at')
                    
                    if self._is_token_valid():
                        logger.info("Loaded valid token from file")
                    else:
                        logger.info("Token expired, will refresh")
                        self._access_token = None
                        self._expires_at = None
            except Exception as e:
                logger.error(f"Failed to load token from file: {e}")
    
    def _save_token(self, access_token: str, expires_in: int):
        """Save token to file"""
        try:
            # Calculate expiration time (expire 5 minutes early)
            expires_at = time.time() + expires_in - 300
            
            data = {
                'access_token': access_token,
                'expires_in': expires_in,
                'expires_at': expires_at,
                'updated_at': datetime.utcnow().isoformat()
            }
            
            with open(self.token_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            self._access_token = access_token
            self._expires_at = expires_at
            
            logger.info(f"Token saved, expires in {expires_in} seconds")
        except Exception as e:
            logger.error(f"Failed to save token: {e}")
    
    def _is_token_valid(self) -> bool:
        """Check if token is valid"""
        if not self._access_token or not self._expires_at:
            return False
        
        # Check if expired
        return time.time() < self._expires_at
    
    async def login(self) -> str:
        """
        Login to obtain access token
        
        Returns:
            access_token
        """
        logger.info("Logging in to Canton...")
        
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'audience': self.audience,
            'scope': self.scope
        }
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    self.auth_url,
                    data=payload
                )
                response.raise_for_status()
                data = response.json()
                
                access_token = data['access_token']
                expires_in = data['expires_in']
                
                # Save token
                self._save_token(access_token, expires_in)
                
                logger.info("Successfully logged in to Canton")
                return access_token
                
        except httpx.HTTPError as e:
            logger.error(f"Failed to login: {e}")
            raise Exception(f"Canton login failed: {e}")
    
    async def get_access_token(self) -> str:
        """
        Get a valid access token
        Will automatically login if token is expired or does not exist
        
        Returns:
            access_token
        """
        if self._is_token_valid():
            return self._access_token
        
        # Token expired or does not exist, re-login
        return await self.login()
    
    def clear_token(self):
        """Clear token cache"""
        self._access_token = None
        self._expires_at = None
        if self.token_file.exists():
            self.token_file.unlink()
        logger.info("Token cleared")


# Global singleton
auth_manager = AuthManager()