import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import ValidationError
from typing import Optional


class Settings(BaseSettings):
    # Canton Network Configuration
    CANTON_AUTH_URL: str
    # 必填: Ledger API 基础地址（/v2）
    CANTON_LEDGER_API_URL: str
    # 必填: Transfer Factory Registry 完整端点 URL
    CANTON_TRANSFER_FACTORY_REGISTRY_URL: str
    CANTON_CLIENT_ID: str
    CANTON_CLIENT_SECRET: str
    CANTON_AUDIENCE: str
    CANTON_SCOPE: str = "daml_ledger_api"
    CANTON_DRY_RUN: bool = False

    # DSO Admin ID
    # mainnet: "DSO::1220b1431ef217342db44d516bb9befde802be7d8899637d290895fa58880f19accc"
    # devnet:  "DSO::1220be58c29e65de40bf273be1dc2b266d43a9a002ea5b18955aeef7aac881bb471a"
    DSO_ADMIN_ID: Optional[str] = None
    
    # Canton Synchronizer ID
    # mainnet: "global-domain::1220be58c29e65de40bf273be1dc2b266d43a9a002ea5b18955aeef7aac881bb471a" 
    # devnet: "global-domain::1220b1431ef217342db44d516bb9befde802be7d8899637d290895fa58880f19accc"
    CANTON_SYNCHRONIZER_ID: Optional[str] = None
    
    
    # Pydantic v2 configuration using ConfigDict
    # Load env based on MODE: dev->.env.dev (default), main->.env.main, else .env
    _mode = os.getenv("MODE") or os.getenv("ENV_MODE") or "dev"
    _env_file = "env.dev" if _mode == "dev" else "env.main" if _mode == "main" else "env"
    model_config = SettingsConfigDict(env_file=_env_file, case_sensitive=True)


def _load_settings() -> Settings:
    try:
        s = Settings()
        # If DSO_ADMIN_ID is not set in env, choose default by mode
        mode = os.getenv("MODE") or os.getenv("ENV_MODE") or "dev"
        if not s.DSO_ADMIN_ID:
            s.DSO_ADMIN_ID = (
                "DSO::1220b1431ef217342db44d516bb9befde802be7d8899637d290895fa58880f19accc"
                if mode == "main"
                else "DSO::1220be58c29e65de40bf273be1dc2b266d43a9a002ea5b18955aeef7aac881bb471a"
            )
        # Synchronizer ID defaults by mode, if not set via env CANTON_SYNCHRONIZER_ID
        if not s.CANTON_SYNCHRONIZER_ID:
            s.CANTON_SYNCHRONIZER_ID = (
                "global-domain::1220b1431ef217342db44d516bb9befde802be7d8899637d290895fa58880f19accc"
                if mode == "main"
                else "global-domain::1220be58c29e65de40bf273be1dc2b266d43a9a002ea5b18955aeef7aac881bb471a"
            )
        return s
    except ValidationError as e:
        missing = [err['loc'][0] for err in e.errors() if err.get('type') == 'missing']
        if missing:
            hint_lines = [
                "Missing required Canton API environment variables:",
                *[f"  - {name}" for name in missing]
            ]
            raise RuntimeError("\n".join(hint_lines)) from e
        raise

settings = _load_settings()
