from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from operations.core import execute, now_iso, row_to_dict, rows


@dataclass
class AuthContext:
    org_id: str
    role: str = "analyst"
    key_name: str = "local"
    authenticated: bool = False


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def env_api_keys() -> list[dict[str, str]]:
    configured = []
    for item in os.getenv("LEMTIK_API_KEYS", "").split(","):
        item = item.strip()
        if not item:
            continue
        parts = [part.strip() for part in item.split(":")]
        configured.append(
            {
                "api_key": parts[0],
                "org_id": parts[1] if len(parts) > 1 and parts[1] else os.getenv("LEMTIK_DEFAULT_ORG_ID", "default"),
                "role": parts[2] if len(parts) > 2 and parts[2] else "analyst",
                "name": parts[3] if len(parts) > 3 and parts[3] else "env-key",
            }
        )
    return configured


def auth_required() -> bool:
    if env_api_keys():
        return True
    try:
        return bool(rows("select id from api_keys where is_active = true limit 1"))
    except Exception:
        return False


def authenticate_api_key(api_key: str | None) -> AuthContext | None:
    if not api_key:
        return None
    for item in env_api_keys():
        if hmac.compare_digest(api_key, item["api_key"]):
            return AuthContext(org_id=item["org_id"], role=item["role"], key_name=item["name"], authenticated=True)

    digest = hash_api_key(api_key)
    try:
        found = rows(
            """
            select name, org_id, role
            from api_keys
            where key_hash = ?
            and is_active = true
            limit 1
            """,
            (digest,),
        )
    except Exception:
        found = []
    if not found:
        return None
    row = row_to_dict(found[0])
    return AuthContext(org_id=row["org_id"], role=row["role"], key_name=row["name"], authenticated=True)


def allowed_org(requested_org_id: str, auth: AuthContext) -> str:
    requested_org_id = requested_org_id or auth.org_id
    if not auth.authenticated or auth.org_id == "*" or requested_org_id == auth.org_id:
        return requested_org_id
    raise PermissionError("API key is not allowed to access this organisation")


def audit_log(
    *,
    org_id: str,
    actor: str,
    action: str,
    resource_type: str = "",
    resource_id: str = "",
    ip_address: str = "",
    user_agent: str = "",
    metadata: str = "{}",
) -> None:
    try:
        execute(
            """
            insert into audit_logs
            (org_id, actor, action, resource_type, resource_id, ip_address, user_agent, metadata, created_at)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (org_id, actor, action, resource_type, resource_id, ip_address, user_agent, metadata, now_iso()),
        )
    except Exception:
        return
