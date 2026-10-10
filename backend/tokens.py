import json
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any

TOKENS_FILE = os.getenv("TOKENS_FILE", "/etc/mail-secrets/api-tokens.json")

def _ensure_file():
    if not os.path.exists(TOKENS_FILE):
        os.makedirs(os.path.dirname(TOKENS_FILE), exist_ok=True)
        with open(TOKENS_FILE, "w") as f:
            json.dump({"tokens": []}, f, indent=2)
        os.chmod(TOKENS_FILE, 0o600)

def load_tokens() -> List[Dict[str, Any]]:
    _ensure_file()
    try:
        with open(TOKENS_FILE, "r") as f:
            data = json.load(f)
            return data.get("tokens", [])
    except Exception:
        return []

def save_tokens(tokens: List[Dict[str, Any]]):
    _ensure_file()
    tmp_file = f"{TOKENS_FILE}.tmp"
    with open(tmp_file, "w") as f:
        json.dump({"tokens": tokens}, f, indent=2)
    os.chmod(tmp_file, 0o600)
    os.replace(tmp_file, TOKENS_FILE)

def find_token(token_str: str) -> Optional[Dict[str, Any]]:
    tokens = load_tokens()
    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    for t in tokens:
        if t.get("active", True) and secrets.compare_digest(t.get("token", ""), token_str):
            if t.get("expires_at") and t["expires_at"] < now_iso:
                return None
            return t
    return None

def create_token(name: str, domain: str, roles: Optional[List[str]] = None, expires_in_hours: Optional[int] = None) -> Dict[str, Any]:
    tokens = load_tokens()
    clean_domain = domain.strip().lower()
    prefix = clean_domain.split(".")[0] if clean_domain != "*" else "admin"
    raw_token = f"sec_{prefix}_{secrets.token_urlsafe(32)}"
    token_id = f"tok_{secrets.token_hex(4)}"
    
    if roles is None:
        roles = ["mailboxes:read", "mailboxes:write", "aliases:read", "aliases:write", "dns:read"]

    expires_at = None
    if expires_in_hours:
        expires_at = (datetime.utcnow() + timedelta(hours=expires_in_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    entry = {
        "id": token_id,
        "token": raw_token,
        "name": name,
        "domain": clean_domain,
        "roles": roles,
        "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires_at,
        "active": True
    }
    tokens.append(entry)
    save_tokens(tokens)
    return entry

def revoke_token(token_id: str) -> bool:
    tokens = load_tokens()
    found = False
    for t in tokens:
        if t.get("id") == token_id or t.get("token") == token_id:
            t["active"] = False
            found = True
            break
    if found:
        save_tokens(tokens)
    return found

def delete_token(token_id: str) -> bool:
    tokens = load_tokens()
    initial_len = len(tokens)
    tokens = [t for t in tokens if t.get("id") != token_id and t.get("token") != token_id]
    if len(tokens) < initial_len:
        save_tokens(tokens)
        return True
    return False
