import os
import re
import shutil
import string
import secrets
import subprocess
from typing import Optional, List, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from pydantic import BaseModel, Field

from database import get_connection
import tokens as token_manager
from helpers import (
    require_admin_token,
    hash_dovecot_password,
    generate_secure_password,
    ensure_dkim_keys,
    build_dns_records,
    check_live_dns,
    generate_app_configs,
    MAIL_STORAGE,
    DKIM_DIR,
    MAIL_HOST,
    WEBMAIL_URL
)

admin_router = APIRouter(prefix="/api/v1/admin")

# --- Pydantic Schemas ---

class AdminDomainCreateRequest(BaseModel):
    domain: str = Field(..., description="Fully qualified domain name, e.g. 'mycompany.com'", example="mycompany.com")
    active: bool = Field(True, description="Whether the domain is active")
    generate_dkim: bool = Field(True, description="Automatically generate a 2048-bit RSA DKIM key via rspamadm")
    default_alias_destination: Optional[str] = Field(None, description="Optional default catch-all destination email for '@domain'", example="admin@ternis.net")
    create_postmaster: bool = Field(False, description="Automatically provision initial postmaster@<domain> mailbox")
    postmaster_password: Optional[str] = Field(None, description="Password for postmaster mailbox (auto-generated if omitted)")

class AdminDomainUpdateRequest(BaseModel):
    active: bool = Field(..., description="Active status of the domain")

class AdminMailboxCreateRequest(BaseModel):
    email: str = Field(..., description="Full email address (e.g. 'alice@mycompany.com')", example="alice@mycompany.com")
    password: Optional[str] = Field(None, description="Mailbox password (auto-generated if omitted)", example="StrongPass123!")
    quota_bytes: Optional[int] = Field(None, description="Storage quota in bytes (e.g. 10737418240 for 10 GB)")
    quota_gb: Optional[float] = Field(10.0, description="Storage quota in gigabytes", example=10.0)
    active: bool = Field(True, description="Whether mailbox is active")
    auto_create_domain: bool = Field(True, description="Automatically create and configure domain in database if it does not exist")

class AdminMailboxUpdateRequest(BaseModel):
    password: Optional[str] = Field(None, description="New password for the mailbox")
    quota_bytes: Optional[int] = Field(None, description="Storage quota in bytes")
    quota_gb: Optional[float] = Field(None, description="Storage quota in gigabytes")
    active: Optional[bool] = Field(None, description="Active status")

class AdminPasswordResetRequest(BaseModel):
    password: Optional[str] = Field(None, description="New password (auto-generated if omitted)")

class AdminAliasCreateRequest(BaseModel):
    source: str = Field(..., description="Source address or catch-all (e.g. 'team@domain.com' or '@domain.com')", example="team@domain.com")
    destination: str = Field(..., description="Destination address or comma-separated list of addresses", example="alice@domain.com, bob@external.org")
    active: bool = Field(True, description="Active status")
    auto_create_domain: bool = Field(True, description="Automatically create domain in database if it does not exist")

class AdminAliasUpdateRequest(BaseModel):
    destination: Optional[str] = Field(None, description="Updated destination address(es)")
    active: Optional[bool] = Field(None, description="Updated active status")

class AdminTokenCreateRequest(BaseModel):
    name: str = Field(..., description="Descriptive name for the token / application", example="Nextcloud Backend API")
    domain: str = Field("*", description="Domain scope: '*' for full root access, or specific domain e.g. 'ternis.net'", example="*")
    roles: Optional[List[str]] = Field(None, description="List of permission roles (defaults to full permissions)")
    expires_in_hours: Optional[int] = Field(None, description="Expiration in hours (null for permanent)")

# --- Helper Utilities ---

def get_dir_size_bytes(path: str) -> int:
    total = 0
    try:
        if os.path.exists(path):
            for dirpath, dirnames, filenames in os.walk(path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    if not os.path.islink(fp):
                        total += os.path.getsize(fp)
    except Exception:
        pass
    return total

# ==============================================================================
# 1. DOMAINS MANAGEMENT (ROOT)
# ==============================================================================

@admin_router.get("/domains", tags=["Admin: Domains"], summary="List All Virtual Domains")
def admin_list_domains(
    search: Optional[str] = Query(None, description="Filter domain names containing this string"),
    active: Optional[bool] = Query(None, description="Filter by active status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            # Count total matching
            count_sql = "SELECT COUNT(*) as total FROM domains WHERE 1=1"
            params: List[Any] = []
            if search:
                count_sql += " AND domain LIKE %s"
                params.append(f"%{search.strip().lower()}%")
            if active is not None:
                count_sql += " AND active = %s"
                params.append(1 if active else 0)

            cur.execute(count_sql, params)
            total = cur.fetchone()["total"]

            # Query list with counts
            sql = """
                SELECT 
                    d.id, d.domain, d.active, d.created_at,
                    COUNT(DISTINCT u.id) AS mailbox_count,
                    COUNT(DISTINCT a.id) AS alias_count
                FROM domains d
                LEFT JOIN users u ON u.domain_id = d.id
                LEFT JOIN aliases a ON a.domain_id = d.id
                WHERE 1=1
            """
            q_params: List[Any] = []
            if search:
                sql += " AND d.domain LIKE %s"
                q_params.append(f"%{search.strip().lower()}%")
            if active is not None:
                sql += " AND d.active = %s"
                q_params.append(1 if active else 0)

            sql += " GROUP BY d.id ORDER BY d.domain LIMIT %s OFFSET %s;"
            q_params.extend([limit, offset])

            cur.execute(sql, q_params)
            rows = cur.fetchall()

            for r in rows:
                r["active"] = bool(r["active"])
                r["created_at"] = str(r["created_at"])
                r["dkim_configured"] = os.path.exists(os.path.join(DKIM_DIR, f"{r['domain']}.mail.key"))

            return {
                "total": total,
                "count": len(rows),
                "limit": limit,
                "offset": offset,
                "domains": rows
            }

@admin_router.post("/domains", status_code=status.HTTP_201_CREATED, tags=["Admin: Domains"], summary="Create a Virtual Domain")
def admin_create_domain(
    req: AdminDomainCreateRequest,
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_domain = req.domain.strip().lower().rstrip(".")
    if not clean_domain or "." not in clean_domain or not re.match(r'^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$', clean_domain):
        raise HTTPException(status_code=422, detail="Invalid domain format.")

    created_postmaster = None
    created_alias = None

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, domain, active FROM domains WHERE domain = %s;", (clean_domain,))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail=f"Domain '{clean_domain}' already exists in mail system.")

            cur.execute("INSERT INTO domains (domain, active) VALUES (%s, %s);", (clean_domain, 1 if req.active else 0))
            domain_id = cur.lastrowid

            # Generate DKIM if requested
            dkim_val = None
            if req.generate_dkim:
                dkim_val = ensure_dkim_keys(clean_domain)

            # Optional postmaster mailbox
            if req.create_postmaster:
                pm_email = f"postmaster@{clean_domain}"
                pm_plain = req.postmaster_password if req.postmaster_password else generate_secure_password(20)
                pm_hash = hash_dovecot_password(pm_plain)
                pm_maildir = f"{clean_domain}/postmaster/"
                cur.execute("""
                    INSERT INTO users (domain_id, email, password, maildir, quota_bytes, active)
                    VALUES (%s, %s, %s, %s, 10737418240, 1);
                """, (domain_id, pm_email, pm_hash, pm_maildir))

                # Physical storage
                user_dir = os.path.join(MAIL_STORAGE, clean_domain, "postmaster")
                for f in ["cur", "new", "tmp"]:
                    os.makedirs(os.path.join(user_dir, "Maildir", f), exist_ok=True)
                subprocess.run(["chown", "-R", "vmail:vmail", os.path.join(MAIL_STORAGE, clean_domain)])
                subprocess.run(["chmod", "-R", "770", os.path.join(MAIL_STORAGE, clean_domain)])

                created_postmaster = {"email": pm_email, "password": pm_plain}

            # Optional default catch-all alias
            if req.default_alias_destination:
                dest = req.default_alias_destination.strip().lower()
                source = f"@{clean_domain}"
                cur.execute("""
                    INSERT INTO aliases (domain_id, source, destination, active)
                    VALUES (%s, %s, %s, 1);
                """, (domain_id, source, dest))
                created_alias = {"source": source, "destination": dest}

    dns_records = build_dns_records(clean_domain)

    return {
        "status": "created",
        "domain": {
            "id": domain_id,
            "domain": clean_domain,
            "active": req.active,
            "dkim_public_key": dkim_val
        },
        "postmaster": created_postmaster,
        "default_alias": created_alias,
        "dns_records": dns_records
    }

@admin_router.get("/domains/{domain}", tags=["Admin: Domains"], summary="Get Domain Details & Sub-resources")
def admin_get_domain(
    domain: str = Path(..., description="Domain name"),
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_domain = domain.strip().lower()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, domain, active, created_at FROM domains WHERE domain = %s;", (clean_domain,))
            dom = cur.fetchone()
            if not dom:
                raise HTTPException(status_code=404, detail=f"Domain '{clean_domain}' not found.")

            dom_id = dom["id"]
            cur.execute("SELECT id, email, quota_bytes, active, created_at FROM users WHERE domain_id = %s ORDER BY email;", (dom_id,))
            mailboxes = cur.fetchall()
            for m in mailboxes:
                m["active"] = bool(m["active"])
                m["created_at"] = str(m["created_at"])
                m["quota_gb"] = round((m["quota_bytes"] or 0) / (1024**3), 2)

            cur.execute("SELECT id, source, destination, active, created_at FROM aliases WHERE domain_id = %s ORDER BY source;", (dom_id,))
            aliases = cur.fetchall()
            for a in aliases:
                a["active"] = bool(a["active"])
                a["created_at"] = str(a["created_at"])

    dkim_key_file = os.path.join(DKIM_DIR, f"{clean_domain}.mail.key")
    dkim_exists = os.path.exists(dkim_key_file)
    dkim_val = ensure_dkim_keys(clean_domain) if dkim_exists else None

    return {
        "domain": {
            "id": dom["id"],
            "domain": dom["domain"],
            "active": bool(dom["active"]),
            "created_at": str(dom["created_at"]),
            "mailbox_count": len(mailboxes),
            "alias_count": len(aliases),
            "dkim_configured": dkim_exists,
            "dkim_public_key": dkim_val
        },
        "mailboxes": mailboxes,
        "aliases": aliases,
        "dns_records": build_dns_records(clean_domain),
        "live_dns": check_live_dns(clean_domain)
    }

@admin_router.patch("/domains/{domain}", tags=["Admin: Domains"], summary="Update Domain Active Status")
def admin_update_domain(
    domain: str,
    req: AdminDomainUpdateRequest,
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_domain = domain.strip().lower()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM domains WHERE domain = %s;", (clean_domain,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail=f"Domain '{clean_domain}' not found.")

            cur.execute("UPDATE domains SET active = %s WHERE domain = %s;", (1 if req.active else 0, clean_domain))

    return {
        "status": "updated",
        "domain": clean_domain,
        "active": req.active
    }

@admin_router.delete("/domains/{domain}", tags=["Admin: Domains"], summary="Delete Domain (Cascading)")
def admin_delete_domain(
    domain: str,
    purge_storage: bool = Query(False, description="Purge physical Maildir and DKIM key files from filesystem"),
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_domain = domain.strip().lower()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM domains WHERE domain = %s;", (clean_domain,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Domain '{clean_domain}' not found.")

            # Deleting domain automatically deletes associated users & aliases via foreign key ON DELETE CASCADE
            cur.execute("DELETE FROM domains WHERE domain = %s;", (clean_domain,))

    purged = False
    if purge_storage:
        dom_dir = os.path.join(MAIL_STORAGE, clean_domain)
        if os.path.exists(dom_dir):
            shutil.rmtree(dom_dir, ignore_errors=True)
            purged = True

        # Remove DKIM files
        for ext in [".key", ".txt"]:
            fp = os.path.join(DKIM_DIR, f"{clean_domain}.mail{ext}")
            if os.path.exists(fp):
                try:
                    os.remove(fp)
                except Exception:
                    pass

    return {
        "status": "deleted",
        "domain": clean_domain,
        "purged_storage": purged
    }

@admin_router.get("/domains/{domain}/dkim", tags=["Admin: Domains"], summary="Get Domain DKIM Public Key")
def admin_get_domain_dkim(
    domain: str,
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_domain = domain.strip().lower()
    val = ensure_dkim_keys(clean_domain)
    key_file = os.path.join(DKIM_DIR, f"{clean_domain}.mail.key")
    return {
        "domain": clean_domain,
        "selector": "mail",
        "key_file": key_file,
        "key_exists": os.path.exists(key_file),
        "dns_record": {
            "name": f"mail._domainkey.{clean_domain}.",
            "type": "TXT",
            "value": val or "DKIM key not found"
        }
    }

@admin_router.post("/domains/{domain}/dkim", tags=["Admin: Domains"], summary="Regenerate or Create DKIM Key")
def admin_regenerate_domain_dkim(
    domain: str,
    force: bool = Query(False, description="Overwrite existing DKIM private key"),
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_domain = domain.strip().lower()
    key_file = os.path.join(DKIM_DIR, f"{clean_domain}.mail.key")
    txt_file = os.path.join(DKIM_DIR, f"{clean_domain}.mail.txt")

    if force:
        if os.path.exists(key_file): os.remove(key_file)
        if os.path.exists(txt_file): os.remove(txt_file)

    val = ensure_dkim_keys(clean_domain)
    return {
        "status": "ok",
        "domain": clean_domain,
        "selector": "mail",
        "key_file": key_file,
        "public_key_txt": val
    }

# ==============================================================================
# 2. MAILBOXES MANAGEMENT (ROOT)
# ==============================================================================

@admin_router.get("/mailboxes", tags=["Admin: Mailboxes"], summary="List All Virtual Mailboxes")
def admin_list_mailboxes(
    domain: Optional[str] = Query(None, description="Filter by domain name"),
    search: Optional[str] = Query(None, description="Filter emails containing substring"),
    active: Optional[bool] = Query(None, description="Filter by active status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            count_sql = """
                SELECT COUNT(*) as total 
                FROM users u
                JOIN domains d ON u.domain_id = d.id
                WHERE 1=1
            """
            params: List[Any] = []
            if domain:
                count_sql += " AND d.domain = %s"
                params.append(domain.strip().lower())
            if search:
                count_sql += " AND u.email LIKE %s"
                params.append(f"%{search.strip().lower()}%")
            if active is not None:
                count_sql += " AND u.active = %s"
                params.append(1 if active else 0)

            cur.execute(count_sql, params)
            total = cur.fetchone()["total"]

            sql = """
                SELECT 
                    u.id, u.email, d.domain, u.maildir, u.quota_bytes, u.active, u.created_at
                FROM users u
                JOIN domains d ON u.domain_id = d.id
                WHERE 1=1
            """
            q_params: List[Any] = []
            if domain:
                sql += " AND d.domain = %s"
                q_params.append(domain.strip().lower())
            if search:
                sql += " AND u.email LIKE %s"
                q_params.append(f"%{search.strip().lower()}%")
            if active is not None:
                sql += " AND u.active = %s"
                q_params.append(1 if active else 0)

            sql += " ORDER BY u.email LIMIT %s OFFSET %s;"
            q_params.extend([limit, offset])

            cur.execute(sql, q_params)
            rows = cur.fetchall()

            for r in rows:
                r["active"] = bool(r["active"])
                r["created_at"] = str(r["created_at"])
                r["quota_gb"] = round((r["quota_bytes"] or 0) / (1024**3), 2)

            return {
                "total": total,
                "count": len(rows),
                "limit": limit,
                "offset": offset,
                "mailboxes": rows
            }

@admin_router.post("/mailboxes", status_code=status.HTTP_201_CREATED, tags=["Admin: Mailboxes"], summary="Create Mailbox on Any Domain")
def admin_create_mailbox(
    req: AdminMailboxCreateRequest,
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    full_email = req.email.strip().lower()
    if "@" not in full_email:
        raise HTTPException(status_code=422, detail="Full email address including domain is required (e.g. user@domain.com).")

    local_part, domain_part = full_email.split("@", 1)
    if not re.match(r'^[a-z0-9._-]+$', local_part):
        raise HTTPException(status_code=422, detail="Invalid characters in mailbox local part.")

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM domains WHERE domain = %s;", (domain_part,))
            dom_row = cur.fetchone()
            if not dom_row:
                if req.auto_create_domain:
                    cur.execute("INSERT INTO domains (domain, active) VALUES (%s, 1);", (domain_part,))
                    domain_id = cur.lastrowid
                    ensure_dkim_keys(domain_part)
                else:
                    raise HTTPException(status_code=404, detail=f"Domain '{domain_part}' does not exist in mail system. Enable auto_create_domain or add domain first.")
            else:
                domain_id = dom_row["id"]

            cur.execute("SELECT id FROM users WHERE email = %s;", (full_email,))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail=f"Mailbox '{full_email}' already exists.")

            plain_password = req.password if req.password else generate_secure_password(20)
            hashed_password = hash_dovecot_password(plain_password)

            quota_bytes = req.quota_bytes if req.quota_bytes is not None else int((req.quota_gb or 10.0) * (1024**3))
            maildir_rel = f"{domain_part}/{local_part}/"

            cur.execute("""
                INSERT INTO users (domain_id, email, password, maildir, quota_bytes, active)
                VALUES (%s, %s, %s, %s, %s, %s);
            """, (domain_id, full_email, hashed_password, maildir_rel, quota_bytes, 1 if req.active else 0))
            user_id = cur.lastrowid

    # Provision physical directory
    user_dir = os.path.join(MAIL_STORAGE, domain_part, local_part)
    for folder in ["cur", "new", "tmp"]:
        os.makedirs(os.path.join(user_dir, "Maildir", folder), exist_ok=True)
    subprocess.run(["chown", "-R", "vmail:vmail", os.path.join(MAIL_STORAGE, domain_part)])
    subprocess.run(["chmod", "-R", "770", os.path.join(MAIL_STORAGE, domain_part)])

    return {
        "status": "created",
        "mailbox": {
            "id": user_id,
            "email": full_email,
            "domain": domain_part,
            "password": plain_password,
            "quota_bytes": quota_bytes,
            "quota_gb": round(quota_bytes / (1024**3), 2),
            "active": req.active,
            "maildir": os.path.join(MAIL_STORAGE, maildir_rel)
        },
        "connection_info": {
            "imap": {"server": MAIL_HOST, "port": 993, "ssl": True, "username": full_email},
            "smtp": {"server": MAIL_HOST, "port": 465, "ssl": True, "starttls_port": 587, "username": full_email},
            "webmail_url": WEBMAIL_URL
        },
        "config_snippets": generate_app_configs(full_email, plain_password, domain_part, local_part)
    }

@admin_router.get("/mailboxes/{email}", tags=["Admin: Mailboxes"], summary="Get Mailbox Details")
def admin_get_mailbox(
    email: str = Path(..., description="Email address"),
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_email = email.strip().lower()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.id, u.email, d.domain, u.maildir, u.quota_bytes, u.active, u.created_at
                FROM users u
                JOIN domains d ON u.domain_id = d.id
                WHERE u.email = %s;
            """, (clean_email,))
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail=f"Mailbox '{clean_email}' not found.")

    local_part, domain_part = clean_email.split("@", 1)
    physical_path = os.path.join(MAIL_STORAGE, domain_part, local_part)
    disk_usage_bytes = get_dir_size_bytes(physical_path)

    return {
        "id": user["id"],
        "email": user["email"],
        "domain": user["domain"],
        "active": bool(user["active"]),
        "quota_bytes": user["quota_bytes"],
        "quota_gb": round((user["quota_bytes"] or 0) / (1024**3), 2),
        "disk_usage_bytes": disk_usage_bytes,
        "disk_usage_mb": round(disk_usage_bytes / (1024**2), 2),
        "maildir": os.path.join(MAIL_STORAGE, user["maildir"]),
        "created_at": str(user["created_at"])
    }

@admin_router.patch("/mailboxes/{email}", tags=["Admin: Mailboxes"], summary="Update Mailbox (Password / Quota / Active)")
def admin_update_mailbox(
    email: str,
    req: AdminMailboxUpdateRequest,
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_email = email.strip().lower()
    updates = []
    params: List[Any] = []

    plain_pass_return = None
    if req.password:
        plain_pass_return = req.password
        updates.append("password = %s")
        params.append(hash_dovecot_password(req.password))

    if req.quota_bytes is not None:
        updates.append("quota_bytes = %s")
        params.append(req.quota_bytes)
    elif req.quota_gb is not None:
        updates.append("quota_bytes = %s")
        params.append(int(req.quota_gb * (1024**3)))

    if req.active is not None:
        updates.append("active = %s")
        params.append(1 if req.active else 0)

    if not updates:
        raise HTTPException(status_code=400, detail="No update fields provided.")

    params.append(clean_email)
    sql = f"UPDATE users SET {', '.join(updates)} WHERE email = %s;"

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s;", (clean_email,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail=f"Mailbox '{clean_email}' not found.")
            cur.execute(sql, params)

    res = {"status": "updated", "email": clean_email}
    if plain_pass_return:
        res["password"] = plain_pass_return
    return res

@admin_router.post("/mailboxes/{email}/password", tags=["Admin: Mailboxes"], summary="Reset Mailbox Password")
def admin_reset_mailbox_password(
    email: str,
    req: AdminPasswordResetRequest,
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_email = email.strip().lower()
    plain = req.password if req.password else generate_secure_password(20)
    hashed = hash_dovecot_password(plain)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s;", (clean_email,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail=f"Mailbox '{clean_email}' not found.")
            cur.execute("UPDATE users SET password = %s WHERE email = %s;", (hashed, clean_email))

    return {
        "status": "password_reset",
        "email": clean_email,
        "new_password": plain
    }

@admin_router.delete("/mailboxes/{email}", tags=["Admin: Mailboxes"], summary="Delete Mailbox")
def admin_delete_mailbox(
    email: str,
    purge_storage: bool = Query(False, description="Purge physical Maildir files from filesystem"),
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_email = email.strip().lower()
    local_part, domain_part = clean_email.split("@", 1)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, maildir FROM users WHERE email = %s;", (clean_email,))
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail=f"Mailbox '{clean_email}' not found.")
            cur.execute("DELETE FROM users WHERE email = %s;", (clean_email,))

    purged = False
    if purge_storage:
        user_dir = os.path.join(MAIL_STORAGE, domain_part, local_part)
        if os.path.exists(user_dir):
            shutil.rmtree(user_dir, ignore_errors=True)
            purged = True

    return {
        "status": "deleted",
        "email": clean_email,
        "purged_storage": purged
    }

# ==============================================================================
# 3. ALIASES & FORWARDERS MANAGEMENT (ROOT)
# ==============================================================================

@admin_router.get("/aliases", tags=["Admin: Aliases"], summary="List All Virtual Aliases / Forwarders")
def admin_list_aliases(
    domain: Optional[str] = Query(None, description="Filter by domain name"),
    search: Optional[str] = Query(None, description="Filter source matching substring"),
    active: Optional[bool] = Query(None, description="Filter by active status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            count_sql = """
                SELECT COUNT(*) as total
                FROM aliases a
                JOIN domains d ON a.domain_id = d.id
                WHERE 1=1
            """
            params: List[Any] = []
            if domain:
                count_sql += " AND d.domain = %s"
                params.append(domain.strip().lower())
            if search:
                count_sql += " AND a.source LIKE %s"
                params.append(f"%{search.strip().lower()}%")
            if active is not None:
                count_sql += " AND a.active = %s"
                params.append(1 if active else 0)

            cur.execute(count_sql, params)
            total = cur.fetchone()["total"]

            sql = """
                SELECT a.id, a.source, a.destination, d.domain, a.active, a.created_at
                FROM aliases a
                JOIN domains d ON a.domain_id = d.id
                WHERE 1=1
            """
            q_params: List[Any] = []
            if domain:
                sql += " AND d.domain = %s"
                q_params.append(domain.strip().lower())
            if search:
                sql += " AND a.source LIKE %s"
                q_params.append(f"%{search.strip().lower()}%")
            if active is not None:
                sql += " AND a.active = %s"
                q_params.append(1 if active else 0)

            sql += " ORDER BY a.source LIMIT %s OFFSET %s;"
            q_params.extend([limit, offset])

            cur.execute(sql, q_params)
            rows = cur.fetchall()

            for r in rows:
                r["active"] = bool(r["active"])
                r["created_at"] = str(r["created_at"])
                r["is_catchall"] = r["source"].startswith("@")

            return {
                "total": total,
                "count": len(rows),
                "limit": limit,
                "offset": offset,
                "aliases": rows
            }

@admin_router.post("/aliases", status_code=status.HTTP_201_CREATED, tags=["Admin: Aliases"], summary="Create or Update an Alias / Catch-all")
def admin_create_alias(
    req: AdminAliasCreateRequest,
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    source = req.source.strip().lower()
    destination = req.destination.strip().lower()

    if "@" not in source:
        raise HTTPException(status_code=422, detail="Source must contain '@' (e.g. info@domain.com or @domain.com).")

    source_domain = source.split("@")[-1]
    if not source_domain:
        raise HTTPException(status_code=422, detail="Invalid source domain.")

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM domains WHERE domain = %s;", (source_domain,))
            dom_row = cur.fetchone()
            if not dom_row:
                if req.auto_create_domain:
                    cur.execute("INSERT INTO domains (domain, active) VALUES (%s, 1);", (source_domain,))
                    domain_id = cur.lastrowid
                    ensure_dkim_keys(source_domain)
                else:
                    raise HTTPException(status_code=404, detail=f"Domain '{source_domain}' not found. Enable auto_create_domain or add domain first.")
            else:
                domain_id = dom_row["id"]

            cur.execute("""
                INSERT INTO aliases (domain_id, source, destination, active)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE destination = %s, active = %s;
            """, (domain_id, source, destination, 1 if req.active else 0, destination, 1 if req.active else 0))

    return {
        "status": "configured",
        "source": source,
        "destination": destination,
        "domain": source_domain,
        "is_catchall": source.startswith("@"),
        "active": req.active
    }

@admin_router.get("/aliases/{source}", tags=["Admin: Aliases"], summary="Get Alias Details")
def admin_get_alias(
    source: str = Path(..., description="Source address (e.g. info@domain.com or @domain.com)"),
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_source = source.strip().lower()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT a.id, a.source, a.destination, d.domain, a.active, a.created_at
                FROM aliases a
                JOIN domains d ON a.domain_id = d.id
                WHERE a.source = %s;
            """, (clean_source,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Alias '{clean_source}' not found.")

    return {
        "id": row["id"],
        "source": row["source"],
        "destination": row["destination"],
        "domain": row["domain"],
        "is_catchall": row["source"].startswith("@"),
        "active": bool(row["active"]),
        "created_at": str(row["created_at"])
    }

@admin_router.patch("/aliases/{source}", tags=["Admin: Aliases"], summary="Update Alias")
def admin_update_alias(
    source: str,
    req: AdminAliasUpdateRequest,
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_source = source.strip().lower()
    updates = []
    params: List[Any] = []

    if req.destination is not None:
        updates.append("destination = %s")
        params.append(req.destination.strip().lower())
    if req.active is not None:
        updates.append("active = %s")
        params.append(1 if req.active else 0)

    if not updates:
        raise HTTPException(status_code=400, detail="No update fields specified.")

    params.append(clean_source)
    sql = f"UPDATE aliases SET {', '.join(updates)} WHERE source = %s;"

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM aliases WHERE source = %s;", (clean_source,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail=f"Alias '{clean_source}' not found.")
            cur.execute(sql, params)

    return {
        "status": "updated",
        "source": clean_source
    }

@admin_router.delete("/aliases/{source}", tags=["Admin: Aliases"], summary="Delete Alias")
def admin_delete_alias(
    source: str,
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_source = source.strip().lower()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM aliases WHERE source = %s;", (clean_source,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail=f"Alias '{clean_source}' not found.")
            cur.execute("DELETE FROM aliases WHERE source = %s;", (clean_source,))

    return {
        "status": "deleted",
        "source": clean_source
    }

# ==============================================================================
# 4. API TOKENS MANAGEMENT (ROOT)
# ==============================================================================

@admin_router.get("/tokens", tags=["Admin: Tokens"], summary="List All API Tokens")
def admin_list_tokens(admin: Dict[str, Any] = Depends(require_admin_token)):
    tokens = token_manager.load_tokens()
    safe_tokens = []
    for t in tokens:
        raw = t.get("token", "")
        masked = raw[:10] + "..." + raw[-4:] if len(raw) > 16 else "***"
        safe_tokens.append({
            "id": t.get("id"),
            "name": t.get("name"),
            "domain": t.get("domain"),
            "roles": t.get("roles"),
            "active": t.get("active", True),
            "created_at": t.get("created_at"),
            "expires_at": t.get("expires_at"),
            "token_masked": masked
        })
    return {"total": len(safe_tokens), "tokens": safe_tokens}

@admin_router.post("/tokens", status_code=status.HTTP_201_CREATED, tags=["Admin: Tokens"], summary="Generate New API Token (Root or Scoped)")
def admin_create_token(
    req: AdminTokenCreateRequest,
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    clean_domain = req.domain.strip().lower()
    entry = token_manager.create_token(
        name=req.name.strip(),
        domain=clean_domain,
        roles=req.roles,
        expires_in_hours=req.expires_in_hours
    )
    return {
        "status": "created",
        "token_entry": entry,
        "note": "Store this token securely; it will not be displayed in full plaintext again."
    }

@admin_router.delete("/tokens/{token_id}", tags=["Admin: Tokens"], summary="Revoke and Delete API Token")
def admin_delete_token(
    token_id: str,
    admin: Dict[str, Any] = Depends(require_admin_token)
):
    ok = token_manager.delete_token(token_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Token '{token_id}' not found.")
    return {"status": "deleted", "token_id": token_id}

# ==============================================================================
# 5. SYSTEM DIAGNOSTICS & METRICS (ROOT)
# ==============================================================================

@admin_router.get("/stats", tags=["Admin: System"], summary="Server Diagnostics & Metrics")
def admin_get_stats(admin: Dict[str, Any] = Depends(require_admin_token)):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt, SUM(CASE WHEN active=1 THEN 1 ELSE 0 END) as active FROM domains;")
            dom_stat = cur.fetchone()

            cur.execute("SELECT COUNT(*) as cnt, SUM(CASE WHEN active=1 THEN 1 ELSE 0 END) as active, SUM(quota_bytes) as total_quota FROM users;")
            user_stat = cur.fetchone()

            cur.execute("SELECT COUNT(*) as cnt, SUM(CASE WHEN source LIKE '@%' THEN 1 ELSE 0 END) as catchalls FROM aliases;")
            alias_stat = cur.fetchone()

    # Disk usage
    disk_total, disk_used, disk_free = shutil.disk_usage(MAIL_STORAGE)

    # Postfix mail queue
    queue_counts = {"active": 0, "deferred": 0, "incoming": 0, "bounce": 0}
    try:
        spool_base = "/var/spool/postfix"
        for q in ["active", "deferred", "incoming", "bounce"]:
            q_dir = os.path.join(spool_base, q)
            if os.path.exists(q_dir):
                cnt = 0
                for _, _, files in os.walk(q_dir):
                    cnt += len(files)
                queue_counts[q] = cnt
    except Exception:
        pass

    # Services check
    services = {}
    for svc in ["postfix", "dovecot", "mariadb", "rspamd"]:
        try:
            res = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True)
            services[svc] = res.stdout.strip()
        except Exception:
            services[svc] = "unknown"

    return {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": MAIL_HOST,
        "counts": {
            "domains_total": dom_stat["cnt"] or 0,
            "domains_active": dom_stat["active"] or 0,
            "mailboxes_total": user_stat["cnt"] or 0,
            "mailboxes_active": user_stat["active"] or 0,
            "aliases_total": alias_stat["cnt"] or 0,
            "catchalls_total": alias_stat["catchalls"] or 0
        },
        "storage": {
            "path": MAIL_STORAGE,
            "total_bytes": disk_total,
            "used_bytes": disk_used,
            "free_bytes": disk_free,
            "used_percent": round((disk_used / disk_total) * 100, 1),
            "allocated_quotas_bytes": user_stat["total_quota"] or 0
        },
        "postfix_queue": queue_counts,
        "services": services
    }
