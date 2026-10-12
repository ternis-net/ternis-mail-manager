import os
import re
import shutil
import string
import secrets
import subprocess
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, Security, status, Query, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from database import get_connection
import tokens as token_manager
import verification

MAIL_STORAGE = os.getenv("MAIL_STORAGE", "/var/vmail")
DKIM_DIR = os.getenv("DKIM_DIR", "/var/lib/rspamd/dkim")
MAIL_HOST = os.getenv("MAIL_HOST", "one.mx.ternis.net")
WEBMAIL_URL = os.getenv("WEBMAIL_URL", "https://one.webmail.ternis.net")

API_DESCRIPTION = """
### Ternis Mail Management REST API

The **Ternis Mail Management REST API** provides autonomous AI agents, microservices, and developers with programmatic access to create and manage mailboxes, forwarders, and DNS records on `one.mx.ternis.net`.

---

### Key Features
* 🛡️ **Cryptographic Domain Isolation:** API tokens are strictly scoped to their assigned domain (e.g. `gormo.de`). Tokens cannot read, create, modify, or delete resources outside their scope (`403 Forbidden`).
* 📦 **Automatic Provisioning:** Mailbox creation provisions MariaDB records, hashes passwords with Dovecot `SHA512-CRYPT`, and initializes the physical Maildir storage directory structure (`cur`, `new`, `tmp`) with `vmail:vmail` permissions.
* 🌐 **Automated DNS Support:** Structured endpoints return ready-to-publish MX, SPF, 2048-bit DKIM, DMARC, and Autoconfig DNS records for automated registrar/Cloudflare integration.
* 🤖 **AI-Agent Ready:** Ingest `/openapi.json` directly into LangChain, AutoGen, CrewAI, OpenAI Assistant tools, or Claude tools.

---

### Authentication
All authenticated requests must provide a Bearer token in the `Authorization` HTTP header:
```http
Authorization: Bearer <API_TOKEN>
```

---

### Mail Protocol Endpoints
Mailboxes provisioned through this API connect using the following host and port configurations:
* **IMAP (Incoming):** `one.mx.ternis.net` | Port `993` (SSL/TLS)
* **SMTP (Outgoing Submission):** `one.mx.ternis.net` | Port `465` (SSL/TLS) or Port `587` (STARTTLS)
* **POP3 (Incoming):** `one.mx.ternis.net` | Port `995` (SSL/TLS)
* **Webmail Portal:** `https://one.webmail.ternis.net`
"""

tags_metadata = [
    {
        "name": "Auth",
        "description": "Postmaster email login code verification for domain management.",
    },
    {
        "name": "Application Accounts",
        "description": "Create and manage dedicated application mail accounts (Nextcloud, WordPress, Docker backends) with ready-to-paste configurations.",
    },
    {
        "name": "Domain",
        "description": "Inspect the properties, mailbox count, forwarder count, and creation timestamp of the scoped domain.",
    },
    {
        "name": "Mailboxes",
        "description": "Create, list, reset passwords for, and delete virtual mailboxes with automatic Maildir provisioning.",
    },
    {
        "name": "Aliases",
        "description": "Manage email forwarders and domain-wide catch-all routing rules.",
    },
    {
        "name": "DNS",
        "description": "Retrieve structured DNS records (MX, SPF, 2048-bit RSA DKIM key, DMARC, and CNAMEs) for DNS automation.",
    },
    {
        "name": "Subdomains",
        "description": "Subdomain registration, mailbox creation, and live DNS zone health verification.",
    },
    {
        "name": "Health",
        "description": "API service liveness and health diagnostics.",
    },
    {
        "name": "Admin",
        "description": "Superadmin token creation and revocation (requires token scoped with `domain='*'`).",
    },
    {
        "name": "Admin: Domains",
        "description": "Root management for virtual domains: create, list, inspect, activate, delete (with cascade storage/DKIM purge), and DKIM regeneration.",
    },
    {
        "name": "Admin: Mailboxes",
        "description": "Root management for virtual mailboxes: create across any domain, list, change passwords, adjust quotas, delete, and inspect storage.",
    },
    {
        "name": "Admin: Aliases",
        "description": "Root management for virtual aliases and catch-alls: create across any domain, update routes, and delete.",
    },
    {
        "name": "Admin: Tokens",
        "description": "Root API key issuance, listing, and revocation with wildcard '*' or scoped access.",
    },
    {
        "name": "Admin: System",
        "description": "Root system observability: domain/mailbox totals, disk usage (/var/vmail), Postfix mail queues, and daemon health.",
    },
]

from admin import admin_router

app = FastAPI(
    title="Ternis Mail Management API",
    description=API_DESCRIPTION,
    version="1.0.0",
    openapi_tags=tags_metadata,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

app.include_router(admin_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

def get_current_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict[str, Any]:
    raw_token = credentials.credentials
    token_data = token_manager.find_token(raw_token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked Bearer API token."
        )
    return token_data

def verify_domain_scope(target_domain: str, token_data: Dict[str, Any]):
    token_domain = token_data.get("domain", "").lower()
    clean_target = target_domain.strip().lower()
    if token_domain != "*" and token_domain != clean_target and not clean_target.endswith("." + token_domain):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Your API token is scoped to '{token_domain}' and its subdomains, not '{clean_target}'."
        )

def generate_secure_password(length: int = 18) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(chars) for _ in range(length))

def hash_dovecot_password(password: str) -> str:
    res = subprocess.run(
        ["doveadm", "pw", "-s", "SHA512-CRYPT", "-p", password],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if res.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Password hashing failed: {res.stderr}")
    return res.stdout.strip()

# --- Pydantic Schemas ---

class MailboxCreateRequest(BaseModel):
    email: str = Field(
        ...,
        description="Email address or local part (e.g. 'agent-1' or 'support@gormo.de'). If no '@' is included, the scoped domain is automatically appended.",
        example="support"
    )
    password: Optional[str] = Field(
        None,
        description="Mailbox password. If omitted, a cryptographically strong 18-character password will be auto-generated.",
        example="OptionalSecurePassword123!"
    )
    quota_gb: Optional[float] = Field(
        10.0,
        description="Mailbox storage quota in Gigabytes (default: 10 GB)",
        example=10.0
    )

class PasswordUpdateRequest(BaseModel):
    password: Optional[str] = Field(
        None,
        description="New mailbox password. If omitted, a strong 18-character password will be auto-generated.",
        example="NewSecurePassword456!"
    )

class AliasCreateRequest(BaseModel):
    source: str = Field(
        ...,
        description="Source address or catch-all (e.g. 'info@gormo.de' or '@gormo.de')",
        example="info@gormo.de"
    )
    destination: str = Field(
        ...,
        description="Target destination email address or comma-separated forwarders",
        example="support@gormo.de"
    )

class TokenCreateRequest(BaseModel):
    name: str = Field(
        ...,
        description="Descriptive label for this token (e.g. 'Gormo Agent')",
        example="Gormo AI Agent"
    )
    domain: str = Field(
        ...,
        description="Domain to scope token to (e.g. 'gormo.de'), or '*' for superadmin",
        example="gormo.de"
    )
    roles: Optional[List[str]] = Field(
        None,
        description="List of authorized permission scopes",
        example=["mailboxes:read", "mailboxes:write", "aliases:read", "aliases:write", "dns:read"]
    )

class CodeRequest(BaseModel):
    domain: str = Field(..., description="Target domain to manage, e.g. 'ternis.net'", example="ternis.net")

class CodeVerifyRequest(BaseModel):
    domain: str = Field(..., description="Target domain to manage, e.g. 'ternis.net'", example="ternis.net")
    code: str = Field(..., description="6-digit verification code sent to postmaster", example="123456")

class AppAccountCreateRequest(BaseModel):
    domain: Optional[str] = Field(None, description="Domain to provision for. If omitted, scoped domain from token is used.", example="ternis.net")
    local_part: str = Field(..., description="Account local part, e.g. 'nextcloud' or 'app-noreply'", example="nextcloud")
    password: Optional[str] = Field(None, description="Optional custom password. Auto-generated if omitted.", example="")
    app_type: Optional[str] = Field("nextcloud", description="App preset: nextcloud, wordpress, gitlab, env, custom", example="nextcloud")
    app_name: Optional[str] = Field("Nextcloud", description="Friendly application label", example="Nextcloud")
    quota_gb: Optional[float] = Field(2.0, description="Mailbox storage quota in GB (default: 2.0)", example=2.0)

class SubdomainMailboxRequest(BaseModel):
    subdomain: str = Field(..., description="Subdomain prefix (e.g. 'cloud' or 'app')", example="cloud")
    local_part: str = Field(..., description="Mailbox local part, e.g. 'nextcloud' or 'noreply'", example="nextcloud")
    password: Optional[str] = Field(None, description="Optional custom password; auto-generated if omitted", example="")
    app_type: Optional[str] = Field("nextcloud", description="App preset: nextcloud, wordpress, gitlab, env, custom", example="nextcloud")
    app_name: Optional[str] = Field("Nextcloud Storage", description="Friendly application label", example="Nextcloud Storage")
    quota_gb: Optional[float] = Field(2.0, description="Mailbox storage quota in GB", example=2.0)

def ensure_dkim_keys(domain: str) -> Optional[str]:
    os.makedirs(DKIM_DIR, exist_ok=True)
    key_file = os.path.join(DKIM_DIR, f"{domain}.mail.key")
    txt_file = os.path.join(DKIM_DIR, f"{domain}.mail.txt")
    if not os.path.exists(key_file) or not os.path.exists(txt_file):
        try:
            cmd = ["rspamadm", "dkim_keygen", "-d", domain, "-s", "mail", "-b", "2048", "-k", key_file]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            with open(txt_file, "w") as f:
                f.write(res.stdout)
            subprocess.run(["chown", "_rspamd:_rspamd", key_file, txt_file], check=False)
            subprocess.run(["chmod", "640", key_file], check=False)
            subprocess.run(["chmod", "644", txt_file], check=False)
        except Exception as e:
            print(f"[WARN] Failed to generate DKIM key for {domain}: {e}")

    if os.path.exists(txt_file):
        with open(txt_file, "r") as f:
            raw = f.read()
            parts = re.findall(r'"([^"]*)"', raw)
            return "".join(parts)
    return None

def build_dns_records(domain: str) -> List[Dict[str, Any]]:
    dkim_val = ensure_dkim_keys(domain)
    return [
        {
            "record_type": "MX",
            "name": "@",
            "priority": 10,
            "value": f"{MAIL_HOST}.",
            "purpose": "Inbound Mail Routing"
        },
        {
            "record_type": "TXT",
            "name": "@",
            "priority": None,
            "value": "v=spf1 ip4:134.255.225.220 mx -all",
            "purpose": "Sender Policy Framework (SPF)"
        },
        {
            "record_type": "TXT",
            "name": "mail._domainkey",
            "priority": None,
            "value": dkim_val if dkim_val else "DKIM not generated yet",
            "purpose": "DKIM Public Key"
        },
        {
            "record_type": "TXT",
            "name": "_dmarc",
            "priority": None,
            "value": "v=DMARC1; p=quarantine; sp=quarantine; pct=100",
            "purpose": "DMARC Alignment Policy"
        },
        {
            "record_type": "TXT",
            "name": "_postmaster",
            "priority": None,
            "value": "admin@yourdomain.com",
            "purpose": "Custom Login Verification Recipient (Optional)"
        },
        {
            "record_type": "CNAME",
            "name": "autoconfig",
            "priority": None,
            "value": f"{MAIL_HOST}.",
            "purpose": "Thunderbird Autoconfig"
        },
        {
            "record_type": "CNAME",
            "name": "autodiscover",
            "priority": None,
            "value": f"{MAIL_HOST}.",
            "purpose": "Outlook Autodiscover"
        }
    ]

def check_live_dns(domain: str) -> Dict[str, Any]:
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    dkim_expected = ensure_dkim_keys(domain)
    records = []

    # 1. MX
    mx_item = {
        "record_type": "MX",
        "name": "@",
        "expected": f"10 {MAIL_HOST}.",
        "purpose": "Inbound Mail Routing"
    }
    try:
        ans = resolver.resolve(domain, 'MX')
        hosts = [f"{r.preference} {str(r.exchange).rstrip('.')}." for r in ans]
        has_mx = any(MAIL_HOST in h for h in hosts)
        mx_item["detected"] = ", ".join(hosts)
        mx_item["status"] = "ok" if has_mx else "warning"
        mx_item["message"] = "Active" if has_mx else "Different MX server detected"
    except Exception:
        mx_item["detected"] = None
        mx_item["status"] = "missing"
        mx_item["message"] = "Not found in DNS zone"
    records.append(mx_item)

    # 2. SPF
    spf_item = {
        "record_type": "TXT",
        "name": "@",
        "expected": "v=spf1 ip4:134.255.225.220 mx -all",
        "purpose": "Sender Policy Framework"
    }
    try:
        ans = resolver.resolve(domain, 'TXT')
        spfs = [str(r).strip('\"') for r in ans if 'v=spf1' in str(r)]
        if spfs:
            val = spfs[0]
            has_ip = ("134.255.225.220" in val or "mx" in val)
            spf_item["detected"] = val
            spf_item["status"] = "ok" if has_ip else "warning"
            spf_item["message"] = "Active" if has_ip else "IP or MX not authorized"
        else:
            spf_item["detected"] = None
            spf_item["status"] = "missing"
            spf_item["message"] = "No SPF record found"
    except Exception:
        spf_item["detected"] = None
        spf_item["status"] = "missing"
        spf_item["message"] = "Not found in DNS zone"
    records.append(spf_item)

    # 3. DKIM
    dkim_item = {
        "record_type": "TXT",
        "name": "mail._domainkey",
        "expected": dkim_expected if dkim_expected else "DKIM public key",
        "purpose": "DKIM Public Key"
    }
    try:
        ans = resolver.resolve(f"mail._domainkey.{domain}", 'TXT')
        dkims = [str(r).strip('\"') for r in ans if 'v=DKIM1' in str(r) or 'p=' in str(r)]
        if dkims:
            dkim_item["detected"] = dkims[0]
            dkim_item["status"] = "ok"
            dkim_item["message"] = "Active"
        else:
            dkim_item["detected"] = None
            dkim_item["status"] = "missing"
            dkim_item["message"] = "Not found under mail._domainkey"
    except Exception:
        dkim_item["detected"] = None
        dkim_item["status"] = "missing"
        dkim_item["message"] = "Not found in DNS zone"
    records.append(dkim_item)

    # 4. DMARC
    dmarc_item = {
        "record_type": "TXT",
        "name": "_dmarc",
        "expected": "v=DMARC1; p=quarantine; sp=quarantine; pct=100",
        "purpose": "DMARC Alignment Policy"
    }
    try:
        ans = resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarcs = [str(r).strip('\"') for r in ans if 'v=DMARC1' in str(r)]
        if dmarcs:
            dmarc_item["detected"] = dmarcs[0]
            dmarc_item["status"] = "ok"
            dmarc_item["message"] = "Active"
        else:
            dmarc_item["detected"] = None
            dmarc_item["status"] = "missing"
            dmarc_item["message"] = "No DMARC record found"
    except Exception:
        dmarc_item["detected"] = None
        dmarc_item["status"] = "missing"
        dmarc_item["message"] = "Not found in DNS zone"
    records.append(dmarc_item)

    # 5. Autoconfig
    ac_item = {
        "record_type": "CNAME",
        "name": "autoconfig",
        "expected": f"{MAIL_HOST}.",
        "purpose": "Thunderbird Autoconfig"
    }
    try:
        ans = resolver.resolve(f"autoconfig.{domain}", 'CNAME')
        targets = [str(r.target).rstrip('.') for r in ans]
        ac_item["detected"] = targets[0]
        ac_item["status"] = "ok"
        ac_item["message"] = "Active"
    except Exception:
        try:
            a_ans = resolver.resolve(f"autoconfig.{domain}", 'A')
            ac_item["detected"] = ", ".join(str(r) for r in a_ans)
            ac_item["status"] = "ok"
            ac_item["message"] = "Active"
        except Exception:
            ac_item["detected"] = None
            ac_item["status"] = "missing"
            ac_item["message"] = "Not found in DNS zone"
    records.append(ac_item)

    # 6. Autodiscover
    ad_item = {
        "record_type": "CNAME",
        "name": "autodiscover",
        "expected": f"{MAIL_HOST}.",
        "purpose": "Outlook Autodiscover"
    }
    try:
        ans = resolver.resolve(f"autodiscover.{domain}", 'CNAME')
        targets = [str(r.target).rstrip('.') for r in ans]
        ad_item["detected"] = targets[0]
        ad_item["status"] = "ok"
        ad_item["message"] = "Active"
    except Exception:
        try:
            a_ans = resolver.resolve(f"autodiscover.{domain}", 'A')
            ad_item["detected"] = ", ".join(str(r) for r in a_ans)
            ad_item["status"] = "ok"
            ad_item["message"] = "Active"
        except Exception:
            ad_item["detected"] = None
            ad_item["status"] = "missing"
            ad_item["message"] = "Not found in DNS zone"
    records.append(ad_item)

    # 7. Postmaster Login Recipient TXT (Optional)
    pm_email, pm_source, pm_record = verification.resolve_postmaster_recipient(domain)
    pm_item = {
        "record_type": "TXT",
        "name": "_postmaster",
        "expected": "admin@yourdomain.com",
        "purpose": "Custom Login Verification Recipient"
    }
    if pm_source == "dns_record":
        pm_item["detected"] = pm_email
        pm_item["status"] = "ok"
        pm_item["message"] = f"Custom: {pm_email} (via {pm_record})"
    else:
        pm_item["detected"] = None
        pm_item["status"] = "optional"
        pm_item["message"] = f"Default: postmaster@{domain} (no custom TXT set)"
    records.append(pm_item)

    all_ok = all(r["status"] in ("ok", "optional") for r in records)
    return {
        "domain": domain,
        "checked_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "all_healthy": all_ok,
        "records": records
    }

def generate_app_configs(email: str, password: str, domain: str, local_part: str, app_name: str = "App") -> Dict[str, Any]:
    nextcloud_config = f"""  'mail_smtpmode' => 'smtp',
  'mail_smtpsecure' => 'ssl',
  'mail_smtphost' => '{MAIL_HOST}',
  'mail_smtpport' => 465,
  'mail_smtpauthtype' => 'LOGIN',
  'mail_smtpauth' => 1,
  'mail_smtpname' => '{email}',
  'mail_smtppassword' => '{password}',
  'mail_from_address' => '{local_part}',
  'mail_domain' => '{domain}',"""

    env_config = f"""# SMTP Configuration ({MAIL_HOST})
MAIL_MAILER=smtp
MAIL_HOST={MAIL_HOST}
MAIL_PORT=465
MAIL_ENCRYPTION=tls
MAIL_USERNAME={email}
MAIL_PASSWORD={password}
MAIL_FROM_ADDRESS={email}
MAIL_FROM_NAME="{app_name} ({domain})"
"""

    starttls_env = f"""# Alternative STARTTLS Submission (Port 587)
MAIL_MAILER=smtp
MAIL_HOST={MAIL_HOST}
MAIL_PORT=587
MAIL_ENCRYPTION=starttls
MAIL_USERNAME={email}
MAIL_PASSWORD={password}
MAIL_FROM_ADDRESS={email}
"""

    return {
        "nextcloud": {
            "ui_settings": {
                "send_mode": "SMTP",
                "encryption": "SSL/TLS",
                "server_address": MAIL_HOST,
                "port": 465,
                "authentication": "Credentials required (Yes)",
                "authentication_type": "LOGIN",
                "username": email,
                "password": password,
                "from_address": local_part,
                "from_domain": domain
            },
            "php_config": nextcloud_config
        },
        "env": env_config,
        "env_starttls": starttls_env
    }

# --- Routes ---

# --- Auth & Postmaster Login Routes ---

@app.post("/api/v1/auth/request-code", tags=["Auth"], summary="Request Postmaster Login Code")
def request_login_code(req: CodeRequest, request: Request):
    clean_domain = req.domain.strip().lower()
    if not clean_domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM domains WHERE domain = %s AND active = 1;", (clean_domain,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail=f"Domain '{clean_domain}' is not registered or active.")

    client_ip = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for") or (request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    ok, msg, meta = verification.request_verification_code(clean_domain, client_ip)
    if not ok:
        raise HTTPException(status_code=429 if "wait" in msg.lower() else 500, detail=msg)

    return {
        "status": "ok",
        "message": msg,
        "domain": clean_domain,
        "target": meta.get("recipient"),
        "target_masked": meta.get("recipient_masked"),
        "target_type": meta.get("source"),
        "record_name": meta.get("record_name")
    }

@app.post("/api/v1/auth/verify-code", tags=["Auth"], summary="Verify Postmaster Login Code")
def verify_login_code(req: CodeVerifyRequest):
    clean_domain = req.domain.strip().lower()
    ok, msg = verification.verify_code(clean_domain, req.code)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    # Issue 24-hour scoped session token
    token_entry = token_manager.create_token(
        name=f"Web Session ({clean_domain})",
        domain=clean_domain,
        roles=["mailboxes:read", "mailboxes:write", "aliases:read"],
        expires_in_hours=24
    )

    return {
        "status": "ok",
        "token": token_entry["token"],
        "domain": clean_domain,
        "expires_in": 86400,
        "message": f"Successfully verified as postmaster for {clean_domain}."
    }

@app.get("/api/v1/auth/session", tags=["Auth"], summary="Check Active Session")
def check_session(token: Dict[str, Any] = Depends(get_current_token)):
    return {
        "valid": True,
        "domain": token["domain"],
        "name": token.get("name"),
        "roles": token.get("roles", [])
    }

@app.get("/api/v1/health", tags=["Health"], summary="API Health Check")
def health_check():
    return {"status": "ok", "service": "ternis-mail-api", "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/v1/domain", tags=["Domain"], summary="Get Current Scoped Domain Info")
def get_domain_info(token: Dict[str, Any] = Depends(get_current_token)):
    token_domain = token["domain"]
    with get_connection() as conn:
        with conn.cursor() as cur:
            if token_domain == "*":
                cur.execute("SELECT id, domain, active, created_at FROM domains ORDER BY domain;")
                rows = cur.fetchall()
                return {"mode": "superadmin", "domains": rows}
            
            cur.execute("SELECT id, domain, active, created_at FROM domains WHERE domain = %s;", (token_domain,))
            dom = cur.fetchone()
            if not dom:
                raise HTTPException(status_code=404, detail=f"Domain '{token_domain}' not found in mail system.")
            
            cur.execute("SELECT COUNT(*) as cnt FROM users WHERE domain_id = %s;", (dom["id"],))
            user_cnt = cur.fetchone()["cnt"]
            
            cur.execute("SELECT COUNT(*) as cnt FROM aliases WHERE domain_id = %s;", (dom["id"],))
            alias_cnt = cur.fetchone()["cnt"]

            return {
                "domain": dom["domain"],
                "active": bool(dom["active"]),
                "mailbox_count": user_cnt,
                "alias_count": alias_cnt,
                "created_at": str(dom["created_at"])
            }

@app.get("/api/v1/mailboxes", tags=["Mailboxes"], summary="List All Mailboxes")
def list_mailboxes(token: Dict[str, Any] = Depends(get_current_token)):
    token_domain = token["domain"]
    with get_connection() as conn:
        with conn.cursor() as cur:
            if token_domain == "*":
                cur.execute("""
                    SELECT u.id, u.email, u.active, ROUND(u.quota_bytes/1073741824, 2) as quota_gb, u.created_at
                    FROM users u ORDER BY u.email;
                """)
            else:
                cur.execute("""
                    SELECT u.id, u.email, u.active, ROUND(u.quota_bytes/1073741824, 2) as quota_gb, u.created_at
                    FROM users u
                    JOIN domains d ON u.domain_id = d.id
                    WHERE d.domain = %s
                    ORDER BY u.email;
                """, (token_domain,))
            rows = cur.fetchall()
            for r in rows:
                r["active"] = bool(r["active"])
                r["created_at"] = str(r["created_at"])
            return {"mailboxes": rows}

@app.post("/api/v1/mailboxes", status_code=status.HTTP_201_CREATED, tags=["Mailboxes"], summary="Create a Mailbox")
def create_mailbox(req: MailboxCreateRequest, token: Dict[str, Any] = Depends(get_current_token)):
    raw_email = req.email.strip().lower()
    token_domain = token["domain"]

    if "@" in raw_email:
        local_part, domain_part = raw_email.split("@", 1)
    else:
        if token_domain == "*":
            raise HTTPException(status_code=400, detail="Superadmin token must provide full email with '@domain'.")
        local_part = raw_email
        domain_part = token_domain

    verify_domain_scope(domain_part, token)
    full_email = f"{local_part}@{domain_part}"

    if not re.match(r'^[a-z0-9._-]+$', local_part):
        raise HTTPException(status_code=422, detail="Invalid characters in mailbox local part.")

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM domains WHERE domain = %s;", (domain_part,))
            dom_row = cur.fetchone()
            if not dom_row:
                raise HTTPException(status_code=404, detail=f"Domain '{domain_part}' does not exist.")
            domain_id = dom_row["id"]

            cur.execute("SELECT id FROM users WHERE email = %s;", (full_email,))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail=f"Mailbox '{full_email}' already exists.")

            plain_password = req.password if req.password else generate_secure_password()
            hashed_password = hash_dovecot_password(plain_password)
            quota_bytes = int((req.quota_gb or 10.0) * 1024 * 1024 * 1024)
            maildir_rel = f"{domain_part}/{local_part}/"

            cur.execute("""
                INSERT INTO users (domain_id, email, password, maildir, quota_bytes, active)
                VALUES (%s, %s, %s, %s, %s, 1);
            """, (domain_id, full_email, hashed_password, maildir_rel, quota_bytes))

    # Provision storage directory
    user_dir = os.path.join(MAIL_STORAGE, domain_part, local_part)
    for folder in ["cur", "new", "tmp"]:
        os.makedirs(os.path.join(user_dir, "Maildir", folder), exist_ok=True)
    subprocess.run(["chown", "-R", "vmail:vmail", os.path.join(MAIL_STORAGE, domain_part)])
    subprocess.run(["chmod", "-R", "770", os.path.join(MAIL_STORAGE, domain_part)])

    return {
        "status": "created",
        "message": f"Mailbox {full_email} created successfully.",
        "mailbox": {
            "email": full_email,
            "password": plain_password,
            "quota_gb": req.quota_gb or 10.0,
            "imap": {
                "server": MAIL_HOST,
                "port": 993,
                "ssl": True,
                "username": full_email
            },
            "smtp": {
                "server": MAIL_HOST,
                "ssl_port": 465,
                "starttls_port": 587,
                "username": full_email
            },
            "webmail_url": WEBMAIL_URL
        }
    }

@app.post("/api/v1/app-accounts", status_code=status.HTTP_201_CREATED, tags=["Application Accounts"], summary="Create an Application Mail Account")
def create_app_account(req: AppAccountCreateRequest, token: Dict[str, Any] = Depends(get_current_token)):
    token_domain = token["domain"]
    target_domain = req.domain.strip().lower() if req.domain else (token_domain if token_domain != "*" else None)
    if not target_domain:
        raise HTTPException(status_code=400, detail="Target domain must be specified.")

    clean_local = req.local_part.strip().lower()
    full_email = f"{clean_local}@{target_domain}"

    # Delegate to create_mailbox
    mailbox_req = MailboxCreateRequest(
        email=full_email,
        password=req.password,
        quota_gb=req.quota_gb or 2.0
    )
    result = create_mailbox(mailbox_req, token)

    plain_password = result["mailbox"]["password"]
    app_configs = generate_app_configs(
        email=full_email,
        password=plain_password,
        domain=target_domain,
        local_part=clean_local,
        app_name=req.app_name or "Application"
    )

    result["app_meta"] = {
        "app_type": req.app_type or "custom",
        "app_name": req.app_name or "Application",
        "local_part": clean_local,
        "domain": target_domain
    }
    result["configs"] = app_configs
    return result

@app.post("/api/v1/mailboxes/{email}/password", tags=["Mailboxes"], summary="Reset Mailbox Password")
def update_mailbox_password(email: str, req: PasswordUpdateRequest, token: Dict[str, Any] = Depends(get_current_token)):
    clean_email = email.strip().lower()
    if "@" not in clean_email:
        raise HTTPException(status_code=400, detail="Email must contain '@'.")
    _, domain_part = clean_email.split("@", 1)
    verify_domain_scope(domain_part, token)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s;", (clean_email,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail=f"Mailbox '{clean_email}' not found.")

            new_plain = req.password if req.password else generate_secure_password()
            new_hashed = hash_dovecot_password(new_plain)

            cur.execute("UPDATE users SET password = %s WHERE email = %s;", (new_hashed, clean_email))

    return {
        "status": "updated",
        "email": clean_email,
        "new_password": new_plain,
        "message": "Mailbox password successfully updated."
    }

@app.delete("/api/v1/mailboxes/{email}", tags=["Mailboxes"], summary="Delete a Mailbox")
def delete_mailbox(email: str, purge: bool = Query(False, description="Purge physical storage directory from disk"), token: Dict[str, Any] = Depends(get_current_token)):
    clean_email = email.strip().lower()
    if "@" not in clean_email:
        raise HTTPException(status_code=400, detail="Email must contain '@'.")
    _, domain_part = clean_email.split("@", 1)
    verify_domain_scope(domain_part, token)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, maildir FROM users WHERE email = %s;", (clean_email,))
            user_row = cur.fetchone()
            if not user_row:
                raise HTTPException(status_code=404, detail=f"Mailbox '{clean_email}' not found.")

            cur.execute("DELETE FROM users WHERE email = %s;", (clean_email,))

    purged = False
    if purge and user_row.get("maildir"):
        storage_path = os.path.realpath(os.path.join(MAIL_STORAGE, user_row["maildir"]))
        # Safety check: ensure path is inside MAIL_STORAGE and not root or domain root
        if storage_path.startswith(MAIL_STORAGE) and storage_path != MAIL_STORAGE and os.path.exists(storage_path):
            shutil.rmtree(storage_path, ignore_errors=True)
            purged = True

    return {
        "status": "deleted",
        "email": clean_email,
        "purged_storage": purged
    }

@app.get("/api/v1/aliases", tags=["Aliases"], summary="List All Aliases")
def list_aliases(token: Dict[str, Any] = Depends(get_current_token)):
    token_domain = token["domain"]
    with get_connection() as conn:
        with conn.cursor() as cur:
            if token_domain == "*":
                cur.execute("SELECT id, source, destination, active, created_at FROM aliases ORDER BY source;")
            else:
                cur.execute("""
                    SELECT a.id, a.source, a.destination, a.active, a.created_at
                    FROM aliases a
                    JOIN domains d ON a.domain_id = d.id
                    WHERE d.domain = %s
                    ORDER BY a.source;
                """, (token_domain,))
            rows = cur.fetchall()
            for r in rows:
                r["active"] = bool(r["active"])
                r["created_at"] = str(r["created_at"])
            return {"aliases": rows}

@app.post("/api/v1/aliases", tags=["Aliases"], summary="Create or Update an Alias / Catch-all")
def create_alias(req: AliasCreateRequest, token: Dict[str, Any] = Depends(get_current_token)):
    source = req.source.strip().lower()
    destination = req.destination.strip().lower()
    token_domain = token["domain"]

    if "@" not in source:
        raise HTTPException(status_code=400, detail="Source must contain '@' (e.g. info@domain.com or @domain.com)")

    source_domain = source.split("@")[-1]
    verify_domain_scope(source_domain, token)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM domains WHERE domain = %s;", (source_domain,))
            dom_row = cur.fetchone()
            if not dom_row:
                raise HTTPException(status_code=404, detail=f"Domain '{source_domain}' not found.")
            domain_id = dom_row["id"]

            cur.execute("""
                INSERT INTO aliases (domain_id, source, destination, active)
                VALUES (%s, %s, %s, 1)
                ON DUPLICATE KEY UPDATE destination = %s, active = 1;
            """, (domain_id, source, destination, destination))

    return {
        "status": "configured",
        "source": source,
        "destination": destination,
        "message": f"Alias {source} -> {destination} active."
    }

@app.delete("/api/v1/aliases/{source}", tags=["Aliases"], summary="Delete an Alias")
def delete_alias(source: str, token: Dict[str, Any] = Depends(get_current_token)):
    clean_source = source.strip().lower()
    if "@" not in clean_source:
        raise HTTPException(status_code=400, detail="Source must contain '@'.")
    source_domain = clean_source.split("@")[-1]
    verify_domain_scope(source_domain, token)

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

@app.get("/api/v1/dns", tags=["DNS"], summary="Get Recommended DNS Records for Domain")
def get_dns_records(domain: Optional[str] = None, token: Dict[str, Any] = Depends(get_current_token)):
    token_domain = token["domain"]
    target_domain = domain.strip().lower() if domain else token_domain

    if target_domain == "*":
        raise HTTPException(status_code=400, detail="Specify domain query parameter for DNS records.")

    verify_domain_scope(target_domain, token)
    records = build_dns_records(target_domain)

    return {
        "domain": target_domain,
        "server_ip": "134.255.225.220",
        "mail_server_hostname": MAIL_HOST,
        "records": records
    }

@app.get("/api/v1/dns/status", tags=["DNS"], summary="Live DNS Zone Status & Verification")
def get_live_dns_status(domain: Optional[str] = None, token: Dict[str, Any] = Depends(get_current_token)):
    token_domain = token["domain"]
    target_domain = domain.strip().lower() if domain else token_domain

    if target_domain == "*":
        raise HTTPException(status_code=400, detail="Specify domain query parameter for DNS status.")

    verify_domain_scope(target_domain, token)
    return check_live_dns(target_domain)

@app.get("/api/v1/subdomains", tags=["Subdomains"], summary="List Subdomains for Scoped Domain")
def list_subdomains(token: Dict[str, Any] = Depends(get_current_token)):
    token_domain = token["domain"]
    with get_connection() as conn:
        with conn.cursor() as cur:
            if token_domain == "*":
                cur.execute("SELECT id, domain, active, created_at FROM domains WHERE domain LIKE '%.%' ORDER BY domain;")
            else:
                cur.execute("SELECT id, domain, active, created_at FROM domains WHERE domain LIKE %s ORDER BY domain;", (f"%.{token_domain}",))
            rows = cur.fetchall()
            for r in rows:
                r["active"] = bool(r["active"])
                r["created_at"] = str(r["created_at"])
            return {"subdomains": rows}

@app.post("/api/v1/subdomains/mailbox", status_code=status.HTTP_201_CREATED, tags=["Subdomains"], summary="Create Subdomain Mailbox and Generate DNS Records")
def create_subdomain_mailbox(req: SubdomainMailboxRequest, token: Dict[str, Any] = Depends(get_current_token)):
    token_domain = token["domain"]
    clean_sub = req.subdomain.strip().lower()
    if clean_sub.endswith("." + token_domain):
        full_subdomain = clean_sub
    elif "." in clean_sub:
        full_subdomain = clean_sub
    else:
        full_subdomain = f"{clean_sub}.{token_domain}"

    verify_domain_scope(full_subdomain, token)
    clean_local = req.local_part.strip().lower()

    # Ensure subdomain exists in MariaDB domains table
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM domains WHERE domain = %s;", (full_subdomain,))
            dom = cur.fetchone()
            if not dom:
                cur.execute("INSERT INTO domains (domain, active) VALUES (%s, 1);", (full_subdomain,))
                dom_id = cur.lastrowid
                # Automatically add default catchall / postmaster forwarder to parent domain
                cur.execute("""
                    INSERT INTO aliases (domain_id, source, destination, active)
                    VALUES (%s, %s, %s, 1)
                    ON DUPLICATE KEY UPDATE destination = VALUES(destination);
                """, (dom_id, f"@{full_subdomain}", f"postmaster@{token_domain}"))

    # Generate DKIM key if missing
    ensure_dkim_keys(full_subdomain)

    # Provision mailbox
    mb_req = AppAccountCreateRequest(
        domain=full_subdomain,
        local_part=clean_local,
        password=req.password,
        app_type=req.app_type,
        app_name=req.app_name,
        quota_gb=req.quota_gb
    )
    result = create_app_account(mb_req, token)

    # Attach required DNS records and live status check
    result["dns_records"] = build_dns_records(full_subdomain)
    result["live_dns"] = check_live_dns(full_subdomain)
    return result

# --- Superadmin Token Management Endpoints ---

@app.get("/api/v1/admin/tokens", tags=["Admin"], summary="List API Tokens (Superadmin)")
def admin_list_tokens(token: Dict[str, Any] = Depends(get_current_token)):
    if token.get("domain") != "*":
        raise HTTPException(status_code=403, detail="Superadmin access required.")
    all_tokens = token_manager.load_tokens()
    # Mask secrets in listing
    result = []
    for t in all_tokens:
        result.append({
            "id": t.get("id"),
            "name": t.get("name"),
            "domain": t.get("domain"),
            "created_at": t.get("created_at"),
            "active": t.get("active"),
            "token_preview": t.get("token", "")[:12] + "..."
        })
    return {"tokens": result}

@app.post("/api/v1/admin/tokens", tags=["Admin"], summary="Create API Token (Superadmin)")
def admin_create_token(req: TokenCreateRequest, token: Dict[str, Any] = Depends(get_current_token)):
    if token.get("domain") != "*":
        raise HTTPException(status_code=403, detail="Superadmin access required.")
    new_token = token_manager.create_token(req.name, req.domain, req.roles)
    return {
        "status": "created",
        "token_data": new_token
    }

@app.delete("/api/v1/admin/tokens/{token_id}", tags=["Admin"], summary="Revoke API Token (Superadmin)")
def admin_revoke_token(token_id: str, token: Dict[str, Any] = Depends(get_current_token)):
    if token.get("domain") != "*":
        raise HTTPException(status_code=403, detail="Superadmin access required.")
    revoked = token_manager.revoke_token(token_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="Token not found.")
    return {"status": "revoked", "token_id": token_id}

@app.get("/mail/config-v1.1.xml", include_in_schema=False)
@app.get("/.well-known/autoconfig/mail/config-v1.1.xml", include_in_schema=False)
def dynamic_autoconfig_xml(request: Request):
    host = request.headers.get("host", "ternis.net").split(":")[0].lower()
    domain = re.sub(r'^(autoconfig|autodiscover|mail|webmail)\.', '', host) or "ternis.net"
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="{domain}">
    <domain>{domain}</domain>
    <displayName>{domain} Mail Service</displayName>
    <displayShortName>{domain}</displayShortName>
    <incomingServer type="imap">
      <hostname>one.mx.ternis.net</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>one.mx.ternis.net</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>one.mx.ternis.net</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
    <outgoingServer type="smtp">
      <hostname>one.mx.ternis.net</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>"""
    return Response(content=xml, media_type="application/xml")

@app.get("/autodiscover/autodiscover.xml", include_in_schema=False)
@app.post("/autodiscover/autodiscover.xml", include_in_schema=False)
def dynamic_autodiscover_xml(request: Request):
    xml = """<?xml version="1.0" encoding="utf-8" ?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>one.mx.ternis.net</Server>
        <Port>993</Port>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>one.mx.ternis.net</Server>
        <Port>465</Port>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>"""
    return Response(content=xml, media_type="application/xml")

