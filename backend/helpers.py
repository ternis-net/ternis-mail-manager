import os
import re
import shutil
import string
import secrets
import subprocess
from typing import Optional, List, Dict, Any
from datetime import datetime
from fastapi import HTTPException, Security, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import tokens as token_manager
import verification

MAIL_STORAGE = os.getenv("MAIL_STORAGE", "/var/vmail")
DKIM_DIR = os.getenv("DKIM_DIR", "/var/lib/rspamd/dkim")
MAIL_HOST = os.getenv("MAIL_HOST", "one.mx.ternis.net")
WEBMAIL_URL = os.getenv("WEBMAIL_URL", "https://one.webmail.ternis.net")

security = HTTPBearer()

def get_current_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict[str, Any]:
    token_str = credentials.credentials.strip()

    # Priority 1: Check static environment MASTER_API_KEY
    master_env_key = os.getenv("MASTER_API_KEY", "").strip() or os.getenv("ADMIN_API_KEY", "").strip()
    if master_env_key and secrets.compare_digest(token_str, master_env_key):
        return {
            "id": "tok_master_env",
            "token": master_env_key,
            "name": "Master Environment Key",
            "domain": "*",
            "roles": ["*"],
            "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "active": True
        }

    token_data = token_manager.find_token(token_str)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked Bearer API token."
        )
    return token_data

def require_admin_token(token: Dict[str, Any] = Depends(get_current_token)) -> Dict[str, Any]:
    if token.get("domain") != "*":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: This endpoint requires root/administrator privileges (token domain '*')."
        )
    return token

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
        dkim_item["message"] = "Not found under mail._domainkey"
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
            dmarc_item["message"] = "Not found under _dmarc"
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
  'mail_smtpport' => '465',
  'mail_smtpauthtype' => 'LOGIN',
  'mail_smtpauth' => 1,
  'mail_smtpname' => '{email}',
  'mail_smtppassword' => '{password}',
  'mail_from_address' => '{local_part}',
  'mail_domain' => '{domain}',
"""

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
