import os
import re
import time
import secrets
import smtplib
from email.message import EmailMessage
from typing import Tuple, Dict, Any, Optional
import dns.resolver
from database import get_connection

SMTP_HOST = os.getenv("SMTP_HOST", "127.0.0.1")
SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))
MAIL_HOST = os.getenv("MAIL_HOST", "one.mx.ternis.net")
SMTP_FROM = os.getenv("SMTP_FROM_EMAIL", f"noreply@{MAIL_HOST}")

CODE_EXPIRY_SECONDS = 900  # 15 minutes
MIN_REQUEST_INTERVAL_SECONDS = 30  # At least 30 seconds between requests for same domain

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

def extract_email_from_txt(txt: str, strict_tag: bool = False) -> Optional[str]:
    """
    Extracts an email address from a DNS TXT record string.
    - If strict_tag is True (apex domain): requires explicit tag like postmaster=..., mailto:..., v=postmaster1
    - If strict_tag is False (_postmaster.<domain>): accepts direct email or tagged email
    """
    txt = txt.strip().strip('"\'')
    if not strict_tag:
        if EMAIL_REGEX.match(txt):
            return txt.lower()
        if txt.lower().startswith('mailto:'):
            candidate = txt[7:].strip()
            if EMAIL_REGEX.match(candidate):
                return candidate.lower()

    # Search for tag, e.g. postmaster=admin@domain.com, mailto:admin@domain.com, v=postmaster1; email=admin@...
    m = re.search(r'(?:mailto:|email=|postmaster=|ternis-postmaster=)\s*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', txt, re.IGNORECASE)
    if m and EMAIL_REGEX.match(m.group(1)):
        return m.group(1).lower()

    if not strict_tag:
        m2 = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', txt)
        if m2 and EMAIL_REGEX.match(m2.group(1)):
            return m2.group(1).lower()

    return None

def resolve_postmaster_recipient(domain: str) -> Tuple[str, str, str]:
    """
    Resolves the destination email address for postmaster login verification.
    1. Checks DNS TXT at _postmaster.<domain>
    2. Checks DNS TXT at _ternis-postmaster.<domain>
    3. Checks DNS TXT at <domain> for postmaster tag
    4. For subdomains, checks parent domain's _postmaster.<parent>
    5. Falls back to postmaster@<domain>

    Returns: (recipient_email, resolution_type, record_name)
    where resolution_type is "dns_record" or "default"
    """
    clean_domain = domain.strip().lower()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.5
    resolver.lifetime = 2.5

    candidates = [
        (f"_postmaster.{clean_domain}", False),
        (f"_ternis-postmaster.{clean_domain}", False),
        (clean_domain, True)
    ]

    parts = clean_domain.split('.')
    if len(parts) > 2:
        parent_domain = '.'.join(parts[1:])
        candidates.append((f"_postmaster.{parent_domain}", False))

    for host, strict in candidates:
        try:
            ans = resolver.resolve(host, 'TXT')
            for rdata in ans:
                txt = b"".join(rdata.strings).decode('utf-8', errors='ignore').strip()
                email = extract_email_from_txt(txt, strict_tag=strict)
                if email:
                    return email, "dns_record", host
        except Exception:
            continue

    default_email = f"postmaster@{clean_domain}"
    return default_email, "default", f"postmaster@{clean_domain}"

def mask_email(email: str) -> str:
    """Mask email for privacy in user-facing responses, e.g. ad***n@example.com"""
    if not email or "@" not in email:
        return email
    local, dom = email.split("@", 1)
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        visible_head = local[:2] if len(local) > 4 else local[:1]
        visible_tail = local[-1]
        stars = "*" * max(1, min(len(local) - len(visible_head) - len(visible_tail), 5))
        masked_local = f"{visible_head}{stars}{visible_tail}"
    return f"{masked_local}@{dom}"

def request_verification_code(domain: str, client_ip: str = "unknown") -> Tuple[bool, str, Dict[str, Any]]:
    domain = domain.strip().lower()
    now = int(time.time())

    recipient, resolution_type, record_name = resolve_postmaster_recipient(domain)
    recipient_masked = mask_email(recipient)

    meta: Dict[str, Any] = {
        "domain": domain,
        "recipient": recipient,
        "recipient_masked": recipient_masked,
        "source": resolution_type,
        "record_name": record_name
    }

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT created_at FROM verification_codes WHERE domain = %s;", (domain,))
            row = cur.fetchone()
            if row and (now - row["created_at"]) < MIN_REQUEST_INTERVAL_SECONDS:
                remaining = int(MIN_REQUEST_INTERVAL_SECONDS - (now - row["created_at"]))
                return False, f"Please wait {remaining} seconds before requesting a new code.", meta

            code = f"{secrets.randbelow(1000000):06d}"
            expires_at = now + CODE_EXPIRY_SECONDS

            cur.execute("""
                INSERT INTO verification_codes (domain, code, attempts, expires_at, created_at, requester_ip)
                VALUES (%s, %s, 0, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    code = VALUES(code),
                    attempts = 0,
                    expires_at = VALUES(expires_at),
                    created_at = VALUES(created_at),
                    requester_ip = VALUES(requester_ip);
            """, (domain, code, expires_at, now, client_ip))

    subject = f"[{code}] Login Verification Code for {domain}"

    source_desc = f"DNS TXT record ({record_name})" if resolution_type == "dns_record" else f"Default postmaster mailbox (postmaster@{domain})"

    text_body = f"""Hello,

You received this email because a login code was requested to manage Application Mail Accounts for '{domain}' on {MAIL_HOST}.

Your 6-digit verification login code is:

    {code}

This code is valid for 15 minutes.
Requested from IP: {client_ip}
Destination resolved via: {source_desc}

If you did not initiate this request, you can safely ignore this email.

---
Ternis Mail Gateway ({MAIL_HOST})
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; margin: 0; padding: 24px; color: #334155; }}
  .container {{ max-width: 540px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 16px rgba(0,0,0,0.1); border: 1px solid #e2e8f0; }}
  .header {{ background: #0284c7; padding: 24px 32px; color: #ffffff; }}
  .header h2 {{ margin: 0; font-size: 20px; font-weight: 600; letter-spacing: -0.02em; }}
  .header p {{ margin: 4px 0 0; font-size: 13px; color: #bae6fd; }}
  .content {{ padding: 32px; }}
  .intro {{ font-size: 15px; color: #334155; line-height: 1.5; margin-bottom: 24px; }}
  .code-box {{ background: #f8fafc; border: 2px dashed #0284c7; border-radius: 10px; padding: 20px; text-align: center; margin: 24px 0; }}
  .code-title {{ font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-bottom: 8px; }}
  .code-value {{ font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 36px; font-weight: 700; color: #0f172a; letter-spacing: 8px; }}
  .meta {{ font-size: 13px; color: #64748b; line-height: 1.6; margin-top: 24px; border-top: 1px solid #f1f5f9; padding-top: 16px; }}
  .footer {{ background: #f8fafc; padding: 16px 32px; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h2>Ternis Mail Gateway</h2>
    <p>Application Mail Management &bull; {MAIL_HOST}</p>
  </div>
  <div class="content">
    <p class="intro">
      A sign-in request was initiated to manage application mailboxes (e.g. Nextcloud, web backends) for domain <strong>{domain}</strong>.
    </p>
    <div class="code-box">
      <div class="code-title">Your 6-Digit Login Code</div>
      <div class="code-value">{code}</div>
    </div>
    <div class="meta">
      &bull; <strong>Validity:</strong> 15 minutes<br>
      &bull; <strong>Destination:</strong> {recipient_masked} ({source_desc})<br>
      &bull; <strong>Requested from IP:</strong> {client_ip}<br>
      &bull; If you did not request this code, no changes have been made and you can safely ignore this message.
    </div>
  </div>
  <div class="footer">
    {MAIL_HOST} &bull; Automated Mail System Notification
  </div>
</div>
</body>
</html>"""

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = f"Ternis Mail Management <{SMTP_FROM}>"
    msg['To'] = recipient
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype='html')

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            smtp.send_message(msg)
        target_display = recipient_masked if resolution_type == "dns_record" else f"postmaster@{domain}"
        return True, f"Verification code sent to {target_display}.", meta
    except Exception as e:
        return False, f"Failed to deliver verification email: {str(e)}", meta

def verify_code(domain: str, input_code: str) -> Tuple[bool, str]:
    domain = domain.strip().lower()
    input_code = input_code.strip()
    now = int(time.time())

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT code, attempts, expires_at FROM verification_codes WHERE domain = %s;", (domain,))
            row = cur.fetchone()
            if not row:
                return False, "No pending verification code found for this domain. Please request a new code."

            if now > row["expires_at"]:
                cur.execute("DELETE FROM verification_codes WHERE domain = %s;", (domain,))
                return False, "Verification code has expired. Please request a new one."

            if row["attempts"] >= 5:
                cur.execute("DELETE FROM verification_codes WHERE domain = %s;", (domain,))
                return False, "Too many failed attempts. Please request a new code."

            if not secrets.compare_digest(row["code"], input_code):
                cur.execute("UPDATE verification_codes SET attempts = attempts + 1 WHERE domain = %s;", (domain,))
                remaining = 4 - row["attempts"]
                return False, f"Invalid verification code. {max(0, remaining)} attempt(s) remaining."

            # Successful verification - consume the code
            cur.execute("DELETE FROM verification_codes WHERE domain = %s;", (domain,))
            return True, "Verification successful."
