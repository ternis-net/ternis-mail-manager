#!/usr/bin/env python3
"""
Ternis Mail Server Root Administrative CLI
Direct management of virtual domains, mailboxes, aliases, quotas, and server diagnostics.
Can operate via local MySQL / Dovecot directly or via the local REST API.
"""

import sys
import os
import argparse
import json
import subprocess
from datetime import datetime, timezone

# Add script directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import get_connection
import tokens as token_manager
from helpers import (
    hash_dovecot_password,
    generate_secure_password,
    ensure_dkim_keys,
    build_dns_records,
    MAIL_STORAGE,
    DKIM_DIR,
    MAIL_HOST
)

def format_json(data):
    return json.dumps(data, indent=2, default=str)

# --- Subcommands ---

def cmd_domains_list(args):
    with get_connection() as conn:
        with conn.cursor() as cur:
            sql = """
                SELECT 
                    d.id, d.domain, d.active, d.created_at,
                    COUNT(DISTINCT u.id) as mailboxes,
                    COUNT(DISTINCT a.id) as aliases
                FROM domains d
                LEFT JOIN users u ON u.domain_id = d.id
                LEFT JOIN aliases a ON a.domain_id = d.id
            """
            params = []
            if args.search:
                sql += " WHERE d.domain LIKE %s"
                params.append(f"%{args.search.strip().lower()}%")
            sql += " GROUP BY d.id ORDER BY d.domain ASC"
            cur.execute(sql, params)
            rows = cur.fetchall()

    if args.json:
        print(format_json(rows))
        return

    print(f"{'ID':<4} {'Domain':<30} {'Active':<8} {'Mailboxes':<10} {'Aliases':<8} {'DKIM':<6}")
    print("-" * 72)
    for r in rows:
        dkim_file = os.path.join(DKIM_DIR, f"{r['domain']}.mail.key")
        dkim_status = "✓" if os.path.isfile(dkim_file) else "-"
        active_str = "yes" if r['active'] else "no"
        print(f"{r['id']:<4} {r['domain']:<30} {active_str:<8} {r['mailboxes']:<10} {r['aliases']:<8} {dkim_status:<6}")

def cmd_domains_add(args):
    domain = args.domain.strip().lower()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM domains WHERE domain = %s", (domain,))
            if cur.fetchone():
                print(f"Error: Domain '{domain}' already exists.", file=sys.stderr)
                sys.exit(1)

            cur.execute("INSERT INTO domains (domain, active) VALUES (%s, 1)", (domain,))
            domain_id = cur.lastrowid
            conn.commit()

    # Generate DKIM
    dkim_info = {}
    if not args.no_dkim:
        try:
            dkim_info = ensure_dkim_keys(domain)
        except Exception as e:
            print(f"Warning: Failed to generate DKIM key: {e}", file=sys.stderr)

    # Optional postmaster mailbox
    postmaster_pw = None
    if args.create_postmaster:
        postmaster_pw = args.postmaster_password or generate_secure_password(18)
        hashed_pw = hash_dovecot_password(postmaster_pw)
        email = f"postmaster@{domain}"
        maildir = f"{domain}/postmaster/"

        full_maildir_path = os.path.join(MAIL_STORAGE, domain, "postmaster", "Maildir")
        for sub in ["cur", "new", "tmp"]:
            os.makedirs(os.path.join(full_maildir_path, sub), exist_ok=True)
        try:
            subprocess.run(["chown", "-R", "vmail:vmail", os.path.join(MAIL_STORAGE, domain)], check=True)
            subprocess.run(["chmod", "-R", "770", os.path.join(MAIL_STORAGE, domain)], check=True)
        except Exception:
            pass

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (domain_id, email, password, maildir, quota_bytes, active) VALUES (%s, %s, %s, %s, %s, 1)",
                    (domain_id, email, hashed_pw, maildir, 10737418240)
                )
                conn.commit()

    # Optional catch-all
    if args.catchall:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO aliases (domain_id, source, destination, active) VALUES (%s, %s, %s, 1)",
                    (domain_id, f"@{domain}", args.catchall.strip())
                )
                conn.commit()

    res = {
        "status": "success",
        "domain": domain,
        "domain_id": domain_id,
        "dkim_configured": bool(dkim_info.get("selector")),
        "postmaster_created": args.create_postmaster,
        "postmaster_password": postmaster_pw
    }

    if args.json:
        print(format_json(res))
    else:
        print(f"✓ Domain '{domain}' successfully created (ID: {domain_id})")
        if dkim_info.get("dns_record"):
            print(f"  DKIM DNS Record: {dkim_info['dns_record']}")
        if postmaster_pw:
            print(f"  Postmaster Mailbox: postmaster@{domain} (Password: {postmaster_pw})")
        if args.catchall:
            print(f"  Catch-all Alias: @{domain} -> {args.catchall}")

def cmd_domains_delete(args):
    domain = args.domain.strip().lower()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM domains WHERE domain = %s", (domain,))
            row = cur.fetchone()
            if not row:
                print(f"Error: Domain '{domain}' not found.", file=sys.stderr)
                sys.exit(1)
            domain_id = row["id"]

            cur.execute("DELETE FROM aliases WHERE domain_id = %s", (domain_id,))
            cur.execute("DELETE FROM users WHERE domain_id = %s", (domain_id,))
            cur.execute("DELETE FROM domains WHERE id = %s", (domain_id,))
            conn.commit()

    if args.purge:
        # Purge storage and dkim
        domain_storage = os.path.join(MAIL_STORAGE, domain)
        if os.path.exists(domain_storage):
            import shutil
            shutil.rmtree(domain_storage, ignore_errors=True)
        dkim_key = os.path.join(DKIM_DIR, f"{domain}.mail.key")
        if os.path.exists(dkim_key):
            os.remove(dkim_key)

    if args.json:
        print(format_json({"status": "deleted", "domain": domain, "purged": args.purge}))
    else:
        print(f"✓ Domain '{domain}' deleted from database" + (" (storage purged)" if args.purge else ""))

def cmd_mailboxes_list(args):
    with get_connection() as conn:
        with conn.cursor() as cur:
            sql = """
                SELECT u.id, u.email, d.domain, u.quota_bytes, u.active, u.created_at
                FROM users u
                JOIN domains d ON d.id = u.domain_id
            """
            params = []
            if args.domain:
                sql += " WHERE d.domain = %s"
                params.append(args.domain.strip().lower())
            elif args.search:
                sql += " WHERE u.email LIKE %s"
                params.append(f"%{args.search.strip().lower()}%")
            sql += " ORDER BY u.email ASC"
            cur.execute(sql, params)
            rows = cur.fetchall()

    if args.json:
        print(format_json(rows))
        return

    print(f"{'ID':<4} {'Email':<35} {'Domain':<25} {'Quota':<10} {'Active':<8}")
    print("-" * 85)
    for r in rows:
        quota_gb = round(r['quota_bytes'] / (1024**3), 1) if r['quota_bytes'] else "None"
        active_str = "yes" if r['active'] else "no"
        print(f"{r['id']:<4} {r['email']:<35} {r['domain']:<25} {str(quota_gb)+' GB':<10} {active_str:<8}")

def cmd_mailboxes_add(args):
    email = args.email.strip().lower()
    if "@" not in email:
        print("Error: Email must contain '@' and domain.", file=sys.stderr)
        sys.exit(1)
    local_part, domain_name = email.split("@", 1)

    with get_connection() as conn:
        with conn.cursor() as cur:
            # Check domain
            cur.execute("SELECT id FROM domains WHERE domain = %s", (domain_name,))
            dom_row = cur.fetchone()
            if not dom_row:
                cur.execute("INSERT INTO domains (domain, active) VALUES (%s, 1)", (domain_name,))
                domain_id = cur.lastrowid
                conn.commit()
                try:
                    ensure_dkim_keys(domain_name)
                except Exception:
                    pass
            else:
                domain_id = dom_row["id"]

            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                print(f"Error: Mailbox '{email}' already exists.", file=sys.stderr)
                sys.exit(1)

            password = args.password or generate_secure_password(18)
            hashed_pw = hash_dovecot_password(password)
            maildir = f"{domain_name}/{local_part}/"
            quota_bytes = int(args.quota_gb * (1024**3))

            # Maildir structure
            full_maildir_path = os.path.join(MAIL_STORAGE, domain_name, local_part, "Maildir")
            for sub in ["cur", "new", "tmp"]:
                os.makedirs(os.path.join(full_maildir_path, sub), exist_ok=True)
            try:
                subprocess.run(["chown", "-R", "vmail:vmail", os.path.join(MAIL_STORAGE, domain_name)], check=True)
                subprocess.run(["chmod", "-R", "770", os.path.join(MAIL_STORAGE, domain_name)], check=True)
            except Exception:
                pass

            cur.execute(
                "INSERT INTO users (domain_id, email, password, maildir, quota_bytes, active) VALUES (%s, %s, %s, %s, %s, 1)",
                (domain_id, email, hashed_pw, maildir, quota_bytes)
            )
            mailbox_id = cur.lastrowid
            conn.commit()

    res = {
        "status": "created",
        "id": mailbox_id,
        "email": email,
        "domain": domain_name,
        "password": password,
        "quota_gb": args.quota_gb
    }
    if args.json:
        print(format_json(res))
    else:
        print(f"✓ Mailbox '{email}' created successfully (ID: {mailbox_id})")
        print(f"  Password: {password}")
        print(f"  Quota: {args.quota_gb} GB")
        print(f"  Maildir: /var/vmail/{maildir}")

def cmd_mailboxes_passwd(args):
    email = args.email.strip().lower()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if not cur.fetchone():
                print(f"Error: Mailbox '{email}' not found.", file=sys.stderr)
                sys.exit(1)

            password = args.password or generate_secure_password(18)
            hashed_pw = hash_dovecot_password(password)
            cur.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
            conn.commit()

    if args.json:
        print(format_json({"status": "updated", "email": email, "password": password}))
    else:
        print(f"✓ Password updated for '{email}'")
        print(f"  New Password: {password}")

def cmd_mailboxes_delete(args):
    email = args.email.strip().lower()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, maildir FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            if not row:
                print(f"Error: Mailbox '{email}' not found.", file=sys.stderr)
                sys.exit(1)
            maildir = row["maildir"]

            cur.execute("DELETE FROM users WHERE email = %s", (email,))
            conn.commit()

    if args.purge and maildir:
        import shutil
        full_path = os.path.join(MAIL_STORAGE, maildir)
        if os.path.exists(full_path):
            shutil.rmtree(full_path, ignore_errors=True)

    if args.json:
        print(format_json({"status": "deleted", "email": email, "purged": args.purge}))
    else:
        print(f"✓ Mailbox '{email}' deleted" + (" (storage purged)" if args.purge else ""))

def cmd_aliases_list(args):
    with get_connection() as conn:
        with conn.cursor() as cur:
            sql = """
                SELECT a.id, a.source, a.destination, d.domain, a.active, a.created_at
                FROM aliases a
                JOIN domains d ON d.id = a.domain_id
            """
            params = []
            if args.domain:
                sql += " WHERE d.domain = %s"
                params.append(args.domain.strip().lower())
            elif args.search:
                sql += " WHERE a.source LIKE %s OR a.destination LIKE %s"
                term = f"%{args.search.strip().lower()}%"
                params.extend([term, term])
            sql += " ORDER BY a.source ASC"
            cur.execute(sql, params)
            rows = cur.fetchall()

    if args.json:
        print(format_json(rows))
        return

    print(f"{'ID':<4} {'Source':<32} {'Destination':<35} {'Active':<8}")
    print("-" * 82)
    for r in rows:
        active_str = "yes" if r['active'] else "no"
        print(f"{r['id']:<4} {r['source']:<32} {r['destination']:<35} {active_str:<8}")

def cmd_aliases_add(args):
    source = args.source.strip().lower()
    destination = args.destination.strip()

    if source.startswith("@"):
        domain_name = source[1:]
    elif "@" in source:
        _, domain_name = source.split("@", 1)
    else:
        print("Error: Source must be an email (user@domain) or catch-all (@domain).", file=sys.stderr)
        sys.exit(1)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM domains WHERE domain = %s", (domain_name,))
            dom = cur.fetchone()
            if not dom:
                cur.execute("INSERT INTO domains (domain, active) VALUES (%s, 1)", (domain_name,))
                domain_id = cur.lastrowid
                conn.commit()
            else:
                domain_id = dom["id"]

            cur.execute("SELECT id FROM aliases WHERE source = %s", (source,))
            if cur.fetchone():
                print(f"Error: Alias source '{source}' already exists.", file=sys.stderr)
                sys.exit(1)

            cur.execute(
                "INSERT INTO aliases (domain_id, source, destination, active) VALUES (%s, %s, %s, 1)",
                (domain_id, source, destination)
            )
            alias_id = cur.lastrowid
            conn.commit()

    if args.json:
        print(format_json({"status": "created", "id": alias_id, "source": source, "destination": destination}))
    else:
        print(f"✓ Alias created: {source} -> {destination} (ID: {alias_id})")

def cmd_aliases_delete(args):
    source = args.source.strip().lower()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM aliases WHERE source = %s", (source,))
            affected = cur.rowcount
            conn.commit()

    if affected == 0:
        print(f"Error: Alias '{source}' not found.", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(format_json({"status": "deleted", "source": source}))
    else:
        print(f"✓ Alias '{source}' deleted successfully.")

def cmd_stats(args):
    import shutil
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as c FROM domains")
            domains_total = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM domains WHERE active = 1")
            domains_active = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM users")
            mb_total = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM users WHERE active = 1")
            mb_active = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM aliases")
            aliases_total = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM aliases WHERE source LIKE '@%'")
            catchalls_total = cur.fetchone()["c"]

    total_b, used_b, free_b = shutil.disk_usage(MAIL_STORAGE)

    # Postfix queues
    queues = {}
    for q in ["active", "deferred", "incoming", "bounce"]:
        q_dir = os.path.join("/var/spool/postfix", q)
        count = 0
        if os.path.isdir(q_dir):
            for _, _, files in os.walk(q_dir):
                count += len(files)
        queues[q] = count

    # Daemon services
    services = {}
    for s in ["postfix", "dovecot", "mariadb", "rspamd"]:
        try:
            r = subprocess.run(["systemctl", "is-active", s], stdout=subprocess.PIPE, text=True)
            services[s] = r.stdout.strip()
        except Exception:
            services[s] = "unknown"

    stats_data = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": MAIL_HOST,
        "counts": {
            "domains_total": domains_total,
            "domains_active": domains_active,
            "mailboxes_total": mb_total,
            "mailboxes_active": mb_active,
            "aliases_total": aliases_total,
            "catchalls_total": catchalls_total
        },
        "storage": {
            "path": MAIL_STORAGE,
            "total_gb": round(total_b / (1024**3), 2),
            "used_gb": round(used_b / (1024**3), 2),
            "free_gb": round(free_b / (1024**3), 2),
            "used_percent": round((used_b / total_b) * 100, 1)
        },
        "postfix_queues": queues,
        "services": services
    }

    if args.json:
        print(format_json(stats_data))
        return

    print("==================================================")
    print(f" Ternis Mail Server Status ({MAIL_HOST})")
    print("==================================================")
    print(f"Domains:   {domains_active} active / {domains_total} total")
    print(f"Mailboxes: {mb_active} active / {mb_total} total")
    print(f"Aliases:   {aliases_total} total ({catchalls_total} catch-alls)")
    print(f"Storage:   {stats_data['storage']['used_gb']} GB / {stats_data['storage']['total_gb']} GB ({stats_data['storage']['used_percent']}% used)")
    print(f"Postfix:   {queues['active']} active, {queues['deferred']} deferred, {queues['incoming']} incoming")
    print("Daemons:")
    for svc, st in services.items():
        symbol = "✓" if st == "active" else "✗"
        print(f"  {symbol} {svc:<10} [{st}]")

def main():
    parser = argparse.ArgumentParser(description="Ternis Mail Server Root CLI")
    parser.add_argument("--json", action="store_true", help="Output in machine-readable JSON format")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # domains
    p_domains = subparsers.add_parser("domains", help="Manage virtual domains")
    sp_dom = p_domains.add_subparsers(dest="action", required=True)
    
    p_dom_list = sp_dom.add_parser("list", help="List domains")
    p_dom_list.add_argument("--search", help="Search pattern")
    p_dom_list.set_defaults(func=cmd_domains_list)

    p_dom_add = sp_dom.add_parser("add", help="Add virtual domain")
    p_dom_add.add_argument("domain", help="Domain name (e.g. example.com)")
    p_dom_add.add_argument("--no-dkim", action="store_true", help="Skip DKIM key generation")
    p_dom_add.add_argument("--create-postmaster", action="store_true", help="Create postmaster@<domain> mailbox")
    p_dom_add.add_argument("--postmaster-password", help="Password for postmaster mailbox")
    p_dom_add.add_argument("--catchall", help="Default destination address for catch-all @<domain>")
    p_dom_add.set_defaults(func=cmd_domains_add)

    p_dom_del = sp_dom.add_parser("delete", help="Delete virtual domain")
    p_dom_del.add_argument("domain", help="Domain name to delete")
    p_dom_del.add_argument("--purge", action="store_true", help="Purge storage files and DKIM keys")
    p_dom_del.set_defaults(func=cmd_domains_delete)

    # mailboxes
    p_mb = subparsers.add_parser("mailboxes", help="Manage virtual mailboxes")
    sp_mb = p_mb.add_subparsers(dest="action", required=True)

    p_mb_list = sp_mb.add_parser("list", help="List mailboxes")
    p_mb_list.add_argument("--domain", help="Filter by domain")
    p_mb_list.add_argument("--search", help="Search by email")
    p_mb_list.set_defaults(func=cmd_mailboxes_list)

    p_mb_add = sp_mb.add_parser("add", help="Add virtual mailbox")
    p_mb_add.add_argument("email", help="Full email (user@domain)")
    p_mb_add.add_argument("--password", help="Password (auto-generated if omitted)")
    p_mb_add.add_argument("--quota-gb", type=float, default=10.0, help="Quota in GB (default: 10)")
    p_mb_add.set_defaults(func=cmd_mailboxes_add)

    p_mb_pw = sp_mb.add_parser("passwd", help="Update mailbox password")
    p_mb_pw.add_argument("email", help="Full email (user@domain)")
    p_mb_pw.add_argument("--password", help="New password (auto-generated if omitted)")
    p_mb_pw.set_defaults(func=cmd_mailboxes_passwd)

    p_mb_del = sp_mb.add_parser("delete", help="Delete virtual mailbox")
    p_mb_del.add_argument("email", help="Full email to delete")
    p_mb_del.add_argument("--purge", action="store_true", help="Purge Maildir from disk")
    p_mb_del.set_defaults(func=cmd_mailboxes_delete)

    # aliases
    p_al = subparsers.add_parser("aliases", help="Manage virtual aliases / forwarders")
    sp_al = p_al.add_subparsers(dest="action", required=True)

    p_al_list = sp_al.add_parser("list", help="List aliases")
    p_al_list.add_argument("--domain", help="Filter by domain")
    p_al_list.add_argument("--search", help="Search alias")
    p_al_list.set_defaults(func=cmd_aliases_list)

    p_al_add = sp_al.add_parser("add", help="Add alias or catch-all")
    p_al_add.add_argument("source", help="Source email (user@domain or @domain)")
    p_al_add.add_argument("destination", help="Destination email(s)")
    p_al_add.set_defaults(func=cmd_aliases_add)

    p_al_del = sp_al.add_parser("delete", help="Delete alias")
    p_al_del.add_argument("source", help="Source email to delete")
    p_al_del.set_defaults(func=cmd_aliases_delete)

    # stats
    p_st = subparsers.add_parser("stats", help="Show system status and daemon health")
    p_st.set_defaults(func=cmd_stats)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
