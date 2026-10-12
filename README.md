# Ternis Mail Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com)
[![Dovecot & Postfix](https://img.shields.io/badge/MTA-Postfix%20%7C%20Dovecot-orange.svg)](https://www.postfix.org/)

**Ternis Mail Manager** is a modern, privacy-focused Mail Gateway REST API and web management interface designed for virtual mail hosting with **Postfix**, **Dovecot**, and **MariaDB**.

It specializes in provisioning and configuring dedicated **"Application Mail Accounts"** (used by Nextcloud, WordPress, GitLab, Docker microservices, and backend APIs) with automated Dovecot `SHA512-CRYPT` hashing, physical Maildir directory creation, and instant ready-to-copy configuration snippets.

---

## Key Features

* 🔐 **Postmaster Login Verification (Zero Enumeration):**
  * No public dropdown or domain listing is exposed.
  * Administrators enter their specific domain, and a secure 6-digit login PIN is dispatched directly to the domain administrator.
  * **Dynamic DNS TXT Postmaster Routing:** Administrators can set an external notification email via a `_postmaster.<domain>` TXT record (e.g. `admin@external.org`, `mailto:admin@external.org`, or `v=postmaster1; mailto:admin@...`).
  * If no `_postmaster` DNS record exists, defaults to `postmaster@<domain>`.
  * Email recipient masking (`ad***n@example.com`) preserves privacy on login attempts.
  * Multi-worker database-synchronized verification codes (15-minute TTL, rate limiting, and brute-force protection).
* 🌐 **Subdomain Mailbox Provisioning:**
  * One-click registration for subdomains (e.g. `cloud.domain.com`, `alerts.domain.com`).
  * Automated 2048-bit RSA DKIM key pair generation via `rspamadm dkim_keygen`.
  * Auto-creates catch-all alias (`@sub.domain` -> `postmaster@domain`) to ensure uninterrupted administrative bounce handling.
  * Instant generation of required DNS records (MX, SPF, DKIM `mail._domainkey`, DMARC).
* 🔍 **Live DNS Zone Health Inspection:**
  * Real-time DNS verification directly querying the public DNS zone via dnspython.
  * Checks and displays live status (configured vs missing/invalid) for MX, SPF, DKIM, DMARC, Autoconfig, and Autodiscover.
* ☁️ **Application Presets & Instant Setup:**
  * One-click presets for **Nextcloud**, **WordPress**, **GitLab**, **Docker/Generic Backend (`.env`)**, and **Monitoring/Alertmanager**.
  * Auto-generates high-entropy passwords (24+ characters) and assigns custom quotas (1 GB, 2 GB, 5 GB, 10 GB).
* 📋 **Ready-to-Paste Configuration Snippets:**
  * **Nextcloud Web UI:** Step-by-step form settings for *Administration → Basic Settings → Email Server*.
  * **Nextcloud `config.php`:** Copy-pasteable PHP configuration array.
  * **Standard `.env`:** Environment variables for Docker Compose, Laravel, Django, Node.js, and Rails.
  * **Dual Protocol Ports:** Ready snippets for both SMTPS (Port 465 SSL/TLS) and Submission (Port 587 STARTTLS).
* 📦 **Automatic Physical Provisioning:**
  * Manages MariaDB records for virtual domains, mailboxes, and aliases.
  * Computes Dovecot-compatible `SHA512-CRYPT` hashes via `doveadm pw`.
  * Creates physical `Maildir` structure (`cur`, `new`, `tmp`) with `vmail:vmail` permissions.
* 🛡️ **Cryptographic Domain & Subdomain Isolation:**
  * Scoped session tokens grant access strictly to the authenticated domain and its subdomains (`403 Forbidden` on unauthorized domains).
* 🎨 **Minimalist Flat UI with Dark/Light Mode:**
  * Zero build-step requirement (pure HTML5, CSS variables, vanilla JS).
  * Flat grayscale design, zero emojis, zero gradients, zero shadows, pure crisp inline SVGs.
  * Integrated Theme toggle (Light / Dark mode).

---

## Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │             Web Browser                │
                      │  (Responsive Single-Page Web UI)       │
                      └──────────────────┬─────────────────────┘
                                         │ HTTPS
                                         ▼
                      ┌────────────────────────────────────────┐
                      │                 Nginx                  │
                      │   /app-accounts/   --> Static HTML/JS  │
                      │   /api/            --> Reverse Proxy   │
                      └──────────────────┬─────────────────────┘
                                         │ HTTP (127.0.0.1:8088)
                                         ▼
                      ┌────────────────────────────────────────┐
                      │        FastAPI Application Server      │
                      │  - Postmaster Verification Flow        │
                      │  - Scoped Bearer Token Engine          │
                      │  - Mailbox & App Provisioning Engine   │
                      └──────────────┬──────────────────┬──────┘
                                     │                  │
                MariaDB Queries      │                  │  Local Delivery
               (vmail DB)            ▼                  ▼  (SMTP 127.0.0.1:25)
  ┌────────────────────────────────────┐             ┌─────────────────────────┐
  │              MariaDB               │             │         Postfix         │
  │ - domains                          │             │ - Delivers PINs to      │
  │ - users                            │             │   postmaster@<domain>   │
  │ - aliases                          │             └────────────┬────────────┘
  │ - verification_codes               │                          │ LMTP
  └────────────────────────────────────┘                          ▼
                                                     ┌─────────────────────────┐
                                                     │         Dovecot         │
                                                     │ - SHA512-CRYPT hashing  │
                                                     │ - Maildir (/var/vmail)  │
                                                     └─────────────────────────┘
```

---

## Directory Structure

```text
ternis-mail-manager/
├── backend/
│   ├── app.py                 # FastAPI application and REST endpoints
│   ├── database.py            # MariaDB database connector (env & cnf support)
│   ├── tokens.py              # Scoped API & session token management
│   └── verification.py        # Postmaster email verification logic
├── frontend/
│   └── index.html             # Responsive Single-Page Application UI
├── deployment/
│   ├── schema.sql             # MariaDB SQL schema
│   ├── ternis-mail-api.service# Systemd service unit file
│   └── nginx-site.example.conf# Nginx virtual host configuration
├── .env.example               # Environment variables template
├── requirements.txt           # Python package dependencies
├── LICENSE                    # MIT Open Source License
└── README.md                  # Project documentation
```

---

## Installation & Setup

### 1. Prerequisites

* Linux (Debian 12+ / Ubuntu 22.04+ recommended)
* Python 3.10+
* Postfix & Dovecot configured for virtual mailboxes
* MariaDB / MySQL server

### 2. Database Initialization

Import the database schema:

```bash
mysql -u root -p < deployment/schema.sql
```

### 3. Install Python Dependencies

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r ../requirements.txt
```

### 4. Configuration

Copy `.env.example` to `.env` and adjust your hostnames and credentials:

```bash
cp ../.env.example .env
```

Key environment variables:
* `MAIL_HOST`: Primary mail server hostname (e.g. `one.mx.ternis.net`).
* `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`: MariaDB database credentials.
* `MAIL_STORAGE`: Maildir root path (default: `/var/vmail`).
* `TOKENS_FILE`: Path to persistent API token JSON file.

### 5. Running with Systemd

Copy the unit file to `/etc/systemd/system/`:

```bash
sudo cp deployment/ternis-mail-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ternis-mail-api
```

### 6. Nginx Web Server & Frontend Deployment

Copy the frontend to your web root:

```bash
sudo mkdir -p /var/www/mail.example.com/app-accounts
sudo cp frontend/index.html /var/www/mail.example.com/app-accounts/index.html
```

Use `deployment/nginx-site.example.conf` as a template for your Nginx configuration.

---

## API Endpoints

### Authentication (Postmaster Verification)
* `POST /api/v1/auth/request-code` — Request a 6-digit verification code to `postmaster@<domain>`.
* `POST /api/v1/auth/verify-code` — Verify PIN and receive a domain-scoped session token.
* `GET /api/v1/auth/session` — Validate active session token.

### Subdomain Provisioning
* `POST /api/v1/subdomains/mailbox` — Register subdomain, generate DKIM key, setup postmaster catch-all alias, and provision mailbox.
* `GET /api/v1/subdomains` — List existing subdomains for authenticated domain.

### DNS Records & Live Health Verification
* `GET /api/v1/dns` — Retrieve required/recommended DNS records (MX, SPF, DKIM, DMARC, Autoconfig, Autodiscover).
* `GET /api/v1/dns/status` — Real-time live DNS zone query inspecting MX, SPF, DKIM, DMARC, Autoconfig, and Autodiscover status.

### Application Accounts
* `POST /api/v1/app-accounts` — Provision application mailbox and generate Nextcloud / `.env` snippets.

### Mailbox Management
* `GET /api/v1/mailboxes` — List mailboxes for authenticated domain.
* `POST /api/v1/mailboxes` — Create a virtual mailbox.
* `POST /api/v1/mailboxes/{email}/password` — Reset mailbox password.
* `DELETE /api/v1/mailboxes/{email}` — Delete a mailbox (with optional storage purge).

---

## Root Administrative REST API (Full Superadmin Access)

For autonomous infrastructure orchestration, server administrators, hosting panels, and deployment pipelines, the Ternis Mail API exposes a high-privilege administrative interface under `/api/v1/admin/*`.

Requests require a Root Bearer token (issued with `domain: "*"` or defined via `MASTER_API_KEY` / `ADMIN_API_KEY` environment variable):

```http
Authorization: Bearer <ROOT_API_TOKEN>
```

Interactive OpenAPI Swagger UI is available at:
```text
https://one.mx.ternis.net/docs
```

### Root Endpoints Matrix

| HTTP Method | Endpoint | Description |
| :--- | :--- | :--- |
| **System** | | |
| `GET` | `/api/v1/admin/stats` | Global metrics: domain/mailbox/alias totals, `/var/vmail` disk capacity, Postfix queue counts, systemd daemon states |
| **Domains** | | |
| `GET` | `/api/v1/admin/domains` | Paginated list of all virtual domains with search, active filter, mailbox counts, and DKIM presence |
| `POST` | `/api/v1/admin/domains` | Provision new virtual domain; automatically generates 2048-bit RSA DKIM key via rspamadm; optional postmaster mailbox & catch-all |
| `GET` | `/api/v1/admin/domains/{domain}` | Deep domain inspection: mailboxes, aliases, DKIM keys, and live DNS health status |
| `PATCH` | `/api/v1/admin/domains/{domain}` | Enable or disable a domain |
| `DELETE` | `/api/v1/admin/domains/{domain}` | Delete domain (cascades MySQL users/aliases; optional `purge_storage=true` for `/var/vmail/<domain>` & DKIM key) |
| `GET` | `/api/v1/admin/domains/{domain}/dkim` | Inspect private and public DKIM keys |
| `POST` | `/api/v1/admin/domains/{domain}/dkim` | Generate or re-generate 2048-bit DKIM key pair |
| **Mailboxes** | | |
| `GET` | `/api/v1/admin/mailboxes` | List all mailboxes across all domains (or filter by `?domain=` or `?search=`) |
| `POST` | `/api/v1/admin/mailboxes` | Provision mailbox on any domain; hashes password with Dovecot `SHA512-CRYPT`; creates Maildir `cur/new/tmp` with `vmail:vmail` permissions |
| `GET` | `/api/v1/admin/mailboxes/{email}` | Detailed mailbox properties and disk usage calculation |
| `PATCH` | `/api/v1/admin/mailboxes/{email}` | Update password, quota (in GB or bytes), or active state |
| `POST` | `/api/v1/admin/mailboxes/{email}/password` | Instant password reset |
| `DELETE` | `/api/v1/admin/mailboxes/{email}` | Delete mailbox (optional `purge_storage=true` removes physical Maildir) |
| **Aliases & Routing** | | |
| `GET` | `/api/v1/admin/aliases` | List all aliases and catch-alls across all domains |
| `POST` | `/api/v1/admin/aliases` | Create alias or catch-all (`@domain.com` or `source@domain.com`) to single or multiple destination emails |
| `GET` | `/api/v1/admin/aliases/{source}` | Inspect specific alias routing |
| `PATCH` | `/api/v1/admin/aliases/{source}` | Update forwarding destinations or active state |
| `DELETE` | `/api/v1/admin/aliases/{source}` | Remove alias |
| **Root Tokens** | | |
| `GET` | `/api/v1/admin/tokens` | List active administrative and domain-scoped API tokens |
| `POST` | `/api/v1/admin/tokens` | Issue new Root API token (`domain: "*"`) or scoped domain token |
| `DELETE` | `/api/v1/admin/tokens/{token_id}` | Revoke an API token |

### Root cURL Examples

#### 1. Server Diagnostics & Mail Queues
```bash
curl -s -H "Authorization: Bearer $ROOT_API_KEY" \
  https://one.mx.ternis.net/api/v1/admin/stats | jq
```

#### 2. Provision Virtual Domain with DKIM & Postmaster
```bash
curl -s -X POST https://one.mx.ternis.net/api/v1/admin/domains \
  -H "Authorization: Bearer $ROOT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "customer.org",
    "create_postmaster": true,
    "default_alias_destination": "noc@ternis.net"
  }' | jq
```

#### 3. Provision Mailbox on Any Domain
```bash
curl -s -X POST https://one.mx.ternis.net/api/v1/admin/mailboxes \
  -H "Authorization: Bearer $ROOT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "billing@customer.org",
    "quota_gb": 15.0
  }' | jq
```

#### 4. Add Multi-Destination Alias or Catch-All
```bash
curl -s -X POST https://one.mx.ternis.net/api/v1/admin/aliases \
  -H "Authorization: Bearer $ROOT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "@customer.org",
    "destination": "admin@customer.org, noc@ternis.net"
  }' | jq
```

---

## Root Administrative CLI (`ternis-mail-admin`)

For direct command-line server administration on `one.mx.ternis.net`:

```bash
# Display server status, quotas, and daemon health
ternis-mail-admin stats

# List virtual domains
ternis-mail-admin domains list
ternis-mail-admin domains add example.com --create-postmaster --catchall admin@ternis.net
ternis-mail-admin domains delete example.com --purge

# Mailbox operations
ternis-mail-admin mailboxes list --domain example.com
ternis-mail-admin mailboxes add user@example.com --quota-gb 5.0
ternis-mail-admin mailboxes passwd user@example.com --password "NewSecurePass123!"
ternis-mail-admin mailboxes delete user@example.com --purge

# Alias operations
ternis-mail-admin aliases list --domain example.com
ternis-mail-admin aliases add @example.com admin@ternis.net
ternis-mail-admin aliases delete @example.com

# Machine-readable output for scripts
ternis-mail-admin --json stats | jq .
```

---

## Dynamic Postmaster DNS Routing (`_postmaster` TXT Record)

### The Problem It Solves
1. **The Bootstrap Dilemma:** When adding a new domain to the mail gateway, `postmaster@domain.com` might not exist yet, or inbound MX records may not be live. Requiring access to a local mailbox on an unconfigured domain creates a circular dependency.
2. **Centralized IT / MSP Administration:** Operators managing multiple virtual domains often prefer receiving login verification PINs in a primary operational inbox (e.g., `noc@ternis.net` or `admin@it-provider.de`) rather than accessing separate webmail accounts for every hosted domain.
3. **Cryptographic Proof of Authority via DNS:** Controlling a domain's authoritative DNS zone is the industry standard proof of domain ownership. By looking up a designated TXT record, the mail gateway delegates login notification routing strictly to the authoritative DNS owner.

### DNS Zone Configuration
To route login PINs to an external or specific administrative address, publish a TXT record at `_postmaster.<domain>`:

| Record Type | Name / Host | Value / Target | Notes |
| :--- | :--- | :--- | :--- |
| **TXT** | `_postmaster` | `admin@external-domain.com` | Standard recommendation |
| **TXT** | `_postmaster` | `mailto:admin@external-domain.com` | URI syntax supported |
| **TXT** | `_postmaster` | `v=postmaster1; mailto:admin@...` | RFC / Tag syntax supported |
| **TXT** | `@` (Apex) | `postmaster=admin@external-domain.com` | Apex tag alternative |

#### BIND Zone File Example:
```text
; Dynamic Postmaster Login Routing
_postmaster.example.com.    IN  TXT  "admin@my-company.net"
```

### Fallback Hierarchy
When a user requests a verification code for `<domain>`:
1. `_postmaster.<domain>` TXT record is queried via `dnspython`.
2. `_ternis-postmaster.<domain>` TXT record is checked.
3. `<domain>` apex TXT record is parsed for `postmaster=` or `v=postmaster1;`.
4. If `<domain>` is a subdomain (e.g. `cloud.example.com`), `_postmaster.example.com` is checked.
5. If no valid record is discovered or DNS times out (2.5s timeout), the system defaults safely to:
   ```text
   postmaster@<domain>
   ```

### Privacy & Anti-Scraping Safeguards
To prevent attackers from probing domain names to discover private email addresses:
* The web interface and public REST API response mask the destination (e.g. `ad***n@my-company.net`). `// note: This is fully unneccessary (because the "attacker" could just check the DNS anyways)`
* The dispatched email clearly states the resolution method (`via DNS TXT record _postmaster.<domain>` vs `default mailbox postmaster@<domain>`).

---

## Security Considerations

1. **Anti-Enumeration:** The system deliberately does not list available domains publicly. Requests require exact domain names.
2. **Brute-Force Protection:** Verification codes expire after 15 minutes and lock out after 5 invalid attempts. Rate limiting prevents code-spamming `postmaster`.
3. **Privilege Separation:** API tokens are cryptographically scoped to specific domains and cannot read or modify mailboxes belonging to other domains.

---

## Open Source & Licensing

Released under the **[MIT License](LICENSE)**.

Developed by **Ternis** ([ternis.dev](https://ternis.dev) / [ternis.org](https://ternis.org)).
Code repository hosted at:
* **Codeberg:** [codeberg.org/ternis/ternis-mail-manager](https://codeberg.org/ternis/ternis-mail-manager)
* **GitHub:** [github.com/ternis-net/ternis-mail-manager](https://github.com/ternis-net/ternis-mail-manager)
