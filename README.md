# Ternis Mail Manager 📬

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
  * Administrators enter their specific domain, and a secure 6-digit login PIN is dispatched directly to `postmaster@<domain>`.
  * Multi-worker database-synchronized verification codes (15-minute TTL, rate limiting, and brute-force protection).
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
* 🛡️ **Cryptographic Domain Isolation:**
  * Scoped session tokens grant access strictly to the authenticated domain (`403 Forbidden` on unauthorized domains).
* 🎨 **Lightweight Responsive Web UI:**
  * Zero build-step requirement (pure HTML5, CSS variables, vanilla JS).
  * High-contrast modern dark mode interface.

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

### Application Accounts
* `POST /api/v1/app-accounts` — Provision application mailbox and generate Nextcloud / `.env` snippets.

### Mailbox Management
* `GET /api/v1/mailboxes` — List mailboxes for authenticated domain.
* `POST /api/v1/mailboxes` — Create a virtual mailbox.
* `POST /api/v1/mailboxes/{email}/password` — Reset mailbox password.
* `DELETE /api/v1/mailboxes/{email}` — Delete a mailbox (with optional storage purge).

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
* **GitHub:** [github.com/ternis-dev/ternis-mail-manager](https://github.com/ternis-dev/ternis-mail-manager)
