<div align="center">

<h1>ionosphere</h1>

### **A complete mail platform in one Node.js process.**

SMTP reception, IMAP and POP3 access, JMAP, outbound delivery, Sieve filtering, forwarding,
domain and account administration, and operational tooling — from one repository and one
application process. Protocol behavior is implemented as isolated state machines; sockets,
HTTP, and database access are thin adapters around them.

<br/>

[![ci](https://github.com/henryj-dev/ionosphere/actions/workflows/ci.yml/badge.svg)](https://github.com/henryj-dev/ionosphere/actions/workflows/ci.yml)
[![codeql](https://github.com/henryj-dev/ionosphere/actions/workflows/codeql.yml/badge.svg)](https://github.com/henryj-dev/ionosphere/actions/workflows/codeql.yml)

<br/>

![node](https://img.shields.io/badge/node-24%2B-5FA04E?logo=node.js&logoColor=white)
![typescript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)
![runtime deps](https://img.shields.io/badge/runtime%20deps-node%3A%20builtins-success)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

<br/>

> *The ionosphere is the layer that reflects a radio signal back down to earth — how a
> transmission reaches somewhere it has no straight line to.*

English · [한국어](README.ko.md)

</div>

---

> [!NOTE]
> This README describes behavior visible in the source code and tests. Production addresses, credentials, host fingerprints, and private deployment procedures are intentionally not included.

---

## Contents

- [The problem](#the-problem)
- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [How it fits together](#how-it-fits-together)
- [Protocol map](#protocol-map)
- [Configuration](#configuration)
- [Command line](#command-line)
- [HTTP API](#http-api)
- [HTTP, JMAP, and autoconfiguration](#http-jmap-and-autoconfiguration)
- [Smarthost and outbound delivery](#smarthost-and-outbound-delivery)
- [Mail security policy](#mail-security-policy)
- [Spam, abuse, and suppression](#spam-abuse-and-suppression)
- [Hard limits](#hard-limits)
- [Operations](#operations)
- [Development](#development)
- [Status & limitations](#status--limitations)
- [License](#license)

---

## The problem

Running mail means running a stack. One daemon accepts messages, another serves IMAP and POP3,
another filters, another signs outbound with DKIM, and something else holds the accounts and
aliases they all read. Each speaks its own configuration language, keeps its own state, and fails
in its own way. The seams are where mail goes missing — accepted by one component, refused by the
next, reconciled by nobody.

Ionosphere is one repository and one process. Reception, access, delivery, storage, authentication
and administration share a single domain model, and one administration command registry backs the
CLI, the REST API and the browser console, so those three cannot drift apart. Protocol behavior is
implemented as isolated state machines; sockets, HTTP and database access are thin adapters around
them, which is what makes the protocol layer testable without a socket.

---

## What it does

<table>
<tr>
<td align="center" width="25%"><strong>Receive</strong><br><sub>SMTP · LMTP<br>aliases · Sieve</sub></td>
<td align="center" width="25%"><strong>Access</strong><br><sub>IMAP · POP3<br>JMAP · push</sub></td>
<td align="center" width="25%"><strong>Deliver</strong><br><sub>MX · smarthost<br>queue · DKIM</sub></td>
<td align="center" width="25%"><strong>Control</strong><br><sub>REST · CLI<br>audit · metrics</sub></td>
</tr>
</table>

| Area | Features |
| --- | --- |
| Mail reception | SMTP, LMTP, aliases, catch-all, forwarding, Sieve |
| Mail access | IMAP, IMAPS, POP3, POP3S, JMAP |
| Outbound delivery | Queue, retries, direct MX delivery, smarthost, DSN, DKIM |
| Authentication | PLAIN, LOGIN, SCRAM-SHA-256, XOAUTH2, OAUTHBEARER |
| Mail security | SPF, DKIM, DMARC, MTA-STS, DANE/TLSA, SRS |
| Administration | REST API, CLI, browser administration console |
| Storage | SQLite, PostgreSQL, MySQL, local blobs, S3-compatible storage |
| Operations | Metrics, audit logs, blob GC, retention/reaper, webhooks, push |

### Choose a starting shape

| If you need… | Start with… | Add later… |
| --- | --- | --- |
| A local development server | SQLite + filesystem blobs + self-signed TLS | IMAP, JMAP, and the admin API |
| A single production node | SQLite or PostgreSQL + filesystem/S3 blobs | ACME, metrics, audit, and workers |
| Multiple mail nodes | PostgreSQL/MySQL + shared S3-compatible blobs | Per-listener TLS and role-specific workers |

### Defaults that protect you

| Boundary | Default behavior |
| --- | --- |
| Secrets at rest | Startup requires a master key; plaintext storage is an explicit opt-in |
| Optional listeners | Disabled until their port is configured |
| Plaintext authentication | Blocked when TLS is unavailable |
| Administration | Scope checks are enforced by HTTP method |
| S3 configuration | Partial configuration fails startup instead of falling back silently |
| Listener binding | Ambiguous numeric addresses are rejected |

---

## Quick start

- Node.js 24 or newer
- npm
- No database server or external runtime service is required for the default configuration
- pg for PostgreSQL or mysql2 for MySQL

Runtime code uses Node built-in node: modules. Development dependencies are installed for testing and type checking.

The following is a development configuration using local SQLite, local blob storage, and a self-signed certificate. example.com is a documentation-only example domain.

~~~bash
npm install

export IONOSPHERE_DB="$PWD/ionosphere.db"
export IONOSPHERE_BLOBS="$PWD/blobs"
export IONOSPHERE_MASTER_KEY="$(openssl rand -hex 32)"

IONOSPHERE_HOSTNAME=mail.example.com \
IONOSPHERE_TLS_MODE=selfsigned \
IONOSPHERE_TLS_DIR="$PWD/tls" \
IONOSPHERE_SMTP_STARTTLS=1 \
IONOSPHERE_SMTP_PORT=2525 \
node apps/server/src/main.ts
~~~

The default development listeners use unprivileged ports:

- SMTP: 2525
- POP3: 1110

IMAP, IMAPS, Submission, JMAP, ManageSieve, the administration API, and other optional listeners start only when their port is configured.

### Loading a .env file

The server does not load the npm `dotenv` package. Node.js 24 provides the required behavior natively through `--env-file`:

~~~bash
node --env-file=.env apps/server/src/main.ts
node --env-file=.env apps/server/src/cli.ts help
~~~

Example `.env`:

~~~dotenv
IONOSPHERE_DB=./ionosphere.db
IONOSPHERE_BLOBS=./blobs
IONOSPHERE_MASTER_KEY=replace-with-a-long-random-secret
IONOSPHERE_HOSTNAME=mail.example.com
IONOSPHERE_TLS_MODE=selfsigned
IONOSPHERE_SMTP_STARTTLS=1
IONOSPHERE_SMTP_PORT=2525
~~~

Keep `.env` out of version control. It may contain database passwords, API tokens, private keys, and the master key. Add it to `.gitignore` for local development.

---

## How it fits together

<div align="center">
<img src="assets/ionosphere-flow.svg" alt="Ionosphere mail flow from protocol surfaces through the core to shared state, message blobs, and workers" width="900">
</div>

The same administration command registry powers the CLI, REST API, and browser console, keeping the three management surfaces aligned.

<div align="center">

<table>
<tr>
<td valign="top" width="33%"><h3>🧩 One platform</h3><sub>Inbound, outbound, storage, authentication, and administration share the same domain model.</sub></td>
<td valign="top" width="33%"><h3>🔒 Fail closed</h3><sub>TLS, host routing, scopes, limits, and secret handling reject ambiguous configuration early.</sub></td>
<td valign="top" width="33%"><h3>🧪 Testable core</h3><sub>Protocol engines are deterministic state machines, separated from sockets and external I/O.</sub></td>
</tr>
</table>

</div>

---

## Protocol map

| Surface | Typical listener | Transport | What it is for |
| --- | --- | --- | --- |
| SMTP | 25 / 2525 | Plain + STARTTLS | Inbound mail from other MTAs |
| Submission | 587 | STARTTLS | Authenticated client submission |
| SMTPS | 465 | Implicit TLS | Authenticated client submission over TLS |
| IMAP | 143 | STARTTLS | Mailbox access and synchronization |
| IMAPS | 993 | Implicit TLS | Mailbox access over TLS |
| POP3 | 110 / 1110 | Plain + TLS policy | Simple maildrop retrieval |
| POP3S | 995 | Implicit TLS | Maildrop retrieval over TLS |
| JMAP | HTTP | HTTP + TLS front | Modern mail and submission API |
| ManageSieve | 4190 | STARTTLS | Sieve script management |
| LMTP | Local port | Trusted local channel | Per-recipient local delivery |

---

## Configuration

### Storage configuration

### Database

~~~bash
# SQLite
IONOSPHERE_DB=./ionosphere.db

# PostgreSQL
IONOSPHERE_DB_URL=postgres://user:password@db.example.com:5432/ionosphere

# MySQL
IONOSPHERE_DB_URL=mysql://user:password@db.example.com:3306/ionosphere
~~~

IONOSPHERE_DB_URL takes precedence over IONOSPHERE_DB. SQLite is intended for a single-writer deployment. Use PostgreSQL or MySQL when multiple servers must share state.

Database drivers are loaded lazily, so SQLite-only deployments do not need pg or mysql2 at runtime.

### Message blobs

The default blob store is the local filesystem:

~~~bash
IONOSPHERE_BLOBS=./blobs
~~~

For S3-compatible storage, all four core settings are required:

~~~bash
IONOSPHERE_S3_ENDPOINT=https://s3.example.com
IONOSPHERE_S3_BUCKET=ionosphere-mail
IONOSPHERE_S3_ACCESS_KEY=access-key
IONOSPHERE_S3_SECRET_KEY=secret-key
IONOSPHERE_S3_REGION=us-east-1
IONOSPHERE_S3_PREFIX=mail/
IONOSPHERE_S3_PATH_STYLE=1
IONOSPHERE_S3_TIMEOUT_MS=30000
~~~

Partial S3 configuration stops startup instead of silently falling back to local storage. During a filesystem-to-S3 migration, keep the local filesystem as a read fallback with IONOSPHERE_S3_MIGRATE_FROM_FS=1.

### Secrets at rest

Production deployments should set:

~~~bash
IONOSPHERE_MASTER_KEY=strong-random-master-key
~~~

The master key seals stored secrets such as DKIM private keys and smarthost passwords. Development-only plaintext storage can be explicitly enabled with IONOSPHERE_ALLOW_PLAINTEXT_SECRETS=1. This emits a warning and stores applicable values with a plain$ prefix.

### Listeners and networking

| Service | Environment variable | Default |
| --- | --- | --- |
| SMTP reception | IONOSPHERE_SMTP_PORT | 2525 |
| POP3 | IONOSPHERE_POP3_PORT | 1110 |
| IMAP | IONOSPHERE_IMAP_PORT | none |
| IMAPS | IONOSPHERE_IMAPS_PORT | none |
| POP3S | IONOSPHERE_POP3S_PORT | none |
| LMTP | IONOSPHERE_LMTP_PORT | none |
| Submission | IONOSPHERE_SUBMISSION_PORT | none |
| SMTPS | IONOSPHERE_SMTPS_PORT | none |
| ManageSieve | IONOSPHERE_MANAGESIEVE_PORT | none |
| JMAP | IONOSPHERE_JMAP_PORT | none |
| Administration API | IONOSPHERE_ADMIN_PORT | none |
| Autoconfig | IONOSPHERE_AUTOCONFIG_PORT | none |
| HTTPS front | IONOSPHERE_HTTPS_FRONT_PORT | none |
| HTTP redirect | IONOSPHERE_HTTP_REDIRECT_PORT | none |
| Metrics | IONOSPHERE_METRICS_PORT | none |

Port values must be integers from 0 through 65535. For direct SMTP and POP3 settings, 0 may be used as an ephemeral test port. Disable a listener with off, false, no, or disabled.

Override a listener bind address and port with IONOSPHERE_LISTEN_<SERVICE>:

~~~bash
IONOSPHERE_LISTEN_ADMIN=127.0.0.1:8080
IONOSPHERE_LISTEN_METRICS=10.0.0.10:9090
IONOSPHERE_LISTEN_IMAP=0.0.0.0:143
IONOSPHERE_LISTEN_IMAPS='[::]:993'
IONOSPHERE_LISTEN_SMTP=off
~~~

Supported forms include 8080, 0.0.0.0:8080, 127.0.0.1:, [::]:8080, and off. IPv6 addresses require brackets. Invalid or ambiguous numeric address forms are rejected at startup.

### TLS and certificates

Select the default certificate source with IONOSPHERE_TLS_MODE:

~~~bash
IONOSPHERE_TLS_MODE=none
IONOSPHERE_TLS_MODE=selfsigned
IONOSPHERE_TLS_MODE=file
IONOSPHERE_TLS_MODE=url
IONOSPHERE_TLS_MODE=acme
IONOSPHERE_TLS_DIR=/var/lib/ionosphere/tls
IONOSPHERE_TLS_CN=mail.example.com
IONOSPHERE_TLS_SANS=mail.example.com,imap.example.com
~~~

File certificates:

~~~bash
IONOSPHERE_TLS_MODE=file
IONOSPHERE_TLS_CERT=/etc/ionosphere/tls/fullchain.pem
IONOSPHERE_TLS_KEY=/etc/ionosphere/tls/privkey.pem
~~~

Legacy IMAPS certificate variables are also supported:

~~~bash
IONOSPHERE_IMAPS_TLS_CERT=/etc/ionosphere/tls/fullchain.pem
IONOSPHERE_IMAPS_TLS_KEY=/etc/ionosphere/tls/privkey.pem
~~~

Remote certificates:

~~~bash
IONOSPHERE_TLS_MODE=url
IONOSPHERE_TLS_URL_CERT=https://cert.example.com/mail/cert.pem
IONOSPHERE_TLS_URL_KEY=https://cert.example.com/mail/key.pem
IONOSPHERE_TLS_URL_AUTH='Bearer token'
~~~

ACME:

~~~bash
IONOSPHERE_TLS_MODE=acme
IONOSPHERE_TLS_ACME_DOMAINS=mail.example.com
IONOSPHERE_TLS_ACME_EMAIL=admin@example.com
IONOSPHERE_TLS_ACME_CHALLENGE=http-01
IONOSPHERE_TLS_ACME_HTTP_PORT=80
~~~

http-01 is the default and opens its challenge listener only while issuing or renewing a certificate. Cloudflare DNS-01 uses IONOSPHERE_TLS_ACME_CHALLENGE=dns-01, IONOSPHERE_CF_DNS_TOKEN, IONOSPHERE_CF_ZONE_ID, and IONOSPHERE_TLS_ACME_DNS_PROVIDER=cloudflare.

Startup is rejected if the ACME http-01 port and the HTTP redirect port conflict.

Per-listener certificates use the IONOSPHERE_TLS_<LISTENER>_ prefix:

~~~bash
IONOSPHERE_TLS_SMTP_MODE=file
IONOSPHERE_TLS_SMTP_CERT=/etc/ionosphere/tls/smtp-cert.pem
IONOSPHERE_TLS_SMTP_KEY=/etc/ionosphere/tls/smtp-key.pem
IONOSPHERE_TLS_SMTP_CN=mx.example.com
~~~

Supported listener names are SMTP, SUBMISSION, SMTPS, IMAP, IMAPS, POP3, POP3S, MANAGESIEVE, HTTPS_FRONT, and ADMIN_TLS.

### Environment variable reference

Core, database, and storage:

~~~text
IONOSPHERE_HOSTNAME
IONOSPHERE_DB
IONOSPHERE_DB_URL
IONOSPHERE_BLOBS
IONOSPHERE_MASTER_KEY
IONOSPHERE_ALLOW_PLAINTEXT_SECRETS
IONOSPHERE_S3_ENDPOINT
IONOSPHERE_S3_BUCKET
IONOSPHERE_S3_ACCESS_KEY
IONOSPHERE_S3_SECRET_KEY
IONOSPHERE_S3_REGION
IONOSPHERE_S3_PREFIX
IONOSPHERE_S3_PATH_STYLE
IONOSPHERE_S3_TIMEOUT_MS
IONOSPHERE_S3_MIGRATE_FROM_FS
~~~

Ports and binding:

~~~text
IONOSPHERE_SMTP_PORT
IONOSPHERE_SUBMISSION_PORT
IONOSPHERE_SMTPS_PORT
IONOSPHERE_POP3_PORT
IONOSPHERE_POP3S_PORT
IONOSPHERE_IMAP_PORT
IONOSPHERE_IMAPS_PORT
IONOSPHERE_LMTP_PORT
IONOSPHERE_MANAGESIEVE_PORT
IONOSPHERE_JMAP_PORT
IONOSPHERE_ADMIN_PORT
IONOSPHERE_AUTOCONFIG_PORT
IONOSPHERE_HTTPS_FRONT_PORT
IONOSPHERE_HTTP_REDIRECT_PORT
IONOSPHERE_METRICS_PORT
IONOSPHERE_METRICS_HOST
IONOSPHERE_LISTEN_<SERVICE>
~~~

TLS and ACME:

~~~text
IONOSPHERE_TLS_MODE
IONOSPHERE_TLS_DIR
IONOSPHERE_TLS_CN
IONOSPHERE_TLS_SANS
IONOSPHERE_TLS_CERT
IONOSPHERE_TLS_KEY
IONOSPHERE_TLS_URL_CERT
IONOSPHERE_TLS_URL_KEY
IONOSPHERE_TLS_URL_AUTH
IONOSPHERE_TLS_ACME_DOMAINS
IONOSPHERE_TLS_ACME_EMAIL
IONOSPHERE_TLS_ACME_DIRECTORY
IONOSPHERE_TLS_ACME_CHALLENGE
IONOSPHERE_TLS_ACME_HTTP_PORT
IONOSPHERE_TLS_ACME_DNS_PROVIDER
IONOSPHERE_TLS_<LISTENER>_MODE
IONOSPHERE_TLS_<LISTENER>_CN
IONOSPHERE_TLS_<LISTENER>_SANS
IONOSPHERE_TLS_<LISTENER>_CERT
IONOSPHERE_TLS_<LISTENER>_KEY
IONOSPHERE_TLS_<LISTENER>_URL_CERT
IONOSPHERE_TLS_<LISTENER>_URL_KEY
IONOSPHERE_CF_DNS_TOKEN
IONOSPHERE_CF_ZONE_ID
~~~

Policy, delivery, and service hosts:

~~~text
IONOSPHERE_HOST_<SERVICE>
IONOSPHERE_IMAP_HOST
IONOSPHERE_SUBMISSION_HOST
IONOSPHERE_POP3_HOST
IONOSPHERE_MX_HOST
IONOSPHERE_AUTOCONFIG_BRAND
IONOSPHERE_JMAP_BASE_URL
IONOSPHERE_ADMIN_TOKEN
IONOSPHERE_SMARTHOST
IONOSPHERE_SMARTHOST_PORT
IONOSPHERE_SMARTHOST_USER
IONOSPHERE_SMARTHOST_PASS
IONOSPHERE_SMARTHOST_TLS
IONOSPHERE_SMARTHOST_SECRET
IONOSPHERE_RATE_PER_MINUTE
IONOSPHERE_RATE_PER_HOUR
IONOSPHERE_RATE_PER_DAY
IONOSPHERE_RELAY_PER_HOUR
IONOSPHERE_LOCAL_ONLY
IONOSPHERE_REQUIRE_SENDER_OWNERSHIP
IONOSPHERE_SRS_SECRET
IONOSPHERE_MTA_STS_MODE
IONOSPHERE_MTA_STS_ENFORCE
IONOSPHERE_DANE
IONOSPHERE_SMTP_STARTTLS
IONOSPHERE_RECURSIVE_DNS
~~~

Workers, GC, audit, and logging:

~~~text
IONOSPHERE_RUN_MTA_WORKER
IONOSPHERE_RUN_WEBHOOK_WORKER
IONOSPHERE_RUN_REAPER
IONOSPHERE_BLOB_GC
IONOSPHERE_BLOB_GC_GRACE_MS
IONOSPHERE_BLOB_UPLOAD_TTL_MS
IONOSPHERE_AUDIT
IONOSPHERE_AUDIT_DIR
IONOSPHERE_AUDIT_FLUSH_MS
IONOSPHERE_AUDIT_SHIP_INTERVAL_MS
IONOSPHERE_AUDIT_LOCAL_RETAIN_DAYS
IONOSPHERE_AUDIT_SHIP_HOST
IONOSPHERE_AUDIT_S3_ENDPOINT
IONOSPHERE_AUDIT_S3_BUCKET
IONOSPHERE_AUDIT_S3_ACCESS_KEY
IONOSPHERE_AUDIT_S3_SECRET_KEY
IONOSPHERE_AUDIT_S3_REGION
IONOSPHERE_AUDIT_S3_PREFIX
IONOSPHERE_AUDIT_S3_PATH_STYLE
IONOSPHERE_LOG_LEVEL
IONOSPHERE_LOG_FORMAT
~~~

</details>

---

## Command line

The CLI follows the same database selection rules as the server.

~~~bash
export IONOSPHERE_DB="$PWD/ionosphere.db"
export IONOSPHERE_MASTER_KEY="$(openssl rand -hex 32)"

node apps/server/src/cli.ts help
node apps/server/src/cli.ts help domain-add
node apps/server/src/cli.ts domain-add example.com
node apps/server/src/cli.ts account-create alice@example.com 'change-this-password'
~~~

General syntax:

~~~text
node apps/server/src/cli.ts <command> [--key=value ...]
node apps/server/src/cli.ts help
node apps/server/src/cli.ts help <command>
~~~

Avoid placing secrets in argv. Smarthost passwords and TLS private keys can be supplied through stdin or environment variables:

~~~bash
export IONOSPHERE_CLI_SECRET='secret-value'
export IONOSPHERE_SMARTHOST_SECRET='relay-password'
~~~

### Available commands

Domains:

- domain-list, domain-add, domain-verify
- domain-disable, domain-enable, domain-release

Accounts and credentials:

- account-list, account-create, account-suspend
- account-activate, account-delete
- app-password-list, app-password-create
- oauth-token-list, oauth-token-create, credential-revoke

Routing:

- alias-list, alias-add, alias-remove

Delivery operations:

- queue-list, queue-retry, queue-cancel
- suppression-list, suppression-remove, usage
- smarthost-list, smarthost-set, smarthost-remove

Tenants, API keys, and TLS:

- tenant-list, tenant-create
- api-key-list, api-key-create, api-key-revoke
- tls-status, tls-refresh, tls-upload

REST domain operations require ownership TXT, MX, and SPF verification before a domain can be used. The CLI is a local operator tool and preserves a compatibility path with relaxed verification defaults; use --preVerified=false when the verification flow is required.

Account deletion starts an irreversible drain. Use account-suspend for a reversible lock. App passwords and OAuth tokens are shown in plaintext only when they are created.

Aliases can route to multiple local accounts or external addresses. A local part of * creates a catch-all. External forwarding requires an SRS secret:

~~~bash
export IONOSPHERE_SRS_SECRET="$(openssl rand -hex 32)"
~~~

API key scopes are read, write, and admin. read permits reads, write permits reads and changes, and admin grants full access.

---

## HTTP API

The administration API starts when IONOSPHERE_ADMIN_PORT is configured:

~~~bash
IONOSPHERE_ADMIN_PORT=8080
IONOSPHERE_ADMIN_TOKEN=bootstrap-root-token
~~~

Authenticate with:

~~~http
Authorization: Bearer <api-key-or-root-token>
~~~

The API covers tenants, accounts, domains, aliases, API keys, app passwords, OAuth tokens, credentials, queue, suppressions, usage, smarthosts, and TLS under the /v1/ path.

GET requests require read; other methods require write. admin scope and the root token have full access. The root token is a bootstrap mechanism and has no automatic rotation implementation.

---

## HTTP, JMAP, and autoconfiguration

JMAP:

~~~bash
IONOSPHERE_JMAP_PORT=8080
IONOSPHERE_JMAP_BASE_URL=https://mail.example.com
~~~

Main paths:

~~~text
GET  /jmap/session
POST /jmap/api
POST /jmap/upload
GET  /jmap/download/<account>/<blob>
GET  /jmap/eventsource
~~~

Implemented modules include Mailbox, Email, Email/query, EmailSubmission, Quota, VacationResponse, PushSubscription, and SearchSnippet. Request bodies are limited to about 10 MB, one upload to 50,000,000 bytes, SSE connections to 256, and the authentication cache to 10,000 entries.

Autoconfiguration:

~~~bash
IONOSPHERE_AUTOCONFIG_PORT=8081
IONOSPHERE_AUTOCONFIG_BRAND=Example Mail
IONOSPHERE_IMAP_HOST=imap.example.com
IONOSPHERE_SUBMISSION_HOST=smtp.example.com
IONOSPHERE_POP3_HOST=pop3.example.com
~~~

POP3 is not advertised merely because its port is open; set IONOSPHERE_POP3_HOST when it should appear in client configuration.

HTTPS front and host allowlists:

~~~bash
IONOSPHERE_HTTPS_FRONT_PORT=443
IONOSPHERE_HTTP_REDIRECT_PORT=80
IONOSPHERE_HOST_MTA_STS=mta-sts.example.com
IONOSPHERE_HOST_ADMIN=admin.example.com
IONOSPHERE_HOST_METRICS=metrics.example.com
~~~

Service hosts are comma-separated. Hosts not on the allowlist are not routed. When a service host is omitted, only its localhost default is accepted. The administration console also applies an internal-exposure check; hiding a name in DNS is not its security boundary.

---

## Smarthost and outbound delivery

~~~bash
IONOSPHERE_SMARTHOST=smtp.example.com
IONOSPHERE_SMARTHOST_PORT=587
IONOSPHERE_SMARTHOST_USER=relay-user
IONOSPHERE_SMARTHOST_PASS=relay-password
IONOSPHERE_SMARTHOST_TLS=required
~~~

TLS modes are required, opportunistic, implicit, and never. Port 587 is intended for STARTTLS and port 465 for implicit TLS.

Outbound controls:

~~~bash
IONOSPHERE_RATE_PER_MINUTE=...
IONOSPHERE_RATE_PER_HOUR=...
IONOSPHERE_RATE_PER_DAY=...
IONOSPHERE_RELAY_PER_HOUR=...
IONOSPHERE_LOCAL_ONLY=1
IONOSPHERE_REQUIRE_SENDER_OWNERSHIP=0
~~~

IONOSPHERE_LOCAL_ONLY=1 blocks external-domain delivery, although a real smarthost route can provide an explicit outbound exception. Sender ownership checks are enabled by default.

---

## Mail security policy

When TLS material is unavailable or STARTTLS cannot actually be performed, plaintext authentication is disabled by default. Depending on the protocol surface, the implementation supports PLAIN, LOGIN, SCRAM-SHA-256, XOAUTH2, and OAUTHBEARER.

The inbound path evaluates and stores SPF, DKIM, and DMARC results. The outbound path can apply DKIM signatures. Domain provisioning generates DKIM keys and DNS record instructions.

MTA-STS modes are enforce, testing, and none:

~~~bash
IONOSPHERE_MTA_STS_MODE=enforce
IONOSPHERE_MTA_STS_ENFORCE=1
IONOSPHERE_MX_HOST=mx.example.com
IONOSPHERE_DANE=1
~~~

DANE uses DNSSEC-validated TLSA results for outbound TLS. Before enabling MTA-STS enforcement, align the MX host, HTTPS front, and host allowlist.

SRS enables external forwarding and forwarding bounce reversal:

~~~bash
IONOSPHERE_SRS_SECRET=strong-random-secret
~~~

An unset or empty value leaves SRS forwarding disabled.

---

## Spam, abuse, and suppression

The code includes greylisting, SPF-pass greylist exemptions, a DNSBL integration point, per-account Bayes training, bounce and complaint monitoring, automatic account suspension, and suppression lists.

Default abuse thresholds:

- Observation window: 24 hours
- Minimum sample: 20 messages
- Bounce rate: over 10%
- Complaint rate: over 0.3%

---

## Hard limits

Protocol-wide safety limits are defined in packages/core/src/limits.ts.

| Limit | Value |
| --- | ---: |
| Maximum message | 25 MiB |
| SMTP/LMTP recipients per session | 1000 |
| SMTP errors per session | 20 |
| Maximum listener connections | 1024 |
| Received hops | 30 |
| SMTP/LMTP/POP3 command line | 4096 bytes |
| Header section | 1 MiB |
| Header line | 64 KiB |
| IMAP line | 64 KiB |
| Pending pipeline | 1 MiB |
| Pre-auth IMAP literal | 8 KiB |
| Queued IMAP line | 1 MiB |
| MIME depth | 20 |
| MIME parts | 1024 |
| Thread references | 64 |
| Addresses per header | 256 |
| JMAP upload | 50,000,000 bytes |

These are code-level safety limits, not ordinary environment configuration.

---

## Operations

### Background workers and retention

~~~bash
IONOSPHERE_RUN_MTA_WORKER=1
IONOSPHERE_RUN_WEBHOOK_WORKER=1
IONOSPHERE_RUN_REAPER=1
~~~

The MTA worker is enabled by default when Submission is enabled. The webhook worker and reaper are enabled by default.

Blob GC:

~~~bash
IONOSPHERE_BLOB_GC=off
IONOSPHERE_BLOB_GC=mark
IONOSPHERE_BLOB_GC=sweep
IONOSPHERE_BLOB_GC_GRACE_MS=...
IONOSPHERE_BLOB_UPLOAD_TTL_MS=...
~~~

The default GC mode is mark. sweep can delete files and should be enabled only after reviewing mark results.

Store retention defaults are 30 days for the change log, 180 days for thread references, and 7 days for completed or failed queue entries.

### Audit logs

~~~bash
IONOSPHERE_AUDIT=1
IONOSPHERE_AUDIT_DIR=/var/lib/ionosphere/audit
IONOSPHERE_AUDIT_FLUSH_MS=1000
IONOSPHERE_AUDIT_SHIP_INTERVAL_MS=60000
IONOSPHERE_AUDIT_LOCAL_RETAIN_DAYS=30
IONOSPHERE_AUDIT_SHIP_HOST=server-1
~~~

S3 shipping:

~~~bash
IONOSPHERE_AUDIT_S3_ENDPOINT=https://audit-s3.example.com
IONOSPHERE_AUDIT_S3_BUCKET=ionosphere-audit
IONOSPHERE_AUDIT_S3_ACCESS_KEY=audit-access-key
IONOSPHERE_AUDIT_S3_SECRET_KEY=audit-secret-key
IONOSPHERE_AUDIT_S3_REGION=us-east-1
IONOSPHERE_AUDIT_S3_PREFIX=audit/
IONOSPHERE_AUDIT_S3_PATH_STYLE=1
~~~

Partial audit S3 configuration stops startup. Keep audit storage in a separate bucket and permission scope from message blobs.

<details>
<summary><strong>Show the complete environment variable reference</strong></summary>

### Operations checklist

1. Set the same IONOSPHERE_MASTER_KEY for every server and CLI process that shares encrypted data.
2. When multiple servers share a database, use shared S3-compatible blob storage as well.
3. Protect the administration API, root token, and API keys from unnecessary external exposure.
4. Ensure ACME http-01 and HTTP redirect do not use the same port.
5. Before enabling MTA-STS enforce, align the MX host, HTTPS front, and host allowlist.
6. If external forwarding is enabled, verify that IONOSPHERE_SRS_SECRET is non-empty.
7. Review blob GC mark results and fallback reads before enabling IONOSPHERE_BLOB_GC=sweep.
8. Use separate buckets and permissions for audit logs and mail blobs.
9. Do not put ordinary passwords in CLI argv when shell history exposure matters.
10. Treat startup validation errors as configuration failures; fix port, TLS, S3, and master-key settings before continuing.

---

## Development

~~~bash
npm run lint
npm run typecheck
npm test
npm run smoke
npm run verify
~~~

`npm run verify` runs lint, type checking, the complete test suite, and smoke checks.

Repository areas:

~~~text
apps/server/             Runnable server and CLI
packages/core/           Shared limits, authentication, logging, security
packages/db/             SQLite/PostgreSQL/MySQL abstractions and migrations
packages/store/          Accounts, mailboxes, messages, blob storage
packages/proto-*/        Protocol state machines and socket adapters
packages/mta/            Queue, SMTP client, outbound worker
packages/admin-cmd/      Shared administration commands
packages/api/            Administration HTTP API
packages/tls/            Certificate, ACME, and TLS material management
packages/dns/            DNS wire protocol, resolver, DNSSEC
packages/mail-auth/      SPF, DKIM, and DMARC functionality
packages/spam/           Greylisting, Bayes, spam integration
packages/webhook/        Webhook worker and storage
scripts/                 Verification, migration, and operational helpers
~~~

Protocol engines keep state transitions in engine.ts so they can be tested without a network. server.ts handles actual connections.

---

## Status & limitations

**What works.** SMTP and LMTP reception with aliases, catch-all, forwarding and Sieve; IMAP,
IMAPS, POP3, POP3S and JMAP access; an outbound queue with retries, direct MX delivery,
smarthost, DSN and DKIM; PLAIN, LOGIN, SCRAM-SHA-256, XOAUTH2 and OAUTHBEARER authentication;
SPF, DKIM, DMARC, MTA-STS, DANE/TLSA and SRS; a REST API, a CLI and a browser administration
console over one command registry; SQLite, PostgreSQL or MySQL with local or S3-compatible blob
storage; metrics, audit logs, blob GC, retention and webhooks.

**Not frozen.** Every one of the 24 packages in this repository is at version `0.0.1`. The
database schema, the environment-variable surface and the administration API are all expected to
change. Pin what you deploy, and read [`SCHEMA.md`](docs/SCHEMA.md) before upgrading.

---

## License

MIT. See [LICENSE](LICENSE).

<sub>Built for reliable mail delivery, clear boundaries, and boring operations.</sub>
