# 🛡️ Custom Threat Intelligence Platform

> A self-hosted, AI-powered Cyber Threat Intelligence (CTI) platform that aggregates indicators from multiple public sources, deduplicates and enriches them, scores their risk, and surfaces everything through a secure, interactive dashboard with a natural-language query assistant.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688)
![React](https://img.shields.io/badge/React-dashboard-61dafb)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791)
![Ollama](https://img.shields.io/badge/LLM-Ollama_llama3.2-black)
![Security](https://img.shields.io/badge/Auth-MFA_%2B_TLS-red)

---

## 📖 Overview

This platform automates the full CTI lifecycle: **collect → normalize → enrich → score → serve**. It pulls threat data from multiple public feeds, resolves it into a clean, deduplicated database with a **sighting-tracking model** (so a recurring indicator is recorded, not duplicated), enriches indicators using **third-party reputation/infrastructure APIs** and a **local LLM**, assigns each indicator a **composite risk score**, and presents everything through an authenticated dashboard with an HTTPS deployment profile — including an **"ask your data" chatbot** that converts plain-English questions into safe SQL.

Built end-to-end as a hands-on SOC/DevSecOps project: data engineering, backend APIs, frontend, enrichment, automation, and production-grade security hardening.

---

## 📸 Screenshots

### Secure Login (MFA + TLS)
![Login](docs/login.png)

### Threat Intelligence Dashboard
![Dashboard](docs/dashboard.png)

### AI Chatbot — Ask Your Data
![Chatbot](docs/chatbot.png)

### IOC Explorer + Enrichment Detail
![IOCs](docs/iocs.png)

### APT Groups
![APT Groups](docs/apt.png)

### Threat Feed
![Threat Feed](docs/threat-feed.png)

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **Multi-source ingestion** | ransomware.live, abuse.ch ThreatFox, CISA KEV, NVD, The Hacker News |
| **Deduplication + Sightings** | Canonical normalization (defang, lowercase, port-strip) + recurring-indicator tracking |
| **IOC enrichment** | AbuseIPDB (reputation, reports, country, ISP) + Shodan (open ports, hosting org) |
| **Composite risk scoring** | Multi-signal score (feed + abuse + suspicious ports + sightings) → HIGH / MEDIUM / LOW |
| **LLM enrichment** | Local Ollama (llama3.2) extracts APT groups, malware, and per-IOC reasoning from articles |
| **CVE intelligence** | CVSS + severity (NVD) combined with actively-exploited flags (CISA KEV) |
| **Interactive dashboard** | React SPA with drill-down, charts, risk breakdown, enrichment detail panels |
| **AI chatbot** | Natural-language → SQL over the threat database (read-only, validated) |
| **Threat correlation** | Evidence-backed IOC ↔ malware ↔ actor ↔ CVE ↔ sighting investigation clusters |
| **MITRE ATT&CK analytics** | Tactic coverage, group-technique matrix, and actor-to-software mappings from STIX/TAXII |
| **AI-assisted investigation** | Read-only, evidence-grounded analyst reports over stored IOC, malware, actor, CVE, sighting, and ATT&CK context |
| **SIEM matching** | Token-protected Wazuh/Elastic JSON ingestion with exact local IOC/CVE matching and an auditable event trail |
| **Full automation** | Cron pipeline: ingest → process → enrich → score, daily, with per-run logging |

---

## 🎯 Composite Risk Scoring

A key design decision: **no single source is trusted alone.** An IP can score `0%` on AbuseIPDB (no community reports) yet still be a live C2 server. The platform combines multiple signals into one risk score:

```
risk = feed_presence (30)
     + abuse_score × 0.4        (AbuseIPDB reputation)
     + suspicious_ports (20)    (e.g. 4444, exposed RDP/SMB)
     + recurring (15)           (seen multiple times / sources)
     + source_confidence × 0.15
  → 0–100  →  HIGH / MEDIUM / LOW
```

**Example:** an IP with `0%` AbuseIPDB score but tagged as a RAT C2 in the feed, with port `4444` open on Shodan, seen twice → scored **HIGH**. This cross-source correlation catches threats a single reputation lookup would miss.

---

## 🏗️ Architecture

```
                 ┌──────────── SOURCES ────────────┐
                 │ ransomware.live · ThreatFox      │
                 │ CISA KEV · NVD · Hacker News     │
                 └────────────────┬─────────────────┘
                                  │  (cron, daily 08:00)
                                  ▼
                        ┌──────────────────┐
                        │   Connectors     │  raw JSONB landing
                        └────────┬─────────┘
                                 ▼
                        ┌──────────────────┐
                        │   Processors     │  normalize · dedup · sightings
                        │  + Ollama (LLM)  │  APT / malware / reasoning
                        └────────┬─────────┘
                                 ▼
                        ┌──────────────────┐
                        │   Enrichment     │  AbuseIPDB · Shodan
                        │   + Risk Scoring │  composite HIGH/MED/LOW
                        └────────┬─────────┘
                                 ▼
                     ┌────────────────────────┐
                     │   PostgreSQL           │  iocs · cves · articles
                     │   (clean, indexed)     │  apt_groups · sightings · enrichment
                     └───────┬────────────────┘
                             │  (read-only user)
                             ▼
                     ┌────────────────┐        ┌──────────────┐
                     │  FastAPI       │◄───────│  Ollama      │  text-to-SQL
                     │  (auth+MFA)    │        │  (chatbot)   │
                     └───────┬────────┘        └──────────────┘
                             │  HTTPS / JWT
                             ▼
                     ┌────────────────┐
                     │  nginx (TLS)   │  reverse proxy + static
                     └───────┬────────┘
                             ▼
                     ┌────────────────┐
                     │  React SPA     │  dashboard + chatbot
                     └────────────────┘
```

---

## 🔐 Security (DevSecOps)

Security was treated as a first-class concern, not an afterthought:

- **Authentication** — username + bcrypt-hashed password
- **MFA** — TOTP (Google Authenticator / Authy), out-of-band second factor
- **JWT** — signed, expiring session tokens
- **TLS/HTTPS** — all traffic encrypted (nginx reverse proxy)
- **Least privilege** — API + chatbot use a dedicated **read-only** database role; connectors use a separate write role
- **Chatbot safety** — SELECT-only validation, forbidden-keyword blocking, single-statement enforcement, query timeout
- **Investigation safety** — evidence-bounded prompts, no response actions, and a deterministic fallback when Ollama is unavailable
- **SIEM trust boundary** — ingestion uses a dedicated `X-SIEM-Token`, separate from interactive dashboard JWT sessions
- **CORS lockdown** — API accepts only the dashboard origin
- **Security headers** — anti-clickjacking, MIME-sniffing protection
- **Rate-limit-aware enrichment** — batched, throttled API calls with graceful 429 handling
- **Secrets hygiene** — no secrets in the repo; `.env` git-ignored, `.env.example` provided

---

## 🧰 Tech Stack

**Backend:** Python, FastAPI, psycopg2, python-jose (JWT), bcrypt, pyotp (MFA)
**Frontend:** React (Vite), Recharts, lucide-react, axios
**Data:** PostgreSQL 16, JSONB landing zone
**Enrichment:** AbuseIPDB API, Shodan API
**AI:** Ollama (llama3.2) — local, offline, free
**Infra:** Docker (Postgres/Ollama), nginx (TLS), systemd, cron

---

## 📊 Data Model Highlights

- **Raw landing zone** (`raw_items`, JSONB) — source of truth, never mutated
- **`iocs`** — deduplicated on `(ioc_type, value)`, with `times_seen`, `first/last_seen`, `is_active`, `risk_score`, `risk_level`
- **`ioc_sightings`** — every observation logged (source + timestamp)
- **`ioc_enrichment`** — AbuseIPDB + Shodan data per indicator
- **`cves`** — CVSS + severity + KEV flag
- **`articles` / `apt_groups`** — LLM-extracted intel
- **`attack_software` / `apt_software`** — ATT&CK software catalogue and actor-to-software mappings
- **`siem_events` / `siem_matches`** — original event payloads plus exact IOC/CVE matches and match provenance

---

## 🚀 Getting Started

> Prerequisites: Docker, Python 3.12, Node.js 20, Ollama with `llama3.2`

```bash
# 1. Backend (starts the local PostgreSQL instance first when needed)
cp backend/.env.example backend/.env  # first run only; fill in DB + API keys
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cd ..
./start_backend.sh

# 2. Admin + MFA setup (run from backend/)
cd backend
./venv/bin/python setup_admin.py
cd ..

# 3. Frontend (development)
cd frontend
cp .env.example .env
npm install
npm run dev -- --host 127.0.0.1 --port 5177

# 4. Run the full pipeline (ingest → process → enrich → score)
cd ../backend
./run_pipeline.sh --force
```

Development URLs: dashboard `http://127.0.0.1:5177`, API docs `http://127.0.0.1:8006/docs`.
For start/stop commands, Wazuh checks, backups, systemd auto-start, and nginx TLS deployment, see [the operations runbook](docs/OPERATIONS.md). Production builds use the same-origin `/api` proxy so credentials are not sent cross-origin.

### Optional Wazuh / Elastic event forwarding

SIEM ingestion is disabled until a dedicated secret is configured. Generate a token locally, place it in `backend/.env` as `SIEM_INGEST_TOKEN`, and restart the API. Do not reuse the dashboard password or JWT secret.

```bash
python -c 'import secrets; print(secrets.token_urlsafe(32))'
python siem_forwarder.py /path/to/wazuh-alert.json wazuh
```

The forwarder reads `SIEM_API_URL` and `SIEM_INGEST_TOKEN` from the environment. It accepts one JSON event or newline-delimited JSON, sends the original payload to `/siem/ingest`, and never prints the token. Use `elastic` as the source name for an Elastic webhook/export payload. The dashboard's **SIEM Matches** page remains readable while ingestion is disabled. The included Wazuh custom integration was verified with a manager-generated level-10 SSH brute-force alert; setup and replay-safe verification are documented in the runbook.

## ✅ Verification

```bash
# Offline SIEM unit tests
backend/venv/bin/python -m unittest discover -s tests -v

# Frontend production build and lint
cd frontend && npm run build && npm run lint

# Running-service smoke test
cd .. && ./scripts/smoke_test.sh

# Encrypted-permission PostgreSQL custom-format backup
./scripts/backup_database.sh
```

Deployment readiness and rollback checks are tracked in [docs/DEPLOY_CHECKLIST.md](docs/DEPLOY_CHECKLIST.md). A short interview-ready architecture explanation is in [docs/INTERVIEW_GUIDE.md](docs/INTERVIEW_GUIDE.md).

---

## 🗺️ Roadmap

- [x] Multi-source ingestion + dedup + sightings
- [x] LLM enrichment (Ollama)
- [x] AbuseIPDB + Shodan enrichment
- [x] Composite risk scoring (HIGH/MED/LOW)
- [x] Authenticated dashboard (MFA + TLS)
- [x] Natural-language chatbot
- [x] Full automation (daily cron pipeline)
- [x] Threat correlation and evidence graph
- [x] MITRE ATT&CK technique/software mapping
- [x] Read-only AI-assisted investigation
- [x] Wazuh/Elastic SIEM ingestion and CTI matching adapter
- [ ] STIX/TAXII + firewall blocklist export
- [ ] Time-series threat trends
- [ ] n8n AI workflows (daily brief, smart alerts)

---

## 📝 Notes

Personal learning + portfolio project demonstrating the full CTI engineering lifecycle — from raw feed ingestion to a secured, AI-assisted analyst interface with automated enrichment and risk scoring. All data sources are public and used within their terms.

---

*Built by [Aditya Raj](https://github.com/adityrajtiwary) 
