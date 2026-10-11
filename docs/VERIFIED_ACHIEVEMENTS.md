# Verified Achievements

This document records the evidence behind the portfolio claims in the repository. It intentionally contains no passwords, API keys, tokens, MFA seeds or private infrastructure credentials.

## Verification snapshot

The dashboard evidence was captured on **2026-10-07**, and deployment/SIEM verification continued on **2026-10-09**.

| Evidence | Result |
|---|---|
| Dashboard dataset | 5,253 IOCs; 1,709 CVEs; 199 APT groups |
| ATT&CK coverage | 4,606 actor/technique mappings |
| Enrichment coverage | 4 VirusTotal IOCs; 22 GreyNoise IPs; 25 NVD-enriched CVEs |
| IOC risk distribution | 2 high; 3,621 medium; 1,630 low |
| Wazuh integration | Real manager-generated event ingested: rule `5712`, level `10`, Ubuntu agent, SSH brute-force title |
| Wazuh matching path | A separate replay-safe test event produced an exact local IOC match for `45.78.201.248`; the test record was removed afterward |
| Automated SIEM tests | 4 unit tests passed |
| Frontend | Production build passed; lint exited successfully with advisory React warnings only |
| Database recovery | PostgreSQL custom-format backup created, mode `600`, and format validated |
| Service smoke test | API and frontend checks passed in the deployed lab |
| Secret hygiene | Real `.env` files, work files and backups are ignored; repository/history scan found no high-confidence secret patterns |

`docs/overview-current.png` is a current application capture from that deployed dataset.

## Evidence matrix

| Achievement | Repository evidence | What was verified |
|---|---|---|
| Expanded live-feed ingestion | `backend/connector_bleeping.py`, `backend/connector_news.py`, updated connectors and `backend/run_pipeline.sh` | Sources can land raw records and progress through the pipeline |
| VirusTotal and GreyNoise enrichment | `backend/enrich_virustotal.py`, `backend/enrich_greynoise.py` | Coverage is visible in the live dashboard without exposing keys |
| NVD CVE completion | `backend/connector_nvd.py`, `backend/enrich_cves.py` | CVE descriptions, score/severity and enrichment state are served to the UI |
| Actor intelligence improvement | `backend/threat_actors.py`, `backend/processor_articles.py` | APT records use actor-specific evidence and no longer rely on one repeated generic description |
| MITRE ATT&CK mapping | `backend/connector_mitre_attack.py`, `backend/schema_phase2.sql` | Tactics, techniques, software and actor relationships are stored and displayed |
| Cross-entity correlation | Correlation endpoints in `backend/api.py` and correlation views in `frontend/src/App.jsx` | Analysts can pivot across IOC, malware, actor, CVE and sighting evidence |
| Local AI assistant | `backend/chatbot.py`, `frontend/src/ChatBot.jsx` | Handles project-domain questions using guarded read-only queries and clear unsupported-query guidance |
| AI investigation | Investigation endpoints in `backend/api.py` and investigation views in `frontend/src/App.jsx` | Reports remain evidence-bounded and read-only, with a deterministic fallback |
| SIEM integration | `backend/siem.py`, `backend/siem_forwarder.py`, `backend/custom-threatintel`, `tests/test_siem.py` | Wazuh event ingestion, audit storage and exact IOC/CVE matching work end to end |
| HTTPS and service operation | `deploy/nginx/`, `deploy/systemd/`, `scripts/install_nginx.sh`, `scripts/install_user_services.sh` | nginx TLS, API autostart and Wazuh tunnel service were configured in the lab |
| Recovery and release safety | `scripts/backup_database.sh`, `scripts/restore_database.sh`, `scripts/smoke_test.sh`, `docs/DEPLOY_CHECKLIST.md` | Backup, restore procedure, smoke checks and rollback gates are documented |
| Quota protection | `backend/schedule_refresh.sh` and operations documentation | Automatic IOC refresh can be disabled when external API quota must be preserved |

## Measured code evolution

The principal implementation commit `09d37b3` records:

- 46 changed files
- 3,827 insertions
- 203 deletions
- new correlation, ATT&CK, AI investigation, SIEM, operations and enrichment modules

This is stronger evidence than a percentage-improvement claim: reviewers can inspect the implementation and reproduce the verification commands.

## Evidence boundaries

- Counts are snapshots and will change after feed refreshes.
- The local TLS certificate is suitable for the lab; public deployment should use a trusted CA certificate.
- External enrichment results depend on provider availability, account tier and rate limits.
- The verified Wazuh event had zero CTI matches, which is expected for an SSH username brute-force alert containing no stored IOC/CVE. Exact-match behavior was separately tested with a controlled Wazuh-style event.
- No automated containment is performed. Investigation and SIEM views are deliberately read-only.
