# Portfolio Evolution

This repository started from an authorized CTI codebase and was developed into a broader SOC investigation platform. This document separates the inherited foundation from the portfolio implementation without overstating authorship.

## Foundation retained

- Python/FastAPI backend and React dashboard structure
- PostgreSQL CTI storage
- baseline IOC/CVE ingestion, deduplication and risk concepts
- local Ollama integration

## Major capabilities added or substantially extended

### Threat data and enrichment

- BleepingComputer and generalized threat-news connectors
- VirusTotal IOC reputation enrichment
- GreyNoise IP context enrichment
- improved NVD/CVE enrichment and complete dashboard descriptions
- expanded APT extraction and actor-specific evidence
- API-quota-aware refresh control

### SOC investigation

- evidence-backed threat correlation across IOCs, malware, APT groups, CVEs and sightings
- MITRE ATT&CK ingestion from STIX with tactic, technique, software and group relationships
- dedicated ATT&CK coverage interface
- evidence-bounded AI investigation reports
- more capable project-aware chatbot queries for IOCs, CVEs, actors, enrichment and ATT&CK

### SIEM integration

- Wazuh/Elastic JSON intake endpoint
- dedicated SIEM bearer token boundary
- exact IOC/CVE extraction and local matching
- original-event and match-provenance storage
- Wazuh custom integration and forwarding utility
- automated SIEM tests and live Wazuh lab verification

### Security and operations

- corrected login/MFA flow and administrator setup
- JWT/TLS/same-origin production deployment
- nginx configuration and installer
- user-level systemd API and Wazuh tunnel services
- backend startup and tunnel helper scripts
- PostgreSQL backup/restore scripts
- smoke test, deployment checklist, operations runbook and interview guide
- expanded dashboard health, freshness and enrichment visibility

## Review trail

Use these commands to inspect the principal evolution commit without needing any secrets:

```bash
git show --stat 09d37b3
git diff upstream/main..main -- README.md backend frontend deploy scripts tests docs
```

The live proof image and verification matrix are available in `docs/overview-current.png` and `docs/VERIFIED_ACHIEVEMENTS.md`.
