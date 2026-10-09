# Interview Guide

## 30-second explanation

This is a self-hosted threat-intelligence and SOC investigation platform. Connectors ingest public IOC, CVE, news, and MITRE ATT&CK data into a raw PostgreSQL landing zone. Processors normalize and deduplicate indicators while keeping sightings, then enrichment services and a composite scorer add context and priority. FastAPI exposes authenticated read APIs to a React dashboard and local Ollama assistant. Wazuh sends real alerts through a token-protected adapter; the backend extracts exact observables and correlates them with stored IOCs and CVEs while preserving the original event for audit.

## Data flow

```text
Threat feeds -> raw_items -> processors -> iocs/cves/articles/actors
             -> enrichment + risk -> FastAPI -> React dashboard
Wazuh alert -> signed adapter -> SIEM ingest -> exact IOC/CVE matches
MITRE STIX -> tactics/techniques/software -> actor mapping + investigations
```

## Strong design points

- Raw input is retained; normalized entities are reproducible.
- IOC uniqueness prevents duplication, while sightings preserve recurrence and provenance.
- Risk is multi-signal instead of trusting one reputation vendor.
- The chatbot and investigator are read-only and evidence-grounded.
- SIEM ingestion has a dedicated secret and stores the raw event plus match provenance.
- External API refresh can be paused to protect quotas.
- PostgreSQL backups, smoke tests, systemd units, nginx TLS, and rollback steps make it operable, not just demonstrable.

## Honest limitations

- Feed freshness depends on scheduled runs and third-party quotas; it is near-real-time only where sources and schedules allow.
- Exact SIEM correlation finds observables present in alerts; behavioral correlation still needs more analytics.
- Local LLM summaries can fail or be incomplete, so deterministic data views remain authoritative.
- TLS/systemd templates must be installed on the final host and validated in that environment.

## Verified result to mention

The Wazuh path was tested with an organically generated level-10 SSH brute-force alert (rule 5712) from the Ubuntu manager. It crossed the reverse SSH tunnel and appeared in the CTI SIEM event store automatically. A separate IOC-bearing adapter test verified exact local IOC matching.
