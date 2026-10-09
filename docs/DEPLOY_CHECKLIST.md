# Deployment Checklist

## Pre-deployment

- [x] Secrets live only in ignored `backend/.env` / `frontend/.env` files.
- [x] Backend binds to loopback by default.
- [x] Production frontend uses same-origin `/api`.
- [x] SIEM ingestion uses a separate constant-time-checked token.
- [x] Wazuh custom adapter and reverse tunnel were proven with a manager-generated alert.
- [x] Offline SIEM tests pass.
- [x] Frontend build and lint pass.
- [x] Database backup command is verified.
- [ ] Install a valid TLS certificate and deploy the nginx template.
- [ ] Install/enable user systemd units on the final host.

## Release verification

1. Run `./scripts/smoke_test.sh`.
2. Log in with password and current MFA code.
3. Confirm Overview, IOCs, CVEs, APT, ATT&CK, Correlations, SIEM Matches, and chatbot pages load.
4. Confirm Automation is paused or enabled according to the intended API quota budget.
5. Generate one benign Wazuh test alert and confirm the SIEM event count increases.
6. Confirm recent pipeline status and inspect its log before presenting fresh data as current.

## Rollback triggers

Rollback if login fails for a known-good account, API health checks fail repeatedly, database migrations error, SIEM authentication rejects a known-good adapter, or nginx validation fails.

## Rollback

1. Disable the new user services if they caused the issue.
2. Restore the previous nginx site and reload only after `nginx -t` succeeds.
3. Restore the pre-release database backup if schema/data changes are implicated.
4. Return to the last known-good Git commit and rerun unit/build/smoke checks.
