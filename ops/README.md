# Operations Runbook

## Health

- `GET /api/health` confirms the process is serving.
- `GET /api/ready` checks database readiness and returns `503` when the database cannot be reached.
- `GET /api/metrics` returns persisted record counts and process metadata.
- `GET /api/security/status` shows whether the app is using demo sessions or configured OIDC.

## Production startup

1. Set `DATABASE_URL` to PostgreSQL or the approved production database.
2. Set `AUTH_MODE=oidc`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET`.
3. Configure an external secrets manager. Never place vendor secrets in `.env` committed to source.
4. Run `npx prisma migrate deploy` against a reviewed migration set.
5. Start the standalone Next server.
6. Verify `/api/ready` before accepting traffic.

## Backups

The local SQLite helper is `scripts/backup-database.ps1`. Production PostgreSQL backups must use the managed database provider's encrypted backup and restore process. Test restores regularly before declaring recovery complete.

## Integrations

`POST /api/integrations/test` validates configuration shape but deliberately does not contact vendors in this demo. A production adapter must add OAuth token exchange, secret retrieval, provider-specific health checks, rate limits, retries, response normalization, and audit logging before enabling live traffic.

## Incident safety

No automated destructive response is enabled. Endpoint isolation, account disablement, credential reset, and network blocking require a separate approved response service, explicit authorization, and an auditable human approval step.
