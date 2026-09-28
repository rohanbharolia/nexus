# Optiv Nexus

Environment-aware security investigation workspace. Nexus connects an analyst workflow across security tools; it does not replace SIEM, EDR, identity, network, or threat-intelligence products.

## Run locally

Requirements: Node.js 18.17+ and npm.

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

The standalone documentation site is available at `http://localhost:3000/docs`. The in-app **API & Docs** page contains the endpoint catalogue; `/api/openapi` returns the machine-readable API specification.

The interactive hackathon slide deck is at `http://localhost:3000/presentation`. The full beginner-friendly speaking script, glossary, demo clicks, timing, and judge Q&A are in [`PRESENTATION_GUIDE.md`](PRESENTATION_GUIDE.md).

For a production build:

```bash
npm run build
npm start
```

Run the deterministic test suite:

```bash
npm test
```

Run the browser smoke suite after installing Playwright browsers:

```bash
npx playwright install chromium
npm run test:e2e
```

For operations and recovery guidance, read [`ops/README.md`](ops/README.md). Local SQLite backups can be created with `powershell -File scripts/backup-database.ps1`. Production backups must use encrypted managed PostgreSQL backups and tested restore procedures.

Build the production container with `docker compose build` and run it with `docker compose up`.

The browser workspace uses local storage for interactive environment choices, SOP checklist progress, and recent query history. A Prisma/SQLite domain schema and seed pipeline are included for server-side persistence work and local development. The current UI/API still uses deterministic fixtures for its demo flow so it remains reliable without a running database connection.

To initialize the local database layer:

```bash
copy .env.example .env
npm run db:generate
npm run db:push
npm run db:seed
```

## Included workflow

- SOC overview with synthetic incidents, search, activity, and illustrative metrics.
- Eight incident templates and an environment-aware 14-step PowerShell investigation.
- Configurable synthetic ACME Financial security tools. Enabled tools shape recommendations and executable query platforms.
- Deterministic Splunk, Google SecOps, CrowdStrike Falcon, Palo Alto, and Sentinel query templates with mock execution results.
- Evidence vault with source, event reference, collection time, confidence, and missing-artifact state.
- Selectable normalized timeline and event provenance.
- Analyst-authored analysis editor with deterministic evidence mismatch and security terminology checks. User text is not silently rewritten.
- Structured report preview, browser print/PDF, local ticket draft, and investigation handoff.
- Persisted client environment, dashboard metrics, analysis drafts, query history, audit events, and replay events through Prisma-backed API routes.
- Operational readiness endpoints: `/api/ready`, `/api/metrics`, `/api/session`, `/api/security/status`, and `/api/integrations`.
- API contract tests, accessibility smoke tests, GitHub Actions CI, database backup helper, and operations runbook.
- Durable analyst notes, detection feedback, custom template creation, and audit-derived SLA analytics.
- Operations Center at `/operations` for notes, detection feedback, SLA summaries, and audit/replay review.
- Template administration at `/templates` for persisted custom incident templates.
- Report approval API with durable reviewer decisions.
- Report approval history UI at `/approvals`.
- Configuration Center at `/configuration` for provider, integration, auth, readiness, and deployment status.
- API reference, OpenAPI JSON, progress tracker, and explicit production roadmap.

## API

The API base path is `/api`. Visit **API & Docs** in the app for request descriptions and the generated OpenAPI document at `/api/openapi`.

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Status and data mode |
| GET | `/api/ready` | Database readiness check |
| GET | `/api/metrics` | Persisted operational counters |
| GET | `/api/session` | Current demo/OIDC session context |
| GET | `/api/security/status` | Authentication and safety status |
| GET | `/api/incidents` | List incidents; supports `?q=` |
| GET | `/api/incidents/INC-1042` | Incident and available environment |
| POST | `/api/investigations` | Start an investigation |
| GET | `/api/investigations/INC-1042` | Steps, progress, next action |
| PATCH | `/api/investigations/INC-1042/steps` | Validate a step update payload |
| POST | `/api/queries/generate` | Generate a deterministic query |
| POST | `/api/queries/run` | Return synthetic query results |
| GET | `/api/evidence` | Evidence with provenance |
| POST | `/api/evidence/collect` | Collect synthetic evidence |
| GET | `/api/environment` | Read persisted client tool configuration |
| POST | `/api/environment/save` | Persist client tool enablement |
| GET | `/api/dashboard` | Read persisted case metrics and activity |
| GET | `/api/queries` | Read persisted generated query history |
| GET | `/api/analysis` | Read persisted analyst draft |
| POST | `/api/analysis/save` | Persist analyst draft and audit event |
| GET | `/api/timeline` | Normalized incident events |
| POST | `/api/analysis/validate` | Validate claims without modifying input |
| POST | `/api/analysis/proofread` | Return wording suggestions without applying them |
| GET | `/api/reports/INC-1042` | Structured draft report |
| POST | `/api/handoff` | Handoff summary |
| GET | `/api/integrations` | Live integration configuration status |
| POST | `/api/integrations/test` | Safe configuration test; no vendor call in demo |
| GET | `/api/analytics/sla` | Audit-derived triage and report timing |
| GET/POST | `/api/notes` | Read or create analyst notes |
| GET/POST | `/api/feedback` | Read or create detection feedback |
| POST | `/api/templates/create` | Create a persisted custom template |
| GET | `/api/reports/approvals` | Read report review decisions |
| POST | `/api/reports/approve` | Approve, escalate, or request report changes |

POST query example:

```json
{
  "incidentId": "INC-1042",
  "platform": "Splunk",
  "indicator": "185.199.110.153",
  "timeRange": "24 hours"
}
```

## Safety and data

Every incident and event is fictional. Tool connectors are mocks; no credentials or production telemetry are used. No external AI provider is called. The application can be used without an AI key. There are no automated endpoint isolation, account changes, or network blocking actions. Recommendations and response drafts require analyst review. Performance figures are illustrative demo metrics, not measured customer outcomes.

AI provider configuration (`AI_PROVIDER`, `AI_MODEL`, `AI_API_KEY`) is represented by a provider interface with a deterministic fallback. Live provider clients remain unimplemented. Mock adapters now expose the shared `SecurityToolAdapter` contract (`search`, `getHost`, `getUser`, `getNetworkActivity`) so live integrations can be added without changing investigation orchestration. See **Progress & Roadmap** in the application for all remaining milestones.
