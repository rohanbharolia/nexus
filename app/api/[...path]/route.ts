import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { generateDeterministicQuery, incidentKindFromName } from "@/lib/queries/engine";
import { validateAnalysis as validateAnalysisEngine } from "@/lib/validation/analysis";
import type { Evidence as DomainEvidence } from "@/types/domain";
import { db } from "@/lib/db";
import { ensureInvestigation, recordAudit, stepDefinitions, toDomainEvidence } from "@/lib/persistence";
import { aiProvider } from "@/lib/ai";
import { buildInvestigationGraph, calculateBlastRadius, calculateBusinessImpact, calculateSocAnalytics, findSimilarInvestigations, buildThreatHuntPivot } from "@/lib/analytics";
import { liveIntegrations } from "@/lib/integrations";
import { incidentTemplates } from "@/lib/templates";
import { getOperationalMetrics } from "@/lib/observability";
import { getSessionFromHeaders } from "@/lib/security/auth";
import { geoLookup, formatGeoValue } from "@/lib/geo/lookup";

const incidents = [
  { id: "INC-1042", rule: "PS-EXEC-001", name: "Suspicious PowerShell Execution", severity: "HIGH", status: "Investigating", host: "WIN-PC-1042", user: "john.smith", sourceIp: "10.10.4.21", destinationIp: "185.199.110.153", detectedAt: "2026-09-28T14:32:08Z" },
  { id: "INC-1041", rule: "ID-TRAVEL-004", name: "Impossible Travel", severity: "MEDIUM", status: "Triage", host: "MAC-FIN-028", user: "rachel.lee", sourceIp: "34.120.8.15", destinationIp: "91.198.174.192", detectedAt: "2026-09-28T14:18:42Z" },
  { id: "INC-1040", rule: "EDR-MAL-022", name: "Malware Detection", severity: "CRITICAL", status: "Investigating", host: "WIN-OPS-088", user: "svc-backup", sourceIp: "10.10.7.88", destinationIp: "—", detectedAt: "2026-09-28T13:56:19Z" },
  { id: "INC-1039", rule: "AUTH-BF-012", name: "Brute Force Authentication", severity: "MEDIUM", status: "Triage", host: "IDP-GW-01", user: "multiple users", sourceIp: "45.33.18.204", destinationIp: "10.10.0.10", detectedAt: "2026-09-28T13:41:02Z" },
  { id: "INC-1038", rule: "NET-C2-008", name: "Suspicious C2 Communication", severity: "HIGH", status: "Investigating", host: "WIN-ENG-116", user: "d.chen", sourceIp: "10.10.8.116", destinationIp: "91.219.236.44", detectedAt: "2026-09-28T13:22:51Z" },
  { id: "INC-1037", rule: "DLP-EXF-031", name: "Potential Data Exfiltration", severity: "HIGH", status: "Awaiting review", host: "FS-FIN-02", user: "a.patel", sourceIp: "10.10.2.19", destinationIp: "—", detectedAt: "2026-09-28T12:58:37Z" },
];
const timeline = [
  { time: "14:21:03", name: "Successful authentication", detail: "Interactive sign-in from 10.10.4.21 · MFA satisfied", source: "Microsoft Entra ID", severity: "normal" },
  { time: "14:21:14", name: "MFA challenge satisfied", detail: "User completed a valid MFA challenge", source: "Microsoft Entra ID", severity: "normal" },
  { time: "14:29:44", name: "PowerShell launched", detail: "powershell.exe spawned by cmd.exe", source: "CrowdStrike Falcon", severity: "warning" },
  { time: "14:29:46", name: "Encoded command executed", detail: "Encoded command-line argument observed", source: "CrowdStrike Falcon", severity: "high" },
  { time: "14:29:51", name: "File created", detail: "Temporary script created in user profile", source: "CrowdStrike Falcon", severity: "warning" },
  { time: "14:30:02", name: "External connection", detail: "Outbound connection to 185.199.110.153", source: "Palo Alto", severity: "high" },
  { time: "14:30:14", name: "DNS lookup", detail: "Newly observed domain resolved by endpoint", source: "Splunk", severity: "warning" },
  { time: "14:30:20", name: "Firewall session allowed", detail: "Outbound session permitted by egress policy", source: "Palo Alto", severity: "high" },
];
const evidence = [
  { name: "Hostname", value: "WIN-PC-1042", sourceTool: "CrowdStrike Falcon", sourceEventId: "MOCK-FALCON-0171", confidence: "high" },
  { name: "Username", value: "john.smith", sourceTool: "Microsoft Entra ID", sourceEventId: "MOCK-ENTRA-0814", confidence: "high" },
  { name: "Source IP", value: "10.10.4.21", sourceTool: "Splunk", sourceEventId: "MOCK-SPL-2401", confidence: "high" },
  { name: "Destination IP", value: "185.199.110.153", sourceTool: "Palo Alto", sourceEventId: "MOCK-PA-8831", confidence: "medium" },
  { name: "Process", value: "powershell.exe", sourceTool: "CrowdStrike Falcon", sourceEventId: "MOCK-FALCON-0172", confidence: "high" },
  { name: "Parent process", value: "cmd.exe", sourceTool: "CrowdStrike Falcon", sourceEventId: "MOCK-FALCON-0172", confidence: "high" },
  { name: "Command line", value: "powershell -enc [synthetic encoded command]", sourceTool: "CrowdStrike Falcon", sourceEventId: "MOCK-FALCON-0172", confidence: "high" },
  { name: "SHA-256", value: "7a91c4d8...e20f", sourceTool: "CrowdStrike Falcon", sourceEventId: "MOCK-FALCON-0173", confidence: "high" },
  { name: "Authentication", value: "Successful sign-in · MFA satisfied", sourceTool: "Microsoft Entra ID", sourceEventId: "MOCK-ENTRA-0814", confidence: "high" },
  { name: "Threat reputation", value: "Suspicious · low prevalence", sourceTool: "Google Threat Intelligence", sourceEventId: "MOCK-GTI-1102", confidence: "medium" },
  { name: "Geo location", value: null, sourceTool: null, sourceEventId: null, confidence: null },
  { name: "Network session", value: null, sourceTool: null, sourceEventId: null, confidence: null },
].map(item => ({ ...item, collectedAt: item.value ? "2026-09-28T14:42:19Z" : null, rawReference: item.sourceEventId }));
const steps = ["Identify affected endpoint", "Identify executing user", "Retrieve process tree", "Review command line", "Identify file and hash", "Investigate source IP", "Investigate destination IP", "Review authentication activity", "Review network activity", "Check threat intelligence", "Establish event timeline", "Determine investigation scope", "Document evidence", "Prepare final analysis"];
const querySchema = z.object({ incidentId: z.string().default("INC-1042"), platform: z.enum(["Splunk", "Google SecOps", "CrowdStrike Falcon", "Palo Alto", "Microsoft Sentinel"]), indicator: z.string().min(1).max(256), timeRange: z.enum(["1 hour", "24 hours", "7 days"]).default("24 hours") });
const incidentSchema = z.object({ incidentId: z.string().default("INC-1042") });
function json(data: unknown, status = 200) { return NextResponse.json(data, { status, headers: { "Cache-Control": "no-store" } }); }
function getIncident(id: string) { return incidents.find(item => item.id === id); }
function makeQuery(input: z.infer<typeof querySchema>) {
  const incident = getIncident(input.incidentId) ?? incidents[0];
  const range = input.timeRange === "1 hour" ? "-1h" : input.timeRange === "7 days" ? "-7d" : "-24h";
  const query = input.platform === "Splunk" ? `index=* (src_ip="${input.indicator}" OR dest_ip="${input.indicator}" OR host="${incident.host}") earliest=${range} latest=now\n| sort _time`
    : input.platform === "CrowdStrike Falcon" ? `host.hostname:"${incident.host}" AND (network.remote_address:"${input.indicator}" OR process.name:"powershell.exe")\n| sort timestamp desc`
      : input.platform === "Palo Alto" ? `(addr.src in ${input.indicator} or addr.dst in ${input.indicator})\n| sort receive_time desc`
        : input.platform === "Google SecOps" ? `metadata.event_type = "NETWORK_CONNECTION"\nAND (principal.ip = "${input.indicator}" OR target.ip = "${input.indicator}")`
          : `CommonSecurityLog\n| where TimeGenerated > ago(${range === "-1h" ? "1h" : range === "-7d" ? "7d" : "24h"})\n| where SourceIP == "${input.indicator}" or DestinationIP == "${input.indicator}"`;
  return { ...input, query, purpose: "Correlate the indicator with affected endpoint telemetry", expectedEvidence: ["timestamp", "source/destination", "action", "endpoint"], confidence: "high", templateVersion: "1.4", executionMode: "deterministic-mock" };
}

export async function GET(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const path = (await context.params).path.join("/");
  const url = new URL(request.url);
  if (path === "health") return json({ status: "ok", mode: "synthetic-mock", externalIntegrations: false, timestamp: new Date().toISOString() });
  if (path === "ready") { try { await db.$queryRaw`SELECT 1`; return json({ status: "ready", database: "ok", timestamp: new Date().toISOString() }); } catch { return json({ status: "not_ready", database: "unavailable" }, 503); } }
  if (path === "metrics") return json(await getOperationalMetrics());
  if (path === "analytics/sla") {
    const events = await db.auditEvent.findMany({ orderBy: { createdAt: "asc" }, take: 500 });
    const grouped = new Map<string, { first?: Date; investigation?: Date; report?: Date; count: number }>();
    for (const event of events) { const key = event.incidentId ?? "unassigned"; const item = grouped.get(key) ?? { count: 0 }; item.count += 1; if (!item.first) item.first = event.createdAt; if (event.action === "investigation.started") item.investigation = event.createdAt; if (event.action === "report.generated") item.report = event.createdAt; grouped.set(key, item); }
    const cases = [...grouped.entries()].map(([incidentId, item]) => ({ incidentId, auditEvents: item.count, triageMinutes: item.first && item.investigation ? Math.max(0, Math.round((item.investigation.getTime() - item.first.getTime()) / 60000)) : null, investigationToReportMinutes: item.investigation && item.report ? Math.max(0, Math.round((item.report.getTime() - item.investigation.getTime()) / 60000)) : null }));
    return json({ targetMinutes: 30, cases, measuredCases: cases.length, caveat: "Calculated from persisted Nexus audit events; vendor-side time is not included." });
  }
  if (path === "session") return json(getSessionFromHeaders(request.headers));
  if (path === "security/status") return json({ authMode: process.env.AUTH_MODE ?? "demo", sessionProvider: process.env.OIDC_ISSUER ? "oidc-configured" : "demo-session", tenantIsolation: true, destructiveActions: false, requiredProductionEnv: ["OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "DATABASE_URL"] });
  if (path === "capabilities") return json({ persistence: { prisma: true, sqlite: true, uiReads: "prisma-backed-api", uiLocalPreferences: true }, adapters: { mock: true, live: liveIntegrations.map(adapter => ({ name: adapter.name, configured: adapter.configured, status: adapter.status })) }, ai: { interface: true, deterministicFallback: true, liveProviders: ["openai", "openrouter", "ollama", "gemini", "deepseek"].map(provider => ({ provider, configured: Boolean(process.env.AI_PROVIDER === provider && process.env.AI_API_KEY && process.env.AI_ENDPOINT), status: process.env.AI_PROVIDER === provider && process.env.AI_API_KEY && process.env.AI_ENDPOINT ? "configured-http-boundary" : "credentials-required" })) }, security: { authContracts: true, oauthContracts: true, destructiveAutomation: false }, analytics: { businessImpact: true, blastRadius: true, attackPath: true, similarity: true, threatHunting: true, socMetrics: true }, testing: { unit: true, api: true, e2e: true, accessibility: true, note: "Test files and CI workflow are present; browser execution requires Playwright browser installation." }, deployment: { docker: true, observability: false, backups: false } });
  if (path === "templates") return json(incidentTemplates);
  if (path.startsWith("templates/")) { const template = incidentTemplates.find(candidate => candidate.id === path.slice("templates/".length)); return template ? json(template) : json({ error: "Template not found" }, 404); }
  if (path === "environment") {
    const client = await db.client.findUnique({ where: { id: "client-acme" }, include: { tools: { orderBy: { category: "asc" } } } });
    return client ? json({ id: client.id, name: client.name, tools: client.tools, availableTools: client.tools.filter(tool => tool.enabled).map(tool => tool.name), persistence: "prisma-sqlite" }) : json({ error: "Client not found" }, 404);
  }
  if (path === "dashboard") {
    const [active, critical, pending, resolved, recent, audit] = await Promise.all([
      db.incident.count({ where: { status: { in: ["TRIAGE", "INVESTIGATING", "AWAITING_REVIEW"] } } }),
      db.incident.count({ where: { severity: "CRITICAL", status: { not: "RESOLVED" } } }),
      db.evidence.count({ where: { value: null } }),
      db.incident.count({ where: { status: "RESOLVED" } }),
      db.incident.findMany({ orderBy: { detectedAt: "desc" }, take: 6 }),
      db.auditEvent.findMany({ orderBy: { createdAt: "desc" }, take: 8 }),
    ]);
    return json({ metrics: { active, critical, pendingEvidence: pending, resolved }, recent, activity: audit, persistence: "prisma-sqlite" });
  }
  if (path === "queries") return json(await db.generatedQuery.findMany({ orderBy: { executedAt: "desc" }, take: 50 }));
  if (path === "notes") return json(await db.analystNote.findMany({ where: { clientId: "client-acme" }, orderBy: { createdAt: "desc" }, take: 100 }));
  if (path === "feedback") return json(await db.detectionFeedback.findMany({ where: { clientId: "client-acme" }, orderBy: { createdAt: "desc" }, take: 100 }));
  if (path === "reports/approvals") return json(await db.reportApproval.findMany({ orderBy: { createdAt: "desc" }, take: 100 }));
  if (path === "integrations") return json(liveIntegrations.map(adapter => ({ name: adapter.name, configured: adapter.configured, status: adapter.status })));
  if (path === "templates") return json(incidentTemplates);
  if (path === "openapi") return json({ openapi: "3.1.0", info: { title: "Optiv Nexus Demo API", version: "1.0.0", description: "Synthetic, deterministic local demonstration API. No live security integrations." }, servers: [{ url: "/api" }], paths: { "/health": { get: { summary: "Health and execution mode" } }, "/incidents": { get: { summary: "List synthetic incidents" } }, "/incidents/{incidentId}": { get: { summary: "Get incident details" } }, "/investigations/{incidentId}": { get: { summary: "Get investigation state" } }, "/investigations/{incidentId}/steps": { patch: { summary: "Update a step", requestBody: { content: { "application/json": { schema: { type: "object", properties: { stepIndex: { type: "integer" }, complete: { type: "boolean" } }, required: ["stepIndex", "complete"] } } } } } }, "/queries/generate": { post: { summary: "Generate a parameterized query" } }, "/queries/run": { post: { summary: "Run a synthetic mock query" } }, "/evidence": { get: { summary: "List evidence with provenance" } }, "/evidence/collect": { post: { summary: "Collect deterministic mock evidence" } }, "/timeline": { get: { summary: "Get chronological synthetic events" } }, "/analysis/validate": { post: { summary: "Validate analyst text without rewriting it" } }, "/analysis/proofread": { post: { summary: "Return deterministic wording suggestions" } }, "/reports/{incidentId}": { get: { summary: "Generate a structured draft report" } }, "/handoff": { post: { summary: "Generate an investigation handoff" } } } });
  if (path === "incidents") { const q = (url.searchParams.get("q") ?? "").toLowerCase(); return json(incidents.filter(i => JSON.stringify(i).toLowerCase().includes(q))); }
  if (path.startsWith("incidents/")) { const item = getIncident(path.split("/")[1]); return item ? json({ ...item, client: "ACME Financial", synthetic: true, availableTools: ["Splunk", "CrowdStrike Falcon", "Microsoft Entra ID", "Palo Alto", "Google Threat Intelligence"] }) : json({ error: "Incident not found" }, 404); }
  if (path.startsWith("investigations/") && !path.includes("/steps")) { const id = path.split("/")[1]; const investigation = await ensureInvestigation(id); if (!investigation) return json({ error: "Incident not found" }, 404);
    // Auto-populate geo_location if still null
    const geoEvidence = investigation.evidence.find(item => item.key === "geo_location");
    const srcEv = investigation.evidence.find(item => item.key === "source_ip" || item.key === "source_location");
    const dstEv = investigation.evidence.find(item => item.key === "destination_ip");
    if (geoEvidence && !geoEvidence.value) {
      const targetIp = (dstEv?.value && dstEv.value !== "—") ? dstEv.value : srcEv?.value;
      if (targetIp) {
        const geo = geoLookup(targetIp);
        await db.evidence.update({ where: { id: geoEvidence.id }, data: { value: formatGeoValue(geo), rawReference: "Geo Intelligence (deterministic)", confidence: "MEDIUM", collectedAt: new Date() } });
      }
    }
    const fresh = await ensureInvestigation(id);
    if (!fresh) return json({ error: "Incident not found" }, 404);
    const complete = fresh.steps.filter(step => step.complete).length; return json({ incident: fresh.incident, investigationId: fresh.id, persistence: "prisma-sqlite", steps: fresh.steps.map(step => ({ ...step, recommendedTools: JSON.parse(String(step.recommendedTools)), requiredArtifacts: JSON.parse(String(step.requiredArtifacts)) })), artifacts: fresh.evidence, timeline: fresh.timeline, queries: fresh.queries, progress: Math.round(complete / fresh.steps.length * 100), nextBestAction: await aiProvider.generateNextBestAction({ incident: fresh.incident as never, completedSteps: fresh.steps.filter(step => step.complete).map(step => step.title), missingArtifacts: fresh.evidence.filter(item => !item.value).map(item => item.label), availableTools: fresh.client.tools.filter(tool => tool.enabled).map(tool => tool.name), incidentKind: incidentKindFromName(fresh.incident.name, fresh.incident.rule) }) }); }
  if (path === "evidence") { const id = url.searchParams.get("incidentId") ?? "INC-1042"; const investigation = await ensureInvestigation(id); return investigation ? json(investigation.evidence) : json({ error: "Incident not found" }, 404); }
  if (path === "timeline") { const id = url.searchParams.get("incidentId") ?? "INC-1042"; const investigation = await ensureInvestigation(id); return investigation ? json(investigation.timeline.map(event => ({ ...event, timestamp: event.timestamp.toISOString(), synthetic: true }))) : json({ error: "Incident not found" }, 404); }
  if (path === "analysis") { const id = url.searchParams.get("incidentId") ?? "INC-1042"; const investigation = await ensureInvestigation(id); return investigation ? json(investigation.analysis ?? { summary: "", technicalFindings: "", scope: "", recommendedActions: "", validations: [] }) : json({ error: "Incident not found" }, 404); }
  if (path === "audit") { const incidentId = url.searchParams.get("incidentId") ?? undefined; return json(await db.auditEvent.findMany({ where: { incidentId }, orderBy: { createdAt: "desc" }, take: 100 })); }
  if (path === "replay") { const incidentId = url.searchParams.get("incidentId") ?? "INC-1042"; const investigation = await ensureInvestigation(incidentId); return investigation ? json(await db.replayEvent.findMany({ where: { investigationId: investigation.id }, orderBy: { createdAt: "asc" } })) : json({ error: "Incident not found" }, 404); }
  if (path === "analytics/similar") return json(findSimilarInvestigations({ title: url.searchParams.get("title") ?? "Suspicious PowerShell", host: url.searchParams.get("host") ?? undefined, indicator: url.searchParams.get("indicator") ?? undefined }));
  if (path === "analytics/blast-radius") return json(calculateBlastRadius());
  if (path === "analytics/attack-path") return json(buildInvestigationGraph({ host: "WIN-PC-1042", user: "john.smith", sourceIp: "10.10.4.21", destinationIp: "185.199.110.153", process: "powershell.exe" }));
  if (path === "analytics/business-impact") return json(calculateBusinessImpact({ assetCriticality: "high", dataClasses: ["PCI", "PII"], confirmedExposure: false }));
  if (path === "analytics/soc") return json(calculateSocAnalytics([{ durationMinutes: 18, toolSwitchingMinutes: 7, evidenceSearchMinutes: 5, documentationMinutes: 3, evidenceCompletion: 87, falsePositive: false }, { durationMinutes: 22, toolSwitchingMinutes: 9, evidenceSearchMinutes: 6, documentationMinutes: 4, evidenceCompletion: 92, falsePositive: true }]));
  if (path === "threat-hunt") return json(buildThreatHuntPivot({ indicator: url.searchParams.get("indicator") ?? "185.199.110.153", type: (url.searchParams.get("type") as "ip" | "hash" | "domain" | "user" | "host") ?? "ip" }));
  if (path.startsWith("reports/")) { const id = path.split("/")[1]; const investigation = await ensureInvestigation(id); if (!investigation) return json({ error: "Incident not found" }, 404); const report = { incident: investigation.incident, executiveSummary: await aiProvider.generateExecutiveSummary({ evidence: investigation.evidence, timeline: investigation.timeline }), timeline: investigation.timeline, evidence: investigation.evidence, investigationSteps: investigation.steps, qaStatus: "Review required", recommendedActions: ["Corroborate destination reputation", "Review related sign-ins", "Preserve endpoint evidence"], draft: true, persistence: "prisma-sqlite" }; await db.report.upsert({ where: { investigationId: investigation.id }, update: { content: report }, create: { id: `RPT-${id}`, investigationId: investigation.id, content: report } }); await recordAudit({ actor: "api", action: "report.generated", incidentId: id }); return json(report); }
  return json({ error: "Route not found", available: ["GET /api/health", "GET /api/incidents", "GET /api/evidence", "GET /api/timeline"] }, 404);
}

export async function POST(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const path = (await context.params).path.join("/");
  let body: unknown;
  try { body = await request.json(); } catch { return json({ error: "Request body must be valid JSON" }, 400); }
  if (path === "queries/generate" || path === "queries/run") {
    const parsed = querySchema.safeParse(body); if (!parsed.success) return json({ error: "Invalid query parameters", details: parsed.error.flatten() }, 400);
    const inc = getIncident(parsed.data.incidentId) ?? incidents[0];
    const generated = generateDeterministicQuery({ ...parsed.data, host: inc.host, incidentKind: incidentKindFromName(inc.name, inc.rule) });
    const investigation = await ensureInvestigation(parsed.data.incidentId); if (investigation) { await db.generatedQuery.create({ data: { id: generated.id, investigationId: investigation.id, platform: generated.platform, indicator: generated.indicator, timeRange: generated.timeRange, query: generated.query, purpose: generated.purpose, resultCount: path.endsWith("run") ? 4 : null, executedAt: path.endsWith("run") ? new Date() : null } }); await recordAudit({ actor: "api", action: path.endsWith("run") ? "query.executed" : "query.generated", incidentId: parsed.data.incidentId, tool: parsed.data.platform, metadata: { indicator: parsed.data.indicator } }); }
    if (path.endsWith("generate")) return json({ ...generated, persistence: "prisma-sqlite" });
    return json({ ...generated, status: "completed", resultCount: 4, results: timeline.slice(2, 6), synthetic: true, persistence: "prisma-sqlite" });
  }
  if (path === "investigations") { const parsed = incidentSchema.safeParse(body); if (!parsed.success) return json({ error: "Invalid incident ID", details: parsed.error.flatten() }, 400); const investigation = await ensureInvestigation(parsed.data.incidentId); if (!investigation) return json({ error: "Incident not found" }, 404); await recordAudit({ actor: "api", action: "investigation.started", incidentId: parsed.data.incidentId }); return json({ incidentId: investigation.incidentId, investigationId: investigation.id, status: investigation.status, createdAt: investigation.startedAt, persistence: "prisma-sqlite", steps: investigation.steps }, 201); }
  if (path === "evidence/collect") { const id = (body as { incidentId?: string })?.incidentId ?? "INC-1042"; const investigation = await ensureInvestigation(id); if (!investigation) return json({ error: "Incident not found" }, 404);
    // Enrich geo_location evidence from source/destination IPs if still null
    const geoEvidence = investigation.evidence.find(item => item.key === "geo_location");
    const srcEvidence = investigation.evidence.find(item => item.key === "source_ip" || item.key === "source_location");
    const dstEvidence = investigation.evidence.find(item => item.key === "destination_ip");
    if (geoEvidence && !geoEvidence.value) {
      const targetIp = (dstEvidence?.value && dstEvidence.value !== "—") ? dstEvidence.value : srcEvidence?.value;
      if (targetIp) {
        const geo = geoLookup(targetIp);
        const geoValue = formatGeoValue(geo);
        await db.evidence.update({ where: { id: geoEvidence.id }, data: { value: geoValue, rawReference: "Geo Intelligence (deterministic)", confidence: "MEDIUM", collectedAt: new Date() } });
      }
    }
    // Re-fetch after enrichment
    const updated = await ensureInvestigation(id);
    if (!updated) return json({ error: "Incident not found" }, 404);
    await recordAudit({ actor: "api", action: "evidence.collected", incidentId: id, metadata: { count: updated.evidence.filter(item => item.value).length } }); return json({ collected: updated.evidence.filter(item => item.value), missing: updated.evidence.filter(item => !item.value).map(item => item.label), provenanceIncluded: true, persistence: "prisma-sqlite", synthetic: true }); }
  if (path === "analysis/validate") {
    const schema = z.object({ text: z.string().min(1).max(20000), incidentId: z.string().default("INC-1042") }); const parsed = schema.safeParse(body); if (!parsed.success) return json({ error: "Invalid analysis input", details: parsed.error.flatten() }, 400);
    const text = parsed.data.text; const issues = [] as { type: string; severity: string; message: string; source?: string; suggestedFix?: string }[];
    const host = text.match(/WIN-PC-\d+/i)?.[0]; if (host && host !== "WIN-PC-1042") issues.push({ type: "evidence_mismatch", severity: "critical", message: `Analyst hostname ${host} does not match collected evidence.`, source: "CrowdStrike Falcon · MOCK-FALCON-0171", suggestedFix: "WIN-PC-1042" });
    const user = text.match(/\b[a-z]+\.[a-z]+\b/i)?.[0]; if (user && user.toLowerCase() !== "john.smith") issues.push({ type: "evidence_mismatch", severity: "warning", message: `Analyst identity ${user} should be checked against the sign-in record.`, source: "Microsoft Entra ID · MOCK-ENTRA-0814", suggestedFix: "john.smith" });
    for (const [field, value, source] of [["source IP", "10.10.4.21", "Splunk · MOCK-SPL-2401"], ["destination IP", "185.199.110.153", "Palo Alto · MOCK-PA-8831"], ["hash", "7a91c4d8...e20f", "CrowdStrike Falcon · MOCK-FALCON-0173"]]) { const regex = field === "hash" ? /\b[a-f0-9]{8,64}\b/ig : field === "source IP" || field === "destination IP" ? /\b(?:\d{1,3}\.){3}\d{1,3}\b/g : null; const found = regex ? [...text.matchAll(regex)].map(m => m[0]) : []; if (found.some(v => !value.toLowerCase().startsWith(v.toLowerCase()) && !value.includes(v))) issues.push({ type: "evidence_mismatch", severity: "warning", message: `An analyst ${field} differs from collected evidence.`, source, suggestedFix: value }); }
    if (/\b(attacker compromised|account was compromised|confirmed malicious|malicious IP)\b/i.test(text)) issues.push({ type: "unsupported_claim", severity: "warning", message: "Evidence supports a suspicious reputation assessment, not a confirmed compromise or malicious verdict.", source: "Google Threat Intelligence · MOCK-GTI-1102", suggestedFix: "potentially malicious; corroboration required" });
    if (/\bpowershell\b/.test(text)) issues.push({ type: "terminology", severity: "info", message: "Use the product-standard capitalization PowerShell.", suggestedFix: "PowerShell" });
    if (/\b(user executed|connection made|powershell and connection)\b/i.test(text)) issues.push({ type: "grammar", severity: "info", message: "Consider clarifying the relationship and improving sentence structure.", suggestedFix: "The user executed PowerShell, after which a network connection was observed." });
    const missing = evidence.filter(item => !item.value); if (missing.length) issues.push({ type: "missing_artifact", severity: "warning", message: `${missing.length} required artifacts are not yet collected: ${missing.map(item => item.name).join(", ")}.`, source: "Incident template · required artifact checklist" });
    const engineIssues = validateAnalysisEngine(text, evidence.map(item => ({ key: item.name.toLowerCase().replaceAll(" ", "_"), label: item.name, value: item.value, sourceTool: item.sourceTool, sourceEventId: item.sourceEventId, collectedAt: item.collectedAt, confidence: item.confidence, rawReference: item.rawReference })) as DomainEvidence[]);
    const mergedIssues = [...issues, ...engineIssues.filter(candidate => !issues.some(existing => existing.type === candidate.type && existing.message === candidate.message))];
    const investigation = await ensureInvestigation(parsed.data.incidentId); if (investigation) { const analysis = await db.analysis.upsert({ where: { investigationId: investigation.id }, update: { summary: text, technicalFindings: text, scope: "Under review", recommendedActions: "Review flagged issues" }, create: { id: `AN-${parsed.data.incidentId}`, investigationId: investigation.id, summary: text, technicalFindings: text, scope: "Under review", recommendedActions: "Review flagged issues" } }); await db.validationResult.deleteMany({ where: { analysisId: analysis.id } }); if (mergedIssues.length) await db.validationResult.createMany({ data: mergedIssues.map((issue, index) => ({ id: `${analysis.id}-${index}`, analysisId: analysis.id, type: issue.type, severity: issue.severity, message: issue.message, source: issue.source, suggestedFix: issue.suggestedFix })) }); await recordAudit({ actor: "api", action: "analysis.validated", incidentId: parsed.data.incidentId, metadata: { issueCount: mergedIssues.length } }); }
    return json({ incidentId: parsed.data.incidentId, issues: mergedIssues, passed: mergedIssues.length === 0, inputPreserved: true, persistence: "prisma-sqlite", synthetic: true });
  }
  if (path === "analysis/proofread") { const schema = z.object({ text: z.string().min(1).max(20000) }); const parsed = schema.safeParse(body); if (!parsed.success) return json({ error: "Invalid analysis text", details: parsed.error.flatten() }, 400); const suggestions = [] as { from: string; to: string; reason: string }[]; if (/\bpowershell\b/.test(parsed.data.text)) suggestions.push({ from: "powershell", to: "PowerShell", reason: "Security product terminology" }); if (/malicious IP/i.test(parsed.data.text)) suggestions.push({ from: "malicious IP", to: "potentially malicious IP", reason: "Align conclusion strength with suspicious reputation evidence" }); return json({ suggestions, originalTextPreserved: parsed.data.text, autoApplied: false }); }
  if (path === "handoff") { const schema = z.object({ incidentId: z.string().default("INC-1042"), completedSteps: z.array(z.number().int()).default([0, 1, 2]), queriesExecuted: z.number().int().nonnegative().default(0) }); const parsed = schema.safeParse(body); if (!parsed.success) return json({ error: "Invalid handoff request", details: parsed.error.flatten() }, 400); const investigation = await ensureInvestigation(parsed.data.incidentId); if (!investigation) return json({ error: "Incident not found" }, 404); await recordAudit({ actor: "api", action: "handoff.generated", incidentId: parsed.data.incidentId }); return json({ incident: investigation.incident, status: investigation.status, completed: investigation.steps.filter(step => parsed.data.completedSteps.includes(step.index)).map(step => step.title), pending: investigation.steps.filter(step => !parsed.data.completedSteps.includes(step.index)).map(step => step.title), keyFindings: ["PowerShell execution observed", "Outbound network session observed", "Threat reputation is suspicious; not confirmed malicious"], missingEvidence: investigation.evidence.filter(item => !item.value).map(item => item.label), nextRecommendedAction: "Investigate destination IP across network and SIEM sources", queriesExecuted: parsed.data.queriesExecuted, evidenceCollected: investigation.evidence.filter(item => item.value).length, persistence: "prisma-sqlite", synthetic: true }); }
  if (path === "analysis/save") {
    const schema = z.object({ incidentId: z.string().default("INC-1042"), summary: z.string().max(20000), technicalFindings: z.string().max(20000), scope: z.string().max(20000), recommendedActions: z.string().max(20000) });
    const parsed = schema.safeParse(body); if (!parsed.success) return json({ error: "Invalid analysis", details: parsed.error.flatten() }, 400);
    const investigation = await ensureInvestigation(parsed.data.incidentId); if (!investigation) return json({ error: "Incident not found" }, 404);
    const analysis = await db.analysis.upsert({ where: { investigationId: investigation.id }, update: parsed.data, create: { id: `AN-${parsed.data.incidentId}`, investigationId: investigation.id, ...parsed.data } });
    await db.replayEvent.create({ data: { investigationId: investigation.id, actor: "analyst", action: "analysis.saved", payload: { fields: Object.keys(parsed.data).filter(key => key !== "incidentId") } } });
    await recordAudit({ actor: "analyst", action: "analysis.saved", incidentId: parsed.data.incidentId }); return json({ ...analysis, persistence: "prisma-sqlite" });
  }
  if (path === "environment/save") {
    const schema = z.object({ tools: z.array(z.object({ id: z.string(), enabled: z.boolean() })) }); const parsed = schema.safeParse(body); if (!parsed.success) return json({ error: "Invalid environment", details: parsed.error.flatten() }, 400);
    const storedTools = await db.tool.findMany({ where: { clientId: "client-acme" } });
    await db.$transaction(parsed.data.tools.flatMap(tool => { const match = storedTools.find(candidate => candidate.id === tool.id || candidate.name.toLowerCase().replaceAll(" ", "") === tool.id.toLowerCase().replaceAll(" ", "")); return match ? [db.tool.update({ where: { id: match.id }, data: { enabled: tool.enabled } })] : []; }));
    await recordAudit({ actor: "admin", action: "environment.saved", metadata: { toolCount: parsed.data.tools.length } });
    return json(await db.client.findUnique({ where: { id: "client-acme" }, include: { tools: true } }));
  }
  if (path === "integrations/test") {
    const schema = z.object({ provider: z.string().min(1), baseUrl: z.string().url().optional(), enabled: z.boolean().default(false) });
    const parsed = schema.safeParse(body); if (!parsed.success) return json({ error: "Invalid integration configuration", details: parsed.error.flatten() }, 400);
    const integration = liveIntegrations.find(candidate => candidate.name.toLowerCase() === parsed.data.provider.toLowerCase());
    if (!integration) return json({ error: "Unsupported integration" }, 404);
    return json({ provider: integration.name, status: integration.configured ? "configured-transport-pending" : "credentials-required", connectionAttempted: false, reason: "Nexus will not contact a vendor until server-side OAuth secrets and provider mappings are configured." });
  }
  if (path === "notes") {
    const schema = z.object({ incidentId: z.string().optional(), investigationId: z.string().optional(), body: z.string().min(1).max(20000), authorId: z.string().default("demo-analyst") });
    const parsed = schema.safeParse(body); if (!parsed.success) return json({ error: "Invalid note", details: parsed.error.flatten() }, 400);
    const note = await db.analystNote.create({ data: { clientId: "client-acme", ...parsed.data } });
    await recordAudit({ actor: parsed.data.authorId, action: "note.created", incidentId: parsed.data.incidentId }); return json(note, 201);
  }
  if (path === "feedback") {
    const schema = z.object({ incidentId: z.string(), rule: z.string(), disposition: z.enum(["TRUE_POSITIVE", "FALSE_POSITIVE", "DUPLICATE", "USEFUL", "NOT_USEFUL"]), reason: z.string().max(2000).optional(), authorId: z.string().default("demo-analyst") });
    const parsed = schema.safeParse(body); if (!parsed.success) return json({ error: "Invalid detection feedback", details: parsed.error.flatten() }, 400);
    const feedback = await db.detectionFeedback.create({ data: { clientId: "client-acme", ...parsed.data } });
    await recordAudit({ actor: parsed.data.authorId, action: "detection.feedback", incidentId: parsed.data.incidentId, metadata: { disposition: parsed.data.disposition } }); return json(feedback, 201);
  }
  if (path === "templates/create") {
    const schema = z.object({ id: z.string().min(2).regex(/^[a-z0-9_-]+$/), name: z.string().min(2), description: z.string().min(2), artifacts: z.array(z.string()).default([]), steps: z.array(z.string()).default([]), recommendedLogSources: z.array(z.string()).default([]), analysisTemplate: z.string().default("Observed evidence, interpretation, hypothesis, recommendation") });
    const parsed = schema.safeParse(body); if (!parsed.success) return json({ error: "Invalid template", details: parsed.error.flatten() }, 400);
    const template = await db.incidentTemplate.create({ data: { id: parsed.data.id, name: parsed.data.name, description: parsed.data.description, severities: JSON.stringify(["MEDIUM", "HIGH", "CRITICAL"]), artifacts: parsed.data.artifacts, steps: parsed.data.steps, queryTemplates: [], recommendedLogSources: parsed.data.recommendedLogSources, analysisTemplate: parsed.data.analysisTemplate } });
    await recordAudit({ actor: "admin", action: "template.created", metadata: { templateId: template.id } }); return json(template, 201);
  }
  if (path === "reports/approve") {
    const schema = z.object({ incidentId: z.string(), decision: z.enum(["APPROVED", "CHANGES_REQUESTED", "ESCALATED"]), comment: z.string().max(4000).optional(), reviewerId: z.string().default("demo-senior-analyst") });
    const parsed = schema.safeParse(body); if (!parsed.success) return json({ error: "Invalid report approval", details: parsed.error.flatten() }, 400);
    const investigation = await ensureInvestigation(parsed.data.incidentId); if (!investigation?.report) return json({ error: "Report not found" }, 404);
    const approval = await db.reportApproval.create({ data: { reportId: investigation.report.id, reviewerId: parsed.data.reviewerId, decision: parsed.data.decision, comment: parsed.data.comment } });
    await db.report.update({ where: { id: investigation.report.id }, data: { status: parsed.data.decision === "APPROVED" ? "APPROVED" : "REVIEW_REQUIRED" } });
    await recordAudit({ actor: parsed.data.reviewerId, action: `report.${parsed.data.decision.toLowerCase()}`, incidentId: parsed.data.incidentId }); return json(approval, 201);
  }
  return json({ error: "Route not found" }, 404);
}

export async function PATCH(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const path = (await context.params).path.join("/");
  if (!/^investigations\/[^/]+\/steps$/.test(path)) return json({ error: "Route not found" }, 404);
  let body: unknown; try { body = await request.json(); } catch { return json({ error: "Request body must be valid JSON" }, 400); }
  const parsed = z.object({ stepIndex: z.number().int().min(0).max(steps.length - 1), complete: z.boolean() }).safeParse(body);
  if (!parsed.success) return json({ error: "Invalid step update", details: parsed.error.flatten() }, 400);
  const incidentId = path.split("/")[1]; if (!getIncident(incidentId)) return json({ error: "Incident not found" }, 404);
  const investigation = await ensureInvestigation(incidentId); if (!investigation) return json({ error: "Incident not found" }, 404); const step = await db.investigationStep.update({ where: { investigationId_index: { investigationId: investigation.id, index: parsed.data.stepIndex } }, data: { complete: parsed.data.complete } }); await db.replayEvent.create({ data: { investigationId: investigation.id, actor: "api", action: parsed.data.complete ? "step.completed" : "step.reopened", payload: { stepIndex: parsed.data.stepIndex, title: step.title } } }); await recordAudit({ actor: "api", action: parsed.data.complete ? "step.completed" : "step.reopened", incidentId }); return json({ incidentId, stepIndex: parsed.data.stepIndex, title: step.title, complete: step.complete, persisted: true });
}
