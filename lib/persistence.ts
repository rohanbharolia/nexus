import { db } from "@/lib/db";
import { mockAdapters } from "@/lib/adapters";
import type { Evidence as DomainEvidence } from "@/types/domain";

export const stepDefinitions = [
  ["Identify affected endpoint", "Confirm endpoint identity and criticality from EDR telemetry."],
  ["Identify executing user", "Correlate the initiating identity with sign-in context."],
  ["Retrieve process tree", "Trace parent-child process relationships and execution time."],
  ["Review command line", "Review encoded arguments and assess intent without assuming maliciousness."],
  ["Identify file and hash", "Record the observed file hash and reputation context."],
  ["Investigate source IP", "Establish whether the source address is expected for this user."],
  ["Investigate destination IP", "Correlate destination activity across network and SIEM sources."],
  ["Review authentication activity", "Review sign-ins and MFA events around the detection window."],
  ["Review network activity", "Determine protocol, duration, volume, and policy disposition."],
  ["Check threat intelligence", "Check configured reputation sources; preserve verdict confidence."],
  ["Establish event timeline", "Correlate timestamps from source telemetry."],
  ["Determine investigation scope", "Search for related users, endpoints, and indicators."],
  ["Document evidence", "Attach provenance and confidence to collected observations."],
  ["Prepare final analysis", "Draft evidence-backed findings and run Security Analysis QA."],
] as const;

export async function ensureInvestigation(incidentId: string) {
  const incident = await db.incident.findUnique({ where: { id: incidentId }, include: { client: { include: { tools: true } } } });
  if (!incident) return null;
  const investigation = await db.investigation.upsert({
    where: { incidentId },
    update: {},
    create: { id: `INV-${incidentId}`, incidentId, clientId: incident.clientId },
    include: { steps: true, artifacts: true, evidence: true, queries: true, timeline: true },
  });
  if (investigation.steps.length === 0) {
    await db.investigationStep.createMany({ data: stepDefinitions.map(([title, purpose], index) => ({ id: `${investigation.id}-STEP-${index + 1}`, investigationId: investigation.id, index, title, purpose, recommendedTools: JSON.stringify(index === 6 ? ["Palo Alto", "Splunk"] : ["CrowdStrike Falcon"]), requiredArtifacts: JSON.stringify([]) })) });
  }
  if (investigation.evidence.length === 0) {
    const evidence = [
      ["hostname", "Hostname", "WIN-PC-1042", "CrowdStrike Falcon", "MOCK-FALCON-0171", "HIGH"],
      ["username", "Username", "john.smith", "Microsoft Entra ID", "MOCK-ENTRA-0814", "HIGH"],
      ["source_ip", "Source IP", "10.10.4.21", "Splunk", "MOCK-SPL-2401", "HIGH"],
      ["destination_ip", "Destination IP", "185.199.110.153", "Palo Alto", "MOCK-PA-8831", "MEDIUM"],
      ["process", "Process", "powershell.exe", "CrowdStrike Falcon", "MOCK-FALCON-0172", "HIGH"],
      ["parent_process", "Parent process", "cmd.exe", "CrowdStrike Falcon", "MOCK-FALCON-0172", "HIGH"],
      ["command_line", "Command line", "powershell -enc [synthetic encoded command]", "CrowdStrike Falcon", "MOCK-FALCON-0172", "HIGH"],
      ["hash", "SHA-256", "7a91c4d8...e20f", "CrowdStrike Falcon", "MOCK-FALCON-0173", "HIGH"],
      ["authentication", "Authentication", "Successful sign-in; MFA satisfied", "Microsoft Entra ID", "MOCK-ENTRA-0814", "HIGH"],
      ["threat_reputation", "Threat reputation", "Suspicious; low prevalence", "Google Threat Intelligence", "MOCK-GTI-1102", "MEDIUM"],
      ["geo_location", "Geo location", null, null, null, null],
      ["network_session", "Network session", null, null, null, null],
    ] as const;
    await db.evidence.createMany({ data: evidence.map(([key, label, value, sourceTool, sourceEventId, confidence]) => ({ id: `${investigation.id}-${key}`, investigationId: investigation.id, key, label, value, sourceEventId, confidence: confidence as "LOW" | "MEDIUM" | "HIGH", collectedAt: value ? new Date("2026-09-28T14:42:19Z") : null, rawReference: sourceEventId })) });
  }
  if (investigation.timeline.length === 0) {
    const adapterEvents = (await mockAdapters[0].search({ query: incident.name })).events;
    await db.timelineEvent.createMany({ data: adapterEvents.map(event => ({ id: `${investigation.id}-${event.id}`, investigationId: investigation.id, timestamp: new Date(event.timestamp), source: event.source, host: event.host, user: event.user, eventType: event.eventType, description: event.description, severity: event.severity })) });
  }
  return db.investigation.findUnique({ where: { id: investigation.id }, include: { incident: true, client: { include: { tools: true } }, steps: { orderBy: { index: "asc" } }, artifacts: true, evidence: true, queries: true, timeline: { orderBy: { timestamp: "asc" } }, analysis: { include: { validations: true } }, report: true } });
}

export async function recordAudit(input: { actor: string; action: string; incidentId?: string; tool?: string; metadata?: Record<string, unknown> }) {
  return db.auditEvent.create({ data: { actor: input.actor, action: input.action, incidentId: input.incidentId, tool: input.tool, metadata: JSON.stringify(input.metadata ?? {}) } });
}

export function toDomainEvidence(items: Array<{ key: string; label: string; value: string | null; sourceTool?: string | null; sourceEventId: string | null; collectedAt: Date | null; confidence: "LOW" | "MEDIUM" | "HIGH" | null; rawReference: string | null }>): DomainEvidence[] {
  return items.map(item => ({ ...item, sourceTool: item.sourceTool ?? null, collectedAt: item.collectedAt?.toISOString() ?? null, confidence: item.confidence?.toLowerCase() as DomainEvidence["confidence"] ?? null }));
}
