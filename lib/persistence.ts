import { db } from "@/lib/db";
import { mockAdapters } from "@/lib/adapters";
import type { Evidence as DomainEvidence } from "@/types/domain";

// Generic 14-step SOP used when a template match is not found
export const stepDefinitions = [
  ["Identify affected endpoint",    "Confirm endpoint identity and criticality from EDR telemetry."],
  ["Identify executing user",       "Correlate the initiating identity with sign-in context."],
  ["Retrieve process tree",         "Trace parent-child process relationships and execution time."],
  ["Review command line",           "Review encoded arguments and assess intent without assuming maliciousness."],
  ["Identify file and hash",        "Record the observed file hash and reputation context."],
  ["Investigate source IP",         "Establish whether the source address is expected for this user."],
  ["Investigate destination IP",    "Correlate destination activity across network and SIEM sources."],
  ["Review authentication activity","Review sign-ins and MFA events around the detection window."],
  ["Review network activity",       "Determine protocol, duration, volume, and policy disposition."],
  ["Check threat intelligence",     "Check configured reputation sources; preserve verdict confidence."],
  ["Establish event timeline",      "Correlate timestamps from source telemetry."],
  ["Determine investigation scope", "Search for related users, endpoints, and indicators."],
  ["Document evidence",             "Attach provenance and confidence to collected observations."],
  ["Prepare final analysis",        "Draft evidence-backed findings and run Security Analysis QA."],
] as const;

// Evidence templates per incident kind (keyed by templateId)
type EvidenceRow = [string, string, string | null, string | null, string | null, "LOW" | "MEDIUM" | "HIGH" | null];

const evidenceByTemplate: Record<string, EvidenceRow[]> = {
  suspicious_powershell: [
    ["hostname",         "Hostname",          "WIN-PC-1042",                              "CrowdStrike Falcon",        "MOCK-FALCON-0171", "HIGH"],
    ["username",         "Username",          "john.smith",                               "Microsoft Entra ID",        "MOCK-ENTRA-0814",  "HIGH"],
    ["source_ip",        "Source IP",         "10.10.4.21",                               "Splunk",                    "MOCK-SPL-2401",    "HIGH"],
    ["destination_ip",   "Destination IP",    "185.199.110.153",                          "Palo Alto",                 "MOCK-PA-8831",     "MEDIUM"],
    ["process",          "Process",           "powershell.exe",                           "CrowdStrike Falcon",        "MOCK-FALCON-0172", "HIGH"],
    ["parent_process",   "Parent process",    "cmd.exe",                                  "CrowdStrike Falcon",        "MOCK-FALCON-0172", "HIGH"],
    ["command_line",     "Command line",      "powershell -enc [synthetic encoded command]","CrowdStrike Falcon",      "MOCK-FALCON-0172", "HIGH"],
    ["hash",             "SHA-256",           "7a91c4d8...e20f",                          "CrowdStrike Falcon",        "MOCK-FALCON-0173", "HIGH"],
    ["authentication",   "Authentication",    "Successful sign-in; MFA satisfied",        "Microsoft Entra ID",        "MOCK-ENTRA-0814",  "HIGH"],
    ["threat_reputation","Threat reputation", "Suspicious; low prevalence",               "Google Threat Intelligence","MOCK-GTI-1102",    "MEDIUM"],
    ["geo_location",     "Geo location",      null,                                       null,                        null,               null],
    ["network_session",  "Network session",   null,                                       null,                        null,               null],
  ],
  impossible_travel: [
    ["username",              "Username",              "rachel.lee",                          "Microsoft Entra ID",        "MOCK-ENTRA-1001",  "HIGH"],
    ["source_ip",             "Source IP",             "34.120.8.15",                         "Microsoft Entra ID",        "MOCK-ENTRA-1002",  "HIGH"],
    ["source_location",       "Source location",       "New York, US",                        "Microsoft Entra ID",        "MOCK-ENTRA-1003",  "HIGH"],
    ["destination_location",  "Destination location",  "London, UK",                          "Microsoft Entra ID",        "MOCK-ENTRA-1004",  "HIGH"],
    ["authentication_event",  "Authentication event",  "Successful sign-in",                  "Microsoft Entra ID",        "MOCK-ENTRA-1005",  "HIGH"],
    ["mfa_status",            "MFA status",            "Satisfied",                           "Microsoft Entra ID",        "MOCK-ENTRA-1006",  "HIGH"],
    ["geo_location",          "Geo location",          null,                                  null,                        null,               null],
    ["session_duration",      "Session duration",      null,                                  null,                        null,               null],
  ],
  malware_detection: [
    ["hostname",         "Hostname",          "WIN-OPS-088",                              "CrowdStrike Falcon",        "MOCK-FALCON-2001", "HIGH"],
    ["username",         "Username",          "svc-backup",                               "CrowdStrike Falcon",        "MOCK-FALCON-2002", "HIGH"],
    ["file_hash",        "File hash",         "4d3a5f9b...1c8e",                          "CrowdStrike Falcon",        "MOCK-FALCON-2003", "HIGH"],
    ["process",          "Process",           "svchost.exe (suspicious variant)",         "CrowdStrike Falcon",        "MOCK-FALCON-2004", "HIGH"],
    ["parent_process",   "Parent process",    "services.exe",                             "CrowdStrike Falcon",        "MOCK-FALCON-2005", "HIGH"],
    ["reputation",       "Threat reputation", "Malicious; known dropper family",          "Google Threat Intelligence","MOCK-GTI-2001",    "HIGH"],
    ["source_ip",        "Source IP",         "10.10.7.88",                               "Splunk",                    "MOCK-SPL-2001",    "MEDIUM"],
    ["geo_location",     "Geo location",      null,                                       null,                        null,               null],
    ["network_session",  "Network session",   null,                                       null,                        null,               null],
  ],
  brute_force_authentication: [
    ["username",           "Targeted accounts", "multiple users",                          "Microsoft Entra ID",        "MOCK-ENTRA-3001",  "HIGH"],
    ["source_ip",          "Source IP",         "45.33.18.204",                            "Splunk",                    "MOCK-SPL-3001",    "HIGH"],
    ["failure_count",      "Failure count",     "247 failed attempts in 4 minutes",        "Microsoft Entra ID",        "MOCK-ENTRA-3002",  "HIGH"],
    ["success_event",      "Successful login",  null,                                      null,                        null,               null],
    ["mfa_status",         "MFA status",        "MFA bypassed on one account",             "Microsoft Entra ID",        "MOCK-ENTRA-3003",  "HIGH"],
    ["time_window",        "Time window",       "13:38:00 – 13:42:00 UTC",                 "Splunk",                    "MOCK-SPL-3002",    "HIGH"],
    ["geo_location",       "Geo location",      null,                                      null,                        null,               null],
    ["targeted_accounts",  "Targeted accounts list", null,                                 null,                        null,               null],
  ],
  c2_communication: [
    ["hostname",         "Hostname",          "WIN-ENG-116",                              "CrowdStrike Falcon",        "MOCK-FALCON-4001", "HIGH"],
    ["source_ip",        "Source IP",         "10.10.8.116",                              "Palo Alto",                 "MOCK-PA-4001",     "HIGH"],
    ["destination_ip",   "Destination IP",    "91.219.236.44",                            "Palo Alto",                 "MOCK-PA-4002",     "HIGH"],
    ["domain",           "Domain",            "update-cdn-srv.net",                       "Splunk",                    "MOCK-SPL-4001",    "MEDIUM"],
    ["network_session",  "Network session",   "TCP/443 · beaconing pattern observed",     "Palo Alto",                 "MOCK-PA-4003",     "HIGH"],
    ["reputation",       "Threat reputation", "Suspicious; C2 infrastructure association","Google Threat Intelligence","MOCK-GTI-4001",    "HIGH"],
    ["geo_location",     "Geo location",      null,                                       null,                        null,               null],
    ["process",          "Originating process",null,                                       null,                        null,               null],
    ["dns_query",        "DNS query",         null,                                       null,                        null,               null],
  ],
  potential_data_exfiltration: [
    ["hostname",          "Hostname",           "FS-FIN-02",                               "Splunk",                    "MOCK-SPL-5001",    "HIGH"],
    ["username",          "Username",           "a.patel",                                 "Microsoft Entra ID",        "MOCK-ENTRA-5001",  "HIGH"],
    ["destination_ip",    "Destination IP",     null,                                      null,                        null,               null],
    ["bytes_transferred", "Bytes transferred",  null,                                      null,                        null,               null],
    ["data_class",        "Data classification","Financial records (PCI scope)",           "Splunk",                    "MOCK-SPL-5002",    "MEDIUM"],
    ["network_session",   "Network session",    null,                                      null,                        null,               null],
    ["geo_location",      "Geo location",       null,                                      null,                        null,               null],
    ["reputation",        "Destination reputation", null,                                  null,                        null,               null],
    ["accessed_files",    "Accessed files",     null,                                      null,                        null,               null],
  ],
};

// Steps per template (title, purpose, recommendedTools)
type StepRow = [string, string, string[]];

const stepsByTemplate: Record<string, StepRow[]> = {
  suspicious_powershell: [
    ["Identify affected endpoint",    "Confirm endpoint identity and criticality from EDR telemetry.",                                      ["CrowdStrike Falcon"]],
    ["Identify executing user",       "Correlate the initiating identity with sign-in context.",                                             ["Microsoft Entra ID"]],
    ["Retrieve process tree",         "Trace parent-child process relationships and execution time.",                                        ["CrowdStrike Falcon"]],
    ["Review command line",           "Review encoded arguments and assess intent without assuming maliciousness.",                          ["CrowdStrike Falcon"]],
    ["Identify file and hash",        "Record the observed file hash and reputation context.",                                               ["CrowdStrike Falcon", "Google Threat Intelligence"]],
    ["Investigate source IP",         "Establish whether the source address is expected for this user.",                                     ["Splunk", "Microsoft Entra ID"]],
    ["Investigate destination IP",    "Correlate destination activity across network and SIEM sources.",                                     ["Palo Alto", "Splunk"]],
    ["Review authentication activity","Review sign-ins and MFA events around the detection window.",                                         ["Microsoft Entra ID"]],
    ["Review network activity",       "Determine protocol, duration, volume, and policy disposition.",                                       ["Palo Alto", "Splunk"]],
    ["Check threat intelligence",     "Check configured reputation sources; preserve verdict confidence.",                                   ["Google Threat Intelligence"]],
    ["Establish event timeline",      "Correlate timestamps from source telemetry.",                                                         ["Splunk", "CrowdStrike Falcon"]],
    ["Determine investigation scope", "Search for related users, endpoints, and indicators.",                                                ["CrowdStrike Falcon", "Splunk"]],
    ["Document evidence",             "Attach provenance and confidence to collected observations.",                                         ["CrowdStrike Falcon", "Microsoft Entra ID"]],
    ["Prepare final analysis",        "Draft evidence-backed findings and run Security Analysis QA.",                                        ["Splunk", "CrowdStrike Falcon"]],
  ],
  impossible_travel: [
    ["Identify affected user account",      "Confirm the user identity and account status.",                                                 ["Microsoft Entra ID"]],
    ["Correlate sign-in locations",         "Compare sign-in geo-locations within the suspicious time window.",                             ["Microsoft Entra ID", "Splunk"]],
    ["Check geo-location and travel velocity","Calculate travel velocity between sign-in locations.",                                        ["Microsoft Entra ID", "Google Threat Intelligence"]],
    ["Review MFA challenge result",         "Determine whether MFA was satisfied or bypassed.",                                             ["Microsoft Entra ID"]],
    ["Inspect session duration and activity","Review session actions following the suspicious sign-in.",                                     ["Microsoft Entra ID", "Splunk"]],
    ["Check for concurrent sessions",       "Identify overlapping sessions from different locations.",                                       ["Microsoft Entra ID"]],
    ["Review prior sign-in history",        "Establish baseline locations and devices for this user.",                                       ["Microsoft Entra ID"]],
    ["Assess account compromise risk",      "Determine whether credential theft or account takeover is likely.",                            ["Microsoft Entra ID", "Google Threat Intelligence"]],
    ["Document evidence",                   "Attach provenance and confidence to collected observations.",                                  ["Microsoft Entra ID"]],
    ["Prepare final analysis",              "Draft evidence-backed findings and run Security Analysis QA.",                                  ["Microsoft Entra ID", "Splunk"]],
  ],
  malware_detection: [
    ["Identify affected endpoint",     "Confirm endpoint identity and criticality from EDR alert.",                                         ["CrowdStrike Falcon"]],
    ["Identify executing user",        "Correlate the user context at detection time.",                                                     ["CrowdStrike Falcon", "Microsoft Entra ID"]],
    ["Retrieve process and file details","Collect full process tree and file path.",                                                        ["CrowdStrike Falcon"]],
    ["Check file hash reputation",     "Query threat intelligence for the file hash.",                                                      ["Google Threat Intelligence", "CrowdStrike Falcon"]],
    ["Identify parent process",        "Determine execution origin and potential dropper.",                                                 ["CrowdStrike Falcon"]],
    ["Review network connections",     "Identify any C2 or lateral movement network activity.",                                            ["Palo Alto", "Splunk"]],
    ["Establish geo-location context", "Geolocate external IPs involved in network sessions.",                                              ["Google Threat Intelligence"]],
    ["Scope lateral movement risk",    "Search for related alerts on peer endpoints.",                                                      ["CrowdStrike Falcon", "Splunk"]],
    ["Collect all related IOCs",       "Document hashes, IPs, domains, and registry keys.",                                                ["CrowdStrike Falcon", "Google Threat Intelligence"]],
    ["Document evidence",              "Attach provenance and confidence to collected observations.",                                       ["CrowdStrike Falcon"]],
    ["Prepare final analysis",         "Draft evidence-backed findings and run Security Analysis QA.",                                      ["Splunk", "CrowdStrike Falcon"]],
  ],
  brute_force_authentication: [
    ["Identify source IP and geo-location",     "Confirm attacker IP and geographic origin.",                                               ["Splunk", "Google Threat Intelligence"]],
    ["Count authentication failures in time window","Quantify the failure volume and velocity.",                                           ["Microsoft Entra ID", "Splunk"]],
    ["Identify targeted accounts",             "List all accounts targeted by the brute force.",                                           ["Microsoft Entra ID"]],
    ["Check for successful authentication",    "Determine if any login succeeded following the failures.",                                 ["Microsoft Entra ID"]],
    ["Verify MFA status on success",           "Confirm whether MFA was enforced for any successful login.",                               ["Microsoft Entra ID"]],
    ["Assess account lockout status",          "Check if targeted accounts triggered lockout policies.",                                   ["Microsoft Entra ID"]],
    ["Check IP reputation",                    "Query threat intelligence for attacker IP reputation.",                                    ["Google Threat Intelligence"]],
    ["Determine scope of affected accounts",   "Review all accounts touched, not just the primary target.",                               ["Microsoft Entra ID", "Splunk"]],
    ["Document evidence",                      "Attach provenance and confidence to collected observations.",                              ["Microsoft Entra ID"]],
    ["Prepare final analysis",                 "Draft evidence-backed findings and run Security Analysis QA.",                             ["Microsoft Entra ID", "Splunk"]],
  ],
  c2_communication: [
    ["Identify affected endpoint",          "Confirm endpoint identity and criticality.",                                                  ["CrowdStrike Falcon"]],
    ["Identify destination IP and domain",  "Record all external IPs and domains contacted.",                                             ["Palo Alto", "Splunk"]],
    ["Check destination geo-location",      "Geolocate external destinations and flag unusual regions.",                                  ["Google Threat Intelligence"]],
    ["Query threat intelligence reputation","Check IP/domain against reputation sources.",                                                 ["Google Threat Intelligence"]],
    ["Review DNS query history",            "Identify DNS resolution for the suspicious domain.",                                         ["Splunk"]],
    ["Identify originating process",        "Trace which process initiated the outbound connection.",                                     ["CrowdStrike Falcon"]],
    ["Review network session details",      "Assess protocol, bytes, duration, and session count.",                                       ["Palo Alto"]],
    ["Check for beaconing pattern",         "Identify periodic outbound connections indicating C2 check-in.",                             ["Palo Alto", "Splunk"]],
    ["Scope affected endpoints",            "Search for the same destination contact from other hosts.",                                   ["Splunk", "CrowdStrike Falcon"]],
    ["Document evidence",                   "Attach provenance and confidence to collected observations.",                                 ["CrowdStrike Falcon"]],
    ["Prepare final analysis",              "Draft evidence-backed findings and run Security Analysis QA.",                                ["Palo Alto", "Splunk"]],
  ],
  potential_data_exfiltration: [
    ["Identify source endpoint and user",       "Confirm which endpoint and user account initiated the transfer.",                        ["Splunk", "Microsoft Entra ID"]],
    ["Identify destination IP and geo-location","Geolocate the external destination.",                                                   ["Palo Alto", "Google Threat Intelligence"]],
    ["Measure data volume transferred",         "Quantify bytes transferred in the session.",                                            ["Palo Alto", "Splunk"]],
    ["Classify data type and sensitivity",      "Determine if PCI, PII, or other regulated data is involved.",                          ["Splunk"]],
    ["Check destination reputation",            "Query threat intelligence for the destination IP.",                                     ["Google Threat Intelligence"]],
    ["Review file access logs",                 "Identify which files were accessed before the transfer.",                              ["Splunk", "Microsoft Entra ID"]],
    ["Correlate with identity activity",        "Check for account anomalies or privilege changes.",                                    ["Microsoft Entra ID"]],
    ["Determine business impact",               "Assess sensitivity of exfiltrated data and regulatory exposure.",                      ["Splunk"]],
    ["Scope additional affected systems",       "Search for similar transfers from other endpoints.",                                   ["Splunk", "Palo Alto"]],
    ["Document evidence",                       "Attach provenance and confidence to collected observations.",                          ["Microsoft Entra ID", "Splunk"]],
    ["Prepare final analysis",                  "Draft evidence-backed findings and run Security Analysis QA.",                         ["Splunk", "Palo Alto"]],
  ],
};

/** Pick recommended tools filtered to the client's actual installed tools */
function filterTools(recommended: string[], availableTools: string[]): string[] {
  const filtered = recommended.filter(t => availableTools.includes(t));
  return filtered.length > 0 ? filtered : recommended; // fall back to recommended if none match
}

export async function ensureInvestigation(incidentId: string) {
  const incident = await db.incident.findUnique({
    where: { id: incidentId },
    include: { client: { include: { tools: true } }, template: true },
  });
  if (!incident) return null;

  const availableTools = incident.client.tools
    .filter(t => t.enabled)
    .map(t => t.name);

  const templateId = incident.templateId ?? "suspicious_powershell";

  const investigation = await db.investigation.upsert({
    where: { incidentId },
    update: {},
    create: { id: `INV-${incidentId}`, incidentId, clientId: incident.clientId },
    include: { steps: true, artifacts: true, evidence: true, queries: true, timeline: true },
  });

  // Create steps from template-specific definitions, filtered to client tools
  if (investigation.steps.length === 0) {
    const stepDefs = stepsByTemplate[templateId] ?? stepDefinitions.map(([title, purpose]) => [title, purpose, ["CrowdStrike Falcon"]] as StepRow);
    await db.investigationStep.createMany({
      data: stepDefs.map(([title, purpose, recommended], index) => ({
        id: `${investigation.id}-STEP-${index + 1}`,
        investigationId: investigation.id,
        index,
        title,
        purpose,
        recommendedTools: JSON.stringify(filterTools(recommended, availableTools)),
        requiredArtifacts: JSON.stringify([]),
      })),
    });
  }

  // Create evidence from template-specific evidence definitions
  if (investigation.evidence.length === 0) {
    const evidenceDefs = evidenceByTemplate[templateId] ?? evidenceByTemplate.suspicious_powershell;
    await db.evidence.createMany({
      data: evidenceDefs.map(([key, label, value, _sourceTool, sourceEventId, confidence]) => ({
        id: `${investigation.id}-${key}`,
        investigationId: investigation.id,
        key,
        label,
        value,
        sourceEventId,
        // Store source tool name in rawReference since the schema has no free-text sourceTool column
        rawReference: sourceEventId ?? _sourceTool ?? null,
        confidence: confidence as "LOW" | "MEDIUM" | "HIGH" | null,
        collectedAt: value ? new Date("2026-09-28T14:42:19Z") : null,
      })),
    });
  }

  if (investigation.timeline.length === 0) {
    const adapterEvents = (await mockAdapters[0].search({ query: incident.name })).events;
    await db.timelineEvent.createMany({
      data: adapterEvents.map(event => ({
        id: `${investigation.id}-${event.id}`,
        investigationId: investigation.id,
        timestamp: new Date(event.timestamp),
        source: event.source,
        host: event.host,
        user: event.user,
        eventType: event.eventType,
        description: event.description,
        severity: event.severity,
      })),
    });
  }

  return db.investigation.findUnique({
    where: { id: investigation.id },
    include: {
      incident: true,
      client: { include: { tools: true } },
      steps: { orderBy: { index: "asc" } },
      artifacts: true,
      evidence: true,
      queries: true,
      timeline: { orderBy: { timestamp: "asc" } },
      analysis: { include: { validations: true } },
      report: true,
    },
  });
}

export async function recordAudit(input: {
  actor: string;
  action: string;
  incidentId?: string;
  tool?: string;
  metadata?: Record<string, unknown>;
}) {
  return db.auditEvent.create({
    data: {
      actor: input.actor,
      action: input.action,
      incidentId: input.incidentId,
      tool: input.tool,
      metadata: JSON.stringify(input.metadata ?? {}),
    },
  });
}

export function toDomainEvidence(
  items: Array<{
    key: string;
    label: string;
    value: string | null;
    sourceTool?: string | null;
    sourceEventId: string | null;
    collectedAt: Date | null;
    confidence: "LOW" | "MEDIUM" | "HIGH" | null;
    rawReference: string | null;
    tool?: { name: string } | null;
  }>
): DomainEvidence[] {
  return items.map(item => ({
    ...item,
    // Prefer sourceTool if present (legacy), else derive from tool relation, else rawReference
    sourceTool: item.sourceTool ?? item.tool?.name ?? item.rawReference ?? null,
    collectedAt: item.collectedAt?.toISOString() ?? null,
    confidence: item.confidence?.toLowerCase() as DomainEvidence["confidence"] ?? null,
  }));
}
