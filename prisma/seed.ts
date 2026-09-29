import { PrismaClient, IncidentStatus, Severity, ToolCategory } from "@prisma/client";
const prisma = new PrismaClient();

const incidentRows = [
  { id: "INC-1042", rule: "PS-EXEC-001",   name: "Suspicious PowerShell Execution", severity: Severity.HIGH,     status: IncidentStatus.INVESTIGATING,    host: "WIN-PC-1042", user: "john.smith",    sourceIp: "10.10.4.21",   destinationIp: "185.199.110.153", templateId: "suspicious_powershell",           detectedAt: new Date("2026-09-28T14:32:08Z") },
  { id: "INC-1041", rule: "ID-TRAVEL-004",  name: "Impossible Travel",               severity: Severity.MEDIUM,   status: IncidentStatus.TRIAGE,           host: "MAC-FIN-028", user: "rachel.lee",   sourceIp: "34.120.8.15",  destinationIp: "91.198.174.192",  templateId: "impossible_travel",              detectedAt: new Date("2026-09-28T14:18:42Z") },
  { id: "INC-1040", rule: "EDR-MAL-022",    name: "Malware Detection",               severity: Severity.CRITICAL, status: IncidentStatus.INVESTIGATING,    host: "WIN-OPS-088", user: "svc-backup",   sourceIp: "10.10.7.88",   destinationIp: "—",               templateId: "malware_detection",              detectedAt: new Date("2026-09-28T13:56:19Z") },
  { id: "INC-1039", rule: "AUTH-BF-012",    name: "Brute Force Authentication",      severity: Severity.MEDIUM,   status: IncidentStatus.TRIAGE,           host: "IDP-GW-01",   user: "multiple users", sourceIp: "45.33.18.204", destinationIp: "10.10.0.10",      templateId: "brute_force_authentication",     detectedAt: new Date("2026-09-28T13:41:02Z") },
  { id: "INC-1038", rule: "NET-C2-008",     name: "Suspicious C2 Communication",     severity: Severity.HIGH,     status: IncidentStatus.INVESTIGATING,    host: "WIN-ENG-116", user: "d.chen",       sourceIp: "10.10.8.116",  destinationIp: "91.219.236.44",   templateId: "c2_communication",              detectedAt: new Date("2026-09-28T13:22:51Z") },
  { id: "INC-1037", rule: "DLP-EXF-031",    name: "Potential Data Exfiltration",     severity: Severity.HIGH,     status: IncidentStatus.AWAITING_REVIEW,  host: "FS-FIN-02",   user: "a.patel",      sourceIp: "10.10.2.19",   destinationIp: "—",               templateId: "potential_data_exfiltration",    detectedAt: new Date("2026-09-28T12:58:37Z") },
];

const templates = [
  {
    id: "suspicious_powershell",
    name: "Suspicious PowerShell Execution",
    description: "Endpoint execution and network pivot investigation",
    severities: JSON.stringify(["HIGH", "CRITICAL"]),
    artifacts: JSON.stringify(["hostname", "username", "process", "parent_process", "command_line", "hash", "source_ip", "destination_ip", "geo_location", "authentication", "threat_reputation", "network_session"]),
    steps: JSON.stringify(["Identify affected endpoint", "Identify executing user", "Retrieve process tree", "Review command line", "Identify file and hash", "Investigate source IP", "Investigate destination IP", "Review authentication activity", "Review network activity", "Check threat intelligence", "Establish event timeline", "Determine investigation scope", "Document evidence", "Prepare final analysis"]),
    queryTemplates: JSON.stringify(["splunk-destination-ip", "falcon-process-tree", "paloalto-network-session"]),
    recommendedLogSources: JSON.stringify(["Splunk", "CrowdStrike Falcon", "Microsoft Entra ID", "Palo Alto", "Google Threat Intelligence"]),
    analysisTemplate: "Observed evidence, analyst interpretation, hypothesis, recommendation",
  },
  {
    id: "impossible_travel",
    name: "Impossible Travel",
    description: "Identity sign-in correlation across geographies, MFA context, and session review.",
    severities: JSON.stringify(["MEDIUM", "HIGH"]),
    artifacts: JSON.stringify(["username", "source_ip", "source_location", "destination_location", "authentication_event", "mfa_status", "geo_location", "session_duration"]),
    steps: JSON.stringify(["Identify affected user account", "Correlate sign-in locations", "Check geo-location and travel velocity", "Review MFA challenge result", "Inspect session duration and activity", "Check for concurrent sessions", "Review prior sign-in history", "Assess account compromise risk", "Document evidence", "Prepare final analysis"]),
    queryTemplates: JSON.stringify(["entra-sign-in-logs", "splunk-auth-events"]),
    recommendedLogSources: JSON.stringify(["Microsoft Entra ID", "Splunk", "Google Threat Intelligence"]),
    analysisTemplate: "User account, sign-in locations, geo velocity, MFA context, session review, risk assessment",
  },
  {
    id: "malware_detection",
    name: "Malware Detection",
    description: "Endpoint alert enrichment, file reputation, process lineage, and scope.",
    severities: JSON.stringify(["HIGH", "CRITICAL"]),
    artifacts: JSON.stringify(["hostname", "username", "file_hash", "process", "parent_process", "reputation", "source_ip", "geo_location", "network_session"]),
    steps: JSON.stringify(["Identify affected endpoint", "Identify executing user", "Retrieve process and file details", "Check file hash reputation", "Identify parent process", "Review network connections", "Establish geo-location context", "Scope lateral movement risk", "Collect all related IOCs", "Document evidence", "Prepare final analysis"]),
    queryTemplates: JSON.stringify(["falcon-file-hash", "splunk-network-connections"]),
    recommendedLogSources: JSON.stringify(["CrowdStrike Falcon", "Splunk", "Google Threat Intelligence"]),
    analysisTemplate: "Endpoint identity, file details, reputation, process lineage, network context, scope",
  },
  {
    id: "brute_force_authentication",
    name: "Brute Force Authentication",
    description: "Authentication failure clustering and successful-login validation.",
    severities: JSON.stringify(["MEDIUM", "HIGH"]),
    artifacts: JSON.stringify(["username", "source_ip", "failure_count", "success_event", "mfa_status", "time_window", "geo_location", "targeted_accounts"]),
    steps: JSON.stringify(["Identify source IP and geo-location", "Count authentication failures in time window", "Identify targeted accounts", "Check for successful authentication", "Verify MFA status on success", "Assess account lockout status", "Check IP reputation", "Determine scope of affected accounts", "Document evidence", "Prepare final analysis"]),
    queryTemplates: JSON.stringify(["entra-auth-failures", "splunk-brute-force", "gsecops-auth-events"]),
    recommendedLogSources: JSON.stringify(["Microsoft Entra ID", "Splunk", "Google SecOps"]),
    analysisTemplate: "Source IP, failure count, targeted accounts, successful login, MFA context, scope",
  },
  {
    id: "c2_communication",
    name: "Suspicious C2 Communication",
    description: "Network session, DNS, endpoint process, and threat-intelligence correlation.",
    severities: JSON.stringify(["HIGH", "CRITICAL"]),
    artifacts: JSON.stringify(["hostname", "source_ip", "destination_ip", "domain", "network_session", "reputation", "geo_location", "process", "dns_query"]),
    steps: JSON.stringify(["Identify affected endpoint", "Identify destination IP and domain", "Check destination geo-location", "Query threat intelligence reputation", "Review DNS query history", "Identify originating process", "Review network session details", "Check for beaconing pattern", "Scope affected endpoints", "Document evidence", "Prepare final analysis"]),
    queryTemplates: JSON.stringify(["paloalto-outbound-session", "splunk-dns-lookup", "falcon-network-connections"]),
    recommendedLogSources: JSON.stringify(["Palo Alto", "Splunk", "CrowdStrike Falcon", "Google Threat Intelligence"]),
    analysisTemplate: "Endpoint, destination IP/domain, geo-location, reputation, DNS, process, beaconing, scope",
  },
  {
    id: "potential_data_exfiltration",
    name: "Potential Data Exfiltration",
    description: "Data movement, network volume, destination reputation, and business context.",
    severities: JSON.stringify(["HIGH", "CRITICAL"]),
    artifacts: JSON.stringify(["hostname", "username", "destination_ip", "bytes_transferred", "data_class", "network_session", "geo_location", "reputation", "accessed_files"]),
    steps: JSON.stringify(["Identify source endpoint and user", "Identify destination IP and geo-location", "Measure data volume transferred", "Classify data type and sensitivity", "Check destination reputation", "Review file access logs", "Correlate with identity activity", "Determine business impact", "Scope additional affected systems", "Document evidence", "Prepare final analysis"]),
    queryTemplates: JSON.stringify(["splunk-data-transfer", "paloalto-outbound-volume", "entra-file-access"]),
    recommendedLogSources: JSON.stringify(["Splunk", "Palo Alto", "Microsoft Entra ID", "Google Threat Intelligence"]),
    analysisTemplate: "Endpoint, user, destination, data volume, data classification, reputation, business impact",
  },
];

async function main() {
  const client = await prisma.client.upsert({
    where: { id: "client-acme" },
    update: {},
    create: { id: "client-acme", name: "ACME Financial" },
  });

  const tools = [
    ["splunk",       "Splunk",                    ToolCategory.SIEM,        "MockSplunkAdapter"],
    ["crowdstrike",  "CrowdStrike Falcon",         ToolCategory.EDR,         "MockCrowdStrikeAdapter"],
    ["entra",        "Microsoft Entra ID",         ToolCategory.IDENTITY,    "MockEntraAdapter"],
    ["paloalto",     "Palo Alto",                  ToolCategory.NETWORK,     "MockPaloAltoAdapter"],
    ["gti",          "Google Threat Intelligence", ToolCategory.THREAT_INTEL,"MockThreatIntelAdapter"],
    ["servicenow",   "ServiceNow",                 ToolCategory.TICKETING,   "MockTicketingAdapter"],
  ] as const;

  for (const [id, name, category, adapter] of tools) {
    await prisma.tool.upsert({
      where: { id },
      update: { enabled: true },
      create: { id, clientId: client.id, name, category, adapter },
    });
  }

  for (const tmpl of templates) {
    await prisma.incidentTemplate.upsert({
      where: { id: tmpl.id },
      update: tmpl,
      create: tmpl,
    });
  }

  for (const incident of incidentRows) {
    await prisma.incident.upsert({
      where: { id: incident.id },
      update: { severity: incident.severity, status: incident.status },
      create: { ...incident, clientId: client.id },
    });
  }

  console.log(`Seeded ${tools.length} tools, ${templates.length} templates, ${incidentRows.length} incidents.`);
}

main().finally(() => prisma.$disconnect());
