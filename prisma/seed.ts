import { PrismaClient, IncidentStatus, Severity, ToolCategory } from "@prisma/client";
const prisma = new PrismaClient();
async function main() {
  const client = await prisma.client.upsert({ where: { id: "client-acme" }, update: {}, create: { id: "client-acme", name: "ACME Financial" } });
  const tools = [
    ["splunk", "Splunk", ToolCategory.SIEM, "MockSplunkAdapter"], ["crowdstrike", "CrowdStrike Falcon", ToolCategory.EDR, "MockCrowdStrikeAdapter"], ["entra", "Microsoft Entra ID", ToolCategory.IDENTITY, "MockEntraAdapter"], ["paloalto", "Palo Alto", ToolCategory.NETWORK, "MockPaloAltoAdapter"], ["gti", "Google Threat Intelligence", ToolCategory.THREAT_INTEL, "MockThreatIntelAdapter"], ["servicenow", "ServiceNow", ToolCategory.TICKETING, "MockTicketingAdapter"]
  ] as const;
  for (const [id, name, category, adapter] of tools) await prisma.tool.upsert({ where: { id }, update: { enabled: true }, create: { id, clientId: client.id, name, category, adapter } });
  await prisma.incidentTemplate.upsert({ where: { id: "powershell_execution" }, update: {}, create: { id: "powershell_execution", name: "Suspicious PowerShell Execution", description: "Endpoint execution and network pivot investigation", severities: JSON.stringify(["HIGH", "CRITICAL"]), artifacts: JSON.stringify(["hostname", "username", "destination_ip", "process", "hash", "network_session"]), steps: JSON.stringify(["Identify affected endpoint", "Identify executing user", "Retrieve process tree", "Review command line", "Investigate destination IP"]), queryTemplates: JSON.stringify(["splunk-destination-ip", "falcon-process-tree", "paloalto-network-session"]), recommendedLogSources: JSON.stringify(["Splunk", "CrowdStrike Falcon", "Microsoft Entra ID", "Palo Alto", "Google Threat Intelligence"]), analysisTemplate: "Observed evidence, interpretation, hypotheses, recommendations" } });
  const incidents = [{ id: "INC-1042", rule: "PS-EXEC-001", name: "Suspicious PowerShell Execution", severity: Severity.HIGH, status: IncidentStatus.INVESTIGATING, host: "WIN-PC-1042", user: "john.smith", sourceIp: "10.10.4.21", destinationIp: "185.199.110.153" }];
  for (const incident of incidents) await prisma.incident.upsert({ where: { id: incident.id }, update: incident, create: { ...incident, clientId: client.id, templateId: "powershell_execution", detectedAt: new Date("2026-09-28T14:32:08Z") } });
}
main().finally(() => prisma.$disconnect());
