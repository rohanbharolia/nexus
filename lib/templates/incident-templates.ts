import type { IncidentTemplate, Severity } from "@/types/domain";

const common = (title: string, purpose: string, sources: string[], artifacts: string[]): IncidentTemplate => ({
  id: title.toLowerCase().replaceAll(" ", "_"), name: title, description: purpose, severities: ["MEDIUM", "HIGH", "CRITICAL"] as Severity[],
  requiredArtifacts: artifacts.map(key => ({ key, label: key.replaceAll("_", " "), required: true, recommendedSources: sources })),
  investigationSteps: ["Classify alert", "Identify affected assets", "Correlate identity", "Review source telemetry", "Determine scope", "Document evidence", "Prepare analysis"].map((step, index) => ({ index, title: step, purpose: `${step} for ${title}.`, recommendedTools: sources, requiredArtifacts: artifacts.slice(0, Math.min(3, artifacts.length)), complete: false })),
  recommendedLogSources: sources,
  queryTemplates: sources.map(platform => ({ id: `${title}-${platform}`.toLowerCase().replaceAll(" ", "-"), platform, purpose: `Investigate ${title}`, template: `indicator={{indicator}} time_range={{timeRange}}`, expectedEvidence: artifacts, confidence: "medium" as const })),
  analysisTemplate: "Observed evidence, analyst interpretation, hypothesis, recommendation",
});

export const incidentTemplates: IncidentTemplate[] = [
  common("Suspicious PowerShell", "Endpoint execution, process lineage, network pivots, identity correlation, and threat context.", ["Splunk", "CrowdStrike Falcon", "Microsoft Entra ID", "Palo Alto", "Google Threat Intelligence"], ["hostname", "username", "process", "parent_process", "command_line", "hash", "destination_ip", "network_session"]),
  common("Impossible Travel", "Identity sign-in correlation across geographies, MFA context, and session review.", ["Microsoft Entra ID", "Splunk", "Google Threat Intelligence"], ["username", "source_ip", "source_location", "destination_location", "authentication_event", "mfa_status"]),
  common("Brute Force Authentication", "Authentication failure clustering and successful-login validation.", ["Microsoft Entra ID", "Splunk", "Google SecOps"], ["username", "source_ip", "failure_count", "success_event", "mfa_status", "time_window"]),
  common("Malware Detection", "Endpoint alert enrichment, file reputation, process lineage, and scope.", ["CrowdStrike Falcon", "Splunk", "Google Threat Intelligence"], ["hostname", "username", "file_hash", "process", "parent_process", "reputation"]),
  common("C2 Communication", "Network session, DNS, endpoint process, and threat-intelligence correlation.", ["Palo Alto", "Splunk", "CrowdStrike Falcon", "Google Threat Intelligence"], ["hostname", "source_ip", "destination_ip", "domain", "network_session", "reputation"]),
  common("Phishing", "Message, identity, URL, endpoint, and user-impact investigation.", ["Splunk", "Microsoft Entra ID", "CrowdStrike Falcon", "Google Threat Intelligence"], ["recipient", "sender", "url", "attachment_hash", "click_event", "authentication_event"]),
  common("Privilege Escalation", "Identity changes, process lineage, account context, and affected assets.", ["Microsoft Entra ID", "CrowdStrike Falcon", "Splunk"], ["username", "target_account", "privilege_change", "hostname", "process", "timestamp"]),
  common("Potential Data Exfiltration", "Data movement, network volume, destination reputation, and business context.", ["Splunk", "Palo Alto", "Microsoft Entra ID", "Google Threat Intelligence"], ["hostname", "username", "destination_ip", "bytes_transferred", "data_class", "network_session"]),
];
export const getTemplate = (id: string) => incidentTemplates.find(template => template.id === id || template.name.toLowerCase() === id.toLowerCase());
