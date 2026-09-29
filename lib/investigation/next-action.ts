import type { Incident, NextBestAction } from "@/types/domain";
export function getNextBestAction(incident: Incident, availableTools: string[], missingArtifacts: string[]): NextBestAction {
  const tools = ["Palo Alto", "Splunk", "Google Threat Intelligence"].filter(tool => availableTools.includes(tool));
  return { action: incident.destinationIp !== "—" ? "Investigate destination IP" : "Review affected endpoint", reason: incident.destinationIp !== "—" ? "An external connection followed endpoint execution; network session and reputation context remain incomplete." : "The alert identifies an endpoint but no destination indicator is available for a network pivot.", tools, requiredArtifacts: missingArtifacts.length ? missingArtifacts : ["destination_ip", "network_session", "reputation"] };
}
