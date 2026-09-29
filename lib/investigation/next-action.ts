import type { Incident, NextBestAction } from "@/types/domain";

type IncidentKind =
  | "powershell"
  | "impossible_travel"
  | "malware"
  | "brute_force"
  | "c2"
  | "exfiltration"
  | "generic";

function classifyIncident(incident: Incident): IncidentKind {
  const n = (incident.name + " " + incident.rule).toLowerCase();
  if (n.includes("powershell") || n.includes("ps-exec"))        return "powershell";
  if (n.includes("impossible travel") || n.includes("travel"))  return "impossible_travel";
  if (n.includes("malware") || n.includes("edr-mal"))           return "malware";
  if (n.includes("brute force") || n.includes("auth-bf"))       return "brute_force";
  if (n.includes("c2") || n.includes("net-c2"))                 return "c2";
  if (n.includes("exfil") || n.includes("dlp-exf"))             return "exfiltration";
  return "generic";
}

interface ActionSpec {
  action: string;
  reason: string;
  preferredTools: string[];
  requiredArtifacts: string[];
}

function getActionSpec(
  kind: IncidentKind,
  incident: Incident,
  completedSteps: string[],
  missingArtifacts: string[]
): ActionSpec {
  const stepsComplete = completedSteps.length;

  switch (kind) {
    case "powershell":
      if (incident.destinationIp && incident.destinationIp !== "—") {
        return {
          action: "Investigate destination IP and network session",
          reason: "An external connection followed encoded PowerShell execution. Network session and threat reputation context remain incomplete.",
          preferredTools: ["Palo Alto", "Splunk", "Google Threat Intelligence"],
          requiredArtifacts: missingArtifacts.length ? missingArtifacts : ["destination_ip", "network_session", "geo_location"],
        };
      }
      return {
        action: "Retrieve PowerShell process tree from EDR",
        reason: "No destination IP is available; process lineage is the highest-value next step.",
        preferredTools: ["CrowdStrike Falcon"],
        requiredArtifacts: ["process", "parent_process", "command_line"],
      };

    case "impossible_travel":
      if (stepsComplete < 3) {
        return {
          action: "Correlate sign-in locations and calculate travel velocity",
          reason: "The impossible travel alert requires confirming geographic distance and travel time between sign-in events.",
          preferredTools: ["Microsoft Entra ID", "Google Threat Intelligence"],
          requiredArtifacts: ["source_location", "destination_location", "geo_location"],
        };
      }
      return {
        action: "Verify MFA status and review session activity",
        reason: "Locations confirmed; MFA bypass or session hijack must be ruled out before disposition.",
        preferredTools: ["Microsoft Entra ID"],
        requiredArtifacts: ["mfa_status", "session_duration"],
      };

    case "malware":
      if (!completedSteps.some(s => s.toLowerCase().includes("hash") || s.toLowerCase().includes("reputation"))) {
        return {
          action: "Submit file hash to threat intelligence",
          reason: "File reputation is the fastest path to a high-confidence malware classification.",
          preferredTools: ["Google Threat Intelligence", "CrowdStrike Falcon"],
          requiredArtifacts: ["file_hash", "reputation"],
        };
      }
      return {
        action: "Scope lateral movement from affected endpoint",
        reason: "Malware is confirmed; identify peer endpoints that may share the same IOC.",
        preferredTools: ["CrowdStrike Falcon", "Splunk"],
        requiredArtifacts: ["network_session", "geo_location"],
      };

    case "brute_force":
      if (!completedSteps.some(s => s.toLowerCase().includes("success"))) {
        return {
          action: "Check for successful authentication following failures",
          reason: "A successful login after brute-force failures indicates credential compromise and is the critical next gate.",
          preferredTools: ["Microsoft Entra ID", "Splunk"],
          requiredArtifacts: ["success_event", "mfa_status"],
        };
      }
      return {
        action: "Identify geo-location of attacker IP and assess scope",
        reason: "Failure volume confirmed; attacker origin and account scope determine priority.",
        preferredTools: ["Google Threat Intelligence", "Microsoft Entra ID"],
        requiredArtifacts: ["geo_location", "targeted_accounts"],
      };

    case "c2":
      return {
        action: "Identify originating process and check for beaconing pattern",
        reason: "C2 communication requires confirming the process responsible and whether periodic beaconing is occurring.",
        preferredTools: ["CrowdStrike Falcon", "Palo Alto", "Google Threat Intelligence"],
        requiredArtifacts: incident.destinationIp !== "—"
          ? ["process", "dns_query", "reputation"]
          : ["hostname", "network_session"],
      };

    case "exfiltration":
      return {
        action: "Measure data volume transferred and classify data sensitivity",
        reason: "Data exfiltration impact depends on volume and data classification. Bytes transferred and destination reputation are critical.",
        preferredTools: ["Palo Alto", "Splunk", "Google Threat Intelligence"],
        requiredArtifacts: ["bytes_transferred", "destination_ip", "data_class", "geo_location"],
      };

    default:
      return {
        action: incident.destinationIp !== "—"
          ? "Investigate destination IP"
          : "Review affected endpoint",
        reason: incident.destinationIp !== "—"
          ? "An external connection was observed; network session and reputation context remain incomplete."
          : "The alert identifies an endpoint but no destination indicator is available.",
        preferredTools: ["Palo Alto", "Splunk", "Google Threat Intelligence"],
        requiredArtifacts: missingArtifacts.length ? missingArtifacts : ["destination_ip", "network_session"],
      };
  }
}

export function getNextBestAction(
  incident: Incident,
  availableTools: string[],
  missingArtifacts: string[],
  completedSteps: string[] = []
): NextBestAction {
  const kind = classifyIncident(incident);
  const spec = getActionSpec(kind, incident, completedSteps, missingArtifacts);

  // Filter preferred tools to what the client actually has configured
  const filteredTools = spec.preferredTools.filter(t => availableTools.includes(t));
  const tools = filteredTools.length > 0 ? filteredTools : spec.preferredTools;

  return {
    action: spec.action,
    reason: spec.reason,
    tools,
    requiredArtifacts: spec.requiredArtifacts,
  };
}
