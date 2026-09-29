import type { GeneratedQuery } from "@/types/domain";

const toSplunkRange = (timeRange: string) =>
  timeRange === "1 hour" ? "-1h" : timeRange === "7 days" ? "-7d" : "-24h";

type QueryInput = {
  incidentId: string;
  platform: string;
  indicator: string;
  timeRange: string;
  host: string;
  /** Incident type drives platform-specific query structure */
  incidentKind?: "powershell" | "impossible_travel" | "malware" | "brute_force" | "c2" | "exfiltration" | "generic";
};

function buildSplunkQuery(input: QueryInput): string {
  const r = toSplunkRange(input.timeRange);
  switch (input.incidentKind) {
    case "impossible_travel":
      return `index=* sourcetype="azure:aad:signin" (user="${input.indicator}" OR src_ip="${input.indicator}") earliest=${r} latest=now\n| eval country=iff(isnotnull(geoip_country), geoip_country, "Unknown")\n| stats count by user, country, src_ip, _time\n| sort _time`;
    case "brute_force":
      return `index=* sourcetype="azure:aad:signin" action=failure src_ip="${input.indicator}" earliest=${r} latest=now\n| stats count as failures by user, src_ip\n| where failures > 10\n| sort -failures`;
    case "c2":
      return `index=* (src_ip="${input.indicator}" OR dest_ip="${input.indicator}") earliest=${r} latest=now\n| stats count by src_ip, dest_ip, dest_port, bytes_out\n| where bytes_out > 0\n| sort -bytes_out`;
    case "exfiltration":
      return `index=* (src_ip="${input.indicator}" OR host="${input.host}") bytes_out>* earliest=${r} latest=now\n| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, host\n| sort -total_bytes`;
    case "malware":
      return `index=* (file_hash="${input.indicator}" OR host="${input.host}") earliest=${r} latest=now\n| stats count by host, file_hash, process_name, parent_process\n| sort _time`;
    default:
      return `index=* (src_ip="${input.indicator}" OR dest_ip="${input.indicator}" OR host="${input.host}") earliest=${r} latest=now\n| sort _time`;
  }
}

function buildFalconQuery(input: QueryInput): string {
  switch (input.incidentKind) {
    case "malware":
      return `hash.sha256:"${input.indicator}" OR host.hostname:"${input.host}"\n| sort timestamp desc`;
    case "c2":
      return `host.hostname:"${input.host}" AND network.remote_address:"${input.indicator}"\n| sort timestamp desc`;
    case "powershell":
      return `host.hostname:"${input.host}" AND (network.remote_address:"${input.indicator}" OR process.name:"powershell.exe")\n| sort timestamp desc`;
    default:
      return `host.hostname:"${input.host}" AND (network.remote_address:"${input.indicator}" OR process.name:"${input.indicator}")\n| sort timestamp desc`;
  }
}

function buildPaloAltoQuery(input: QueryInput): string {
  switch (input.incidentKind) {
    case "exfiltration":
      return `(addr.src in ${input.indicator} or addr.src in ${input.host}) and bytes > 1000000\n| sort receive_time desc`;
    case "c2":
      return `(addr.src in ${input.host} and addr.dst in ${input.indicator}) and application neq "ssl"\n| sort receive_time desc`;
    default:
      return `(addr.src in ${input.indicator} or addr.dst in ${input.indicator})\n| sort receive_time desc`;
  }
}

function buildGoogleSecOpsQuery(input: QueryInput): string {
  switch (input.incidentKind) {
    case "impossible_travel":
      return `metadata.event_type = "USER_LOGIN"\nAND principal.user.userid = "${input.indicator}"\nAND metadata.base_labels.key = "result" AND metadata.base_labels.value = "SUCCESS"`;
    case "brute_force":
      return `metadata.event_type = "USER_LOGIN"\nAND principal.ip = "${input.indicator}"\nAND security_result.action = "BLOCK"`;
    case "c2":
      return `metadata.event_type = "NETWORK_CONNECTION"\nAND (principal.ip = "${input.indicator}" OR target.ip = "${input.indicator}")\nAND network.application_protocol != "HTTP"`;
    case "malware":
      return `metadata.event_type = "PROCESS_LAUNCH"\nAND (target.process.file.sha256 = "${input.indicator}" OR principal.hostname = "${input.host}")`;
    default:
      return `metadata.event_type = "NETWORK_CONNECTION"\nAND (principal.ip = "${input.indicator}" OR target.ip = "${input.indicator}")`;
  }
}

function buildSentinelQuery(input: QueryInput): string {
  const r = toSplunkRange(input.timeRange);
  const duration = r === "-1h" ? "1h" : r === "-7d" ? "7d" : "24h";
  switch (input.incidentKind) {
    case "brute_force":
      return `SigninLogs\n| where TimeGenerated > ago(${duration})\n| where IPAddress == "${input.indicator}" and ResultType != "0"\n| summarize Failures=count() by UserPrincipalName, IPAddress\n| where Failures > 10`;
    case "impossible_travel":
      return `SigninLogs\n| where TimeGenerated > ago(${duration})\n| where UserPrincipalName == "${input.indicator}"\n| project TimeGenerated, IPAddress, Location, ResultType`;
    default:
      return `CommonSecurityLog\n| where TimeGenerated > ago(${duration})\n| where SourceIP == "${input.indicator}" or DestinationIP == "${input.indicator}"`;
  }
}

function getPurpose(incidentKind: QueryInput["incidentKind"], platform: string): string {
  const purposeMap: Record<string, string> = {
    powershell:        "Trace PowerShell execution and associated network activity",
    impossible_travel: "Correlate user sign-ins across geographic locations",
    malware:           "Identify malicious file activity and lateral movement",
    brute_force:       "Quantify authentication failure volume and identify successes",
    c2:                "Detect C2 beaconing patterns and associated DNS activity",
    exfiltration:      "Measure data transfer volume and destination reputation",
    generic:           "Correlate the indicator with affected endpoint telemetry",
  };
  return `${purposeMap[incidentKind ?? "generic"]} via ${platform}`;
}

export function generateDeterministicQuery(input: QueryInput): GeneratedQuery {
  let query: string;
  switch (input.platform) {
    case "Splunk":            query = buildSplunkQuery(input);     break;
    case "CrowdStrike Falcon":query = buildFalconQuery(input);     break;
    case "Palo Alto":         query = buildPaloAltoQuery(input);   break;
    case "Google SecOps":     query = buildGoogleSecOpsQuery(input);break;
    default:                  query = buildSentinelQuery(input);   break;
  }

  return {
    id: `${input.platform.toLowerCase().replaceAll(" ", "-")}-${Date.now()}`,
    platform: input.platform,
    purpose: getPurpose(input.incidentKind, input.platform),
    template: "deterministic-v2.0",
    expectedEvidence: ["timestamp", "source/destination", "action", "endpoint"],
    confidence: "high",
    incidentId: input.incidentId,
    indicator: input.indicator,
    timeRange: input.timeRange,
    query,
  };
}

/** Map an incident name/rule to a kind for query generation */
export function incidentKindFromName(name: string, rule?: string): QueryInput["incidentKind"] {
  const n = (name + " " + (rule ?? "")).toLowerCase();
  if (n.includes("powershell") || n.includes("ps-exec"))       return "powershell";
  if (n.includes("impossible travel") || n.includes("travel")) return "impossible_travel";
  if (n.includes("malware") || n.includes("edr-mal"))          return "malware";
  if (n.includes("brute force") || n.includes("auth-bf"))      return "brute_force";
  if (n.includes("c2") || n.includes("net-c2"))                return "c2";
  if (n.includes("exfil") || n.includes("dlp-exf"))            return "exfiltration";
  return "generic";
}
