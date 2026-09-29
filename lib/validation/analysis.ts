import type { Evidence, ValidationResult } from "@/types/domain";

export function validateAnalysis(text: string, evidence: Evidence[]): ValidationResult[] {
  const results: ValidationResult[] = [];
  const expected = new Map(evidence.filter(item => item.value).map(item => [item.key, item.value as string]));
  const host = text.match(/WIN-PC-\d+/i)?.[0]; if (host && expected.get("hostname") && host !== expected.get("hostname")) results.push({ type: "evidence_mismatch", severity: "critical", message: `Analyst hostname ${host} does not match collected evidence.`, source: "CrowdStrike Falcon", suggestedFix: expected.get("hostname") });
  if (/\b(attacker compromised|account was compromised|confirmed malicious|malicious IP)\b/i.test(text)) results.push({ type: "unsupported_claim", severity: "warning", message: "Evidence supports a suspicious reputation assessment, not a confirmed compromise or malicious verdict.", source: "Google Threat Intelligence", suggestedFix: "potentially malicious; corroboration required" });
  if (/\bpowershell\b/.test(text)) results.push({ type: "terminology", severity: "info", message: "Use the product-standard capitalization PowerShell.", suggestedFix: "PowerShell" });
  if (/\b(user executed|connection made|powershell and connection)\b/i.test(text)) results.push({ type: "grammar", severity: "info", message: "Clarify the relationship and improve sentence structure.", suggestedFix: "The user executed PowerShell, after which a network connection was observed." });
  const missing = evidence.filter(item => item.value === null); if (missing.length) results.push({ type: "missing_artifact", severity: "warning", message: `${missing.length} required artifacts remain unresolved: ${missing.map(item => item.label).join(", ")}.`, source: "Incident template" });
  return results;
}
