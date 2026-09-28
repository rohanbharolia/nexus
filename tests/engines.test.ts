import { describe, expect, it } from "vitest";
import { generateDeterministicQuery } from "@/lib/queries/engine";
import { validateAnalysis } from "@/lib/validation/analysis";
import { calculateBusinessImpact, buildInvestigationGraph, findSimilarInvestigations } from "@/lib/analytics";

describe("Nexus deterministic engines", () => {
  it("generates a parameterized Splunk query", () => {
    const result = generateDeterministicQuery({ incidentId: "INC-1042", platform: "Splunk", indicator: "185.199.110.153", timeRange: "24 hours", host: "WIN-PC-1042" });
    expect(result.query).toContain("185.199.110.153");
    expect(result.query).toContain("earliest=-24h");
  });
  it("detects an evidence mismatch without rewriting text", () => {
    const issues = validateAnalysis("The user ran code on WIN-PC-1047 and connected to malicious IP.", [{ key: "hostname", label: "Hostname", value: "WIN-PC-1042", sourceTool: "CrowdStrike Falcon", sourceEventId: "event", collectedAt: null, confidence: "high", rawReference: "event" }]);
    expect(issues.some(issue => issue.type === "evidence_mismatch")).toBe(true);
    expect(issues.some(issue => issue.type === "unsupported_claim")).toBe(true);
  });
  it("labels inferred graph relationships as unconfirmed", () => {
    const graph = buildInvestigationGraph({ host: "WIN-PC-1042", user: "john.smith", sourceIp: "10.10.4.21", destinationIp: "185.199.110.153", process: "powershell.exe" });
    expect(graph.edges.find(edge => edge.relationship.includes("potentially"))?.confirmed).toBe(false);
  });
  it("returns explainable business impact and similarity data", () => {
    expect(calculateBusinessImpact({ assetCriticality: "critical", dataClasses: ["PCI"], confirmedExposure: false }).label).toBe("Potential impact");
    expect(findSimilarInvestigations({ title: "Suspicious PowerShell" })[0].similarity).toBe(87);
  });
});
