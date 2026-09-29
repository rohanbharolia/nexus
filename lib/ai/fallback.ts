import type { AIProvider } from "./types";
import { getNextBestAction } from "@/lib/investigation/next-action";
import { validateAnalysis } from "@/lib/validation/analysis";
import type { Evidence, Incident, TimelineEvent } from "@/types/domain";
export class DeterministicAIProvider implements AIProvider {
  name = "deterministic-fallback";
  async generateInvestigationPlan(input: { incident: Incident; tools: string[] }) { return { incidentId: input.incident.id, tools: input.tools, rationale: "Template-driven plan generated from incident type and configured sources.", humanReviewRequired: true }; }
  async generateNextBestAction(input: { incident: Incident; completedSteps: string[]; missingArtifacts: string[]; availableTools: string[]; incidentKind?: string }) { return getNextBestAction(input.incident, input.availableTools, input.missingArtifacts, input.completedSteps); }
  async generateAnalysis(input: { incident: Incident; evidence: unknown; timeline: unknown }) { return { summary: `Observed activity on ${input.incident.host} includes PowerShell execution followed by network activity.`, technicalFindings: "Findings are limited to supplied telemetry and remain subject to analyst review.", scope: "Scope requires additional endpoint and identity pivots.", recommendedActions: "Corroborate the destination and preserve evidence before response." }; }
  async validateAnalysis(input: { text: string; evidence: unknown }) { return validateAnalysis(input.text, input.evidence as Evidence[]); }
  async generateExecutiveSummary(input: { evidence: unknown; timeline: unknown }) { return `Synthetic summary: ${Array.isArray(input.timeline) ? input.timeline.length : 0} correlated events and ${Array.isArray(input.evidence) ? input.evidence.length : 0} evidence records are available. Confirmed conclusions require analyst review.`; }
}
export const aiProvider: AIProvider = new DeterministicAIProvider();
