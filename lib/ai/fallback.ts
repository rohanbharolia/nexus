import type { AIProvider } from "./types";
import { getNextBestAction } from "@/lib/investigation/next-action";
import { validateAnalysis } from "@/lib/validation/analysis";
import type { Evidence, Incident } from "@/types/domain";

export class DeterministicAIProvider implements AIProvider {
  name = "deterministic-fallback";

  async generateInvestigationPlan(input: { incident: Incident; tools: string[] }) {
    return {
      incidentId: input.incident.id,
      tools: input.tools,
      rationale: "Template-driven plan generated from incident type and configured tool sources.",
      humanReviewRequired: true,
    };
  }

  async generateNextBestAction(input: {
    incident: Incident;
    completedSteps: string[];
    missingArtifacts: string[];
    availableTools: string[];
    incidentKind?: string;
  }) {
    return getNextBestAction(
      input.incident,
      input.availableTools,
      input.missingArtifacts,
      input.completedSteps,
    );
  }

  async generateAnalysis(input: { incident: Incident; evidence: unknown; timeline: unknown }) {
    return {
      summary: `Activity observed on ${input.incident.host} associated with rule ${input.incident.rule}. Investigation is in progress.`,
      technicalFindings: "Findings are limited to supplied telemetry and remain subject to analyst review.",
      scope: "Scope requires additional endpoint and identity pivots to confirm.",
      recommendedActions: "Corroborate the destination, preserve endpoint evidence, and review related identity activity.",
    };
  }

  async validateAnalysis(input: { text: string; evidence: unknown }) {
    return validateAnalysis(input.text, input.evidence as Evidence[]);
  }

  async generateExecutiveSummary(input: { evidence: unknown; timeline: unknown }) {
    const evCount = Array.isArray(input.evidence) ? input.evidence.length : 0;
    const tlCount = Array.isArray(input.timeline) ? input.timeline.length : 0;
    return `${tlCount} correlated timeline events and ${evCount} evidence records are available for review. No confirmed conclusions have been established. Analyst review is required before any response action.`;
  }
}
