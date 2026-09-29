import { z } from "zod";
import type { AIProvider } from "./types";
import type { AnalysisDraft, Incident, NextBestAction, ValidationResult } from "@/types/domain";

const providerEnvelope = z.object({ output: z.unknown() });
export class ConfiguredHTTPAIProvider implements AIProvider {
  constructor(public name: string, private endpoint: string, private apiKey: string, private model: string) {}
  private async call<T>(input: unknown, schema: z.ZodType<T>): Promise<T> { const response = await fetch(this.endpoint, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.apiKey}` }, body: JSON.stringify({ model: this.model, input }) }); if (!response.ok) throw new Error(`${this.name} returned HTTP ${response.status}`); const parsed = providerEnvelope.safeParse(await response.json()); if (!parsed.success) throw new Error(`${this.name} returned an invalid envelope`); return schema.parse(parsed.data.output); }
  async generateInvestigationPlan(input: { incident: Incident; tools: string[] }) { return this.call(input, z.object({ incidentId: z.string(), tools: z.array(z.string()), rationale: z.string(), humanReviewRequired: z.boolean() })); }
  async generateNextBestAction(input: { incident: Incident; completedSteps: string[]; missingArtifacts: string[]; availableTools: string[] }) { return this.call(input, z.object({ action: z.string(), reason: z.string(), tools: z.array(z.string()), requiredArtifacts: z.array(z.string()) })); }
  async generateAnalysis(input: { incident: Incident; evidence: unknown; timeline: unknown }): Promise<AnalysisDraft> { return this.call(input, z.object({ summary: z.string(), technicalFindings: z.string(), scope: z.string(), recommendedActions: z.string() })); }
  async validateAnalysis(input: { text: string; evidence: unknown }): Promise<ValidationResult[]> { return this.call(input, z.array(z.object({ type: z.enum(["grammar", "evidence_mismatch", "missing_artifact", "unsupported_claim", "terminology"]), severity: z.enum(["info", "warning", "critical"]), message: z.string(), source: z.string().optional(), suggestedFix: z.string().optional() }))); }
  async generateExecutiveSummary(input: { evidence: unknown; timeline: unknown }) { return this.call(input, z.string()); }
}
