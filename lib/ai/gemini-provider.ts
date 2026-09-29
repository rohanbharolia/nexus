/**
 * Google Gemini provider using the Generative Language REST API.
 *
 * Set in .env:
 *   AI_PROVIDER=gemini
 *   AI_API_KEY=AIza...          (Google AI Studio key)
 *   AI_MODEL=gemini-1.5-flash   (or gemini-1.5-pro, gemini-2.0-flash-exp)
 */

import { z } from "zod";
import type { AIProvider } from "./types";
import type { AnalysisDraft, Incident, NextBestAction, ValidationResult } from "@/types/domain";
import {
  INVESTIGATION_SYSTEM_PROMPT,
  analysisValidationPrompt,
  executiveSummaryPrompt,
} from "@/prompts";

// ─── Schemas ─────────────────────────────────────────────────────────────────

const nextBestActionSchema = z.object({
  action: z.string(),
  reason: z.string(),
  tools: z.array(z.string()),
  requiredArtifacts: z.array(z.string()),
});

const analysisDraftSchema = z.object({
  summary: z.string(),
  technicalFindings: z.string(),
  scope: z.string(),
  recommendedActions: z.string(),
});

const validationResultSchema = z.array(z.object({
  type: z.enum(["grammar", "evidence_mismatch", "missing_artifact", "unsupported_claim", "terminology"]),
  severity: z.enum(["info", "warning", "critical"]),
  message: z.string(),
  source: z.string().optional(),
  suggestedFix: z.string().optional(),
}));

// ─── Gemini REST types ────────────────────────────────────────────────────────

interface GeminiPart { text: string }
interface GeminiContent { role: "user" | "model"; parts: GeminiPart[] }
interface GeminiRequest {
  system_instruction?: { parts: GeminiPart[] };
  contents: GeminiContent[];
  generationConfig?: {
    temperature?: number;
    maxOutputTokens?: number;
    responseMimeType?: string;
  };
}
interface GeminiResponse {
  candidates?: Array<{ content?: { parts?: GeminiPart[] } }>;
}

// ─── Provider ────────────────────────────────────────────────────────────────

export class GeminiProvider implements AIProvider {
  name = "gemini";
  private baseUrl = "https://generativelanguage.googleapis.com/v1beta/models";

  constructor(private apiKey: string, private model: string) {}

  private async generate(prompt: string, opts: { json?: boolean; maxTokens?: number } = {}): Promise<string> {
    const url = `${this.baseUrl}/${this.model}:generateContent?key=${this.apiKey}`;

    const body: GeminiRequest = {
      system_instruction: { parts: [{ text: INVESTIGATION_SYSTEM_PROMPT }] },
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens: opts.maxTokens ?? 1200,
        ...(opts.json ? { responseMimeType: "application/json" } : {}),
      },
    };

    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.text().catch(() => res.statusText);
      throw new Error(`Gemini API error ${res.status}: ${err}`);
    }

    const data = await res.json() as GeminiResponse;
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text) throw new Error("Gemini returned empty response");
    return text;
  }

  private async generateJSON<T>(prompt: string, schema: z.ZodType<T>, fallback: T): Promise<T> {
    try {
      const raw = await this.generate(prompt, { json: true });
      const cleaned = raw.replace(/^```(?:json)?\n?/i, "").replace(/\n?```$/i, "").trim();
      const parsed = schema.safeParse(JSON.parse(cleaned));
      if (parsed.success) return parsed.data;
      const parsed2 = schema.safeParse(JSON.parse(raw));
      if (parsed2.success) return parsed2.data;
      console.warn("[gemini] Schema validation failed, using fallback");
      return fallback;
    } catch (e) {
      console.warn("[gemini] generateJSON failed:", e);
      return fallback;
    }
  }

  async generateInvestigationPlan(input: { incident: Incident; tools: string[] }) {
    const prompt = `Create a structured investigation plan for this incident using ONLY these configured tools: ${input.tools.join(", ")}.
Return JSON matching exactly: { "incidentId": string, "tools": string[], "rationale": string, "humanReviewRequired": boolean }

Incident:
${JSON.stringify(input.incident, null, 2)}`;

    return this.generateJSON(prompt, z.object({
      incidentId: z.string(),
      tools: z.array(z.string()),
      rationale: z.string(),
      humanReviewRequired: z.boolean(),
    }), {
      incidentId: input.incident.id,
      tools: input.tools,
      rationale: "Investigation plan generation failed.",
      humanReviewRequired: true,
    });
  }

  async generateNextBestAction(input: {
    incident: Incident;
    completedSteps: string[];
    missingArtifacts: string[];
    availableTools: string[];
    incidentKind?: string;
  }): Promise<NextBestAction> {
    const prompt = `You are advising a SOC analyst on their next investigative action.

Incident: ${input.incident.name} (${input.incident.severity} severity, rule: ${input.incident.rule})
Host: ${input.incident.host} | User: ${input.incident.user}
Source IP: ${input.incident.sourceIp} | Destination IP: ${input.incident.destinationIp}
Completed steps: ${input.completedSteps.length > 0 ? input.completedSteps.join(", ") : "None yet"}
Missing artifacts: ${input.missingArtifacts.length > 0 ? input.missingArtifacts.join(", ") : "None"}
Available tools: ${input.availableTools.join(", ")}

Return JSON:
{
  "action": "one clear imperative sentence describing the next step",
  "reason": "1-2 sentences explaining why this is the highest priority",
  "tools": ["only tools from the available tools list above"],
  "requiredArtifacts": ["artifact keys needed"]
}`;

    return this.generateJSON(prompt, nextBestActionSchema, {
      action: "Review available evidence and determine next investigative step",
      reason: "AI recommendation unavailable.",
      tools: input.availableTools.slice(0, 2),
      requiredArtifacts: input.missingArtifacts,
    });
  }

  async generateAnalysis(input: { incident: Incident; evidence: unknown; timeline: unknown }): Promise<AnalysisDraft> {
    const prompt = `You are a SOC analyst. Write a concise security incident analysis using ONLY the evidence provided.

Incident: ${input.incident.name} | Rule: ${input.incident.rule} | Severity: ${input.incident.severity}
Host: ${input.incident.host} | User: ${input.incident.user}
Source IP: ${input.incident.sourceIp} | Destination IP: ${input.incident.destinationIp}

Evidence:
${JSON.stringify((input.evidence as Array<{key:string;label:string;value:string|null}>).filter(e => e.value).map(e => `${e.label}: ${e.value}`), null, 2)}

Return ONLY this JSON (no markdown):
{"summary":"2-3 sentences","technicalFindings":"key technical details","scope":"current scope","recommendedActions":"top 3 actions"}`;

    return this.generateJSON(prompt, analysisDraftSchema, {
      summary: `Activity on ${input.incident.host} related to ${input.incident.name}.`,
      technicalFindings: "Review collected evidence for full details.",
      scope: "Scope requires additional pivots.",
      recommendedActions: "Review evidence, run queries, complete investigation steps.",
    });
  }

  async validateAnalysis(input: { text: string; evidence: unknown }): Promise<ValidationResult[]> {
    const prompt = `${analysisValidationPrompt(input.text, input.evidence)}

Return a JSON array of issues. Each item:
{
  "type": "grammar" | "evidence_mismatch" | "missing_artifact" | "unsupported_claim" | "terminology",
  "severity": "info" | "warning" | "critical",
  "message": "description",
  "source": "optional evidence source",
  "suggestedFix": "optional corrected text"
}
Return [] if no issues found. DO NOT modify original text.`;

    return this.generateJSON(prompt, validationResultSchema, []);
  }

  async generateExecutiveSummary(input: { evidence: unknown; timeline: unknown }): Promise<string> {
    const prompt = `${executiveSummaryPrompt(input.evidence, input.timeline)}
Write a concise executive summary (3-5 sentences) for a non-technical audience. Return plain text only.`;
    try {
      return await this.generate(prompt, { maxTokens: 300 });
    } catch {
      return "Executive summary generation failed. Please review evidence manually.";
    }
  }
}
