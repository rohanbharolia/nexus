/**
 * OpenAI-compatible provider.
 * Works with: OpenAI, OpenRouter, DeepSeek, Ollama (openai-compat mode),
 * Azure OpenAI, Mistral, Groq, and any endpoint that speaks the
 * OpenAI chat-completions API.
 *
 * Set in .env:
 *   AI_PROVIDER=openai
 *   AI_API_KEY=sk-...
 *   AI_MODEL=gpt-4o                   (or gpt-4-turbo, gpt-3.5-turbo, etc.)
 *   AI_ENDPOINT=https://api.openai.com/v1   (optional – override for OpenRouter etc.)
 */

import { z } from "zod";
import type { AIProvider } from "./types";
import type { AnalysisDraft, Incident, NextBestAction, ValidationResult } from "@/types/domain";
import {
  INVESTIGATION_SYSTEM_PROMPT,
  investigationPlanPrompt,
  analysisValidationPrompt,
  executiveSummaryPrompt,
} from "@/prompts";

// ─── Types ───────────────────────────────────────────────────────────────────

interface Message { role: "system" | "user" | "assistant"; content: string }

interface ChatCompletionRequest {
  model: string;
  messages: Message[];
  temperature?: number;
  max_tokens?: number;
  response_format?: { type: "json_object" };
}

interface ChatCompletionResponse {
  choices: Array<{ message: { content: string } }>;
}

// ─── Schemas for structured output ───────────────────────────────────────────

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

const investigationPlanSchema = z.object({
  incidentId: z.string(),
  tools: z.array(z.string()),
  rationale: z.string(),
  humanReviewRequired: z.boolean(),
});

// ─── Provider ────────────────────────────────────────────────────────────────

export class OpenAICompatibleProvider implements AIProvider {
  private baseUrl: string;

  constructor(
    public name: string,
    private apiKey: string,
    private model: string,
    endpoint?: string,
  ) {
    // Default to OpenAI; override for OpenRouter, DeepSeek, Ollama, etc.
    this.baseUrl = (endpoint ?? "https://api.openai.com/v1").replace(/\/$/, "");
  }

  // ── Core chat call ──────────────────────────────────────────────────────

  private async chat(messages: Message[], opts: { json?: boolean; maxTokens?: number } = {}): Promise<string> {
    const body: ChatCompletionRequest = {
      model: this.model,
      messages,
      temperature: 0.2,
      max_tokens: opts.maxTokens ?? 1200,
      ...(opts.json ? { response_format: { type: "json_object" } } : {}),
    };

    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
        // OpenRouter needs this header
        "HTTP-Referer": "https://nexus.demo",
        "X-Title": "Nexus SOC Platform",
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.text().catch(() => res.statusText);
      throw new Error(`${this.name} API error ${res.status}: ${err}`);
    }

    const data = await res.json() as ChatCompletionResponse;
    const content = data?.choices?.[0]?.message?.content;
    if (!content) throw new Error(`${this.name} returned empty response`);
    return content;
  }

  // ── JSON call with schema validation + fallback ─────────────────────────

  private async chatJSON<T>(messages: Message[], schema: z.ZodType<T>, fallback: T, maxTokens = 2000): Promise<T> {
    try {
      const raw = await this.chat(messages, { json: true, maxTokens });
      // Strip markdown fences if model wraps JSON in ```json ... ```
      const cleaned = raw.replace(/^```(?:json)?\n?/i, "").replace(/\n?```$/i, "").trim();

      // Try to extract valid JSON even if the string is truncated
      // by finding the last complete field using a safe truncation approach
      const toparse = [cleaned, raw].find(s => {
        try { JSON.parse(s); return true; } catch { return false; }
      });

      if (toparse) {
        const parsed = schema.safeParse(JSON.parse(toparse));
        if (parsed.success) return parsed.data;
      }

      // Last resort: try to repair a truncated JSON object by closing it
      const repaired = cleaned.replace(/,\s*$/, "").replace(/:\s*"[^"]*$/, ': "..."') + "}";
      try {
        const parsed = schema.safeParse(JSON.parse(repaired));
        if (parsed.success) return parsed.data;
      } catch { /* ignore */ }

      console.warn(`[${this.name}] Schema validation failed, using fallback`);
      return fallback;
    } catch (e) {
      console.warn(`[${this.name}] chatJSON failed:`, e);
      return fallback;
    }
  }

  // ── AIProvider implementation ───────────────────────────────────────────

  async generateInvestigationPlan(input: { incident: Incident; tools: string[] }) {
    const messages: Message[] = [
      { role: "system", content: INVESTIGATION_SYSTEM_PROMPT },
      {
        role: "user",
        content: `Create a structured investigation plan for this incident using ONLY these configured tools: ${input.tools.join(", ")}.
Return JSON matching exactly: { "incidentId": string, "tools": string[], "rationale": string, "humanReviewRequired": boolean }

Incident:
${JSON.stringify(input.incident, null, 2)}`,
      },
    ];
    return this.chatJSON(messages, investigationPlanSchema, {
      incidentId: input.incident.id,
      tools: input.tools,
      rationale: "Investigation plan generation failed — using configured tools.",
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
    const messages: Message[] = [
      { role: "system", content: INVESTIGATION_SYSTEM_PROMPT },
      {
        role: "user",
        content: `You are advising a SOC analyst on what to do next.

Incident: ${input.incident.name} (${input.incident.severity} severity, rule: ${input.incident.rule})
Host: ${input.incident.host} | User: ${input.incident.user}
Source IP: ${input.incident.sourceIp} | Destination IP: ${input.incident.destinationIp}
Completed steps: ${input.completedSteps.length > 0 ? input.completedSteps.join(", ") : "None yet"}
Missing artifacts: ${input.missingArtifacts.length > 0 ? input.missingArtifacts.join(", ") : "None"}
Available tools in this client environment: ${input.availableTools.join(", ")}

Return JSON matching exactly:
{
  "action": "one clear imperative sentence describing the next step",
  "reason": "1-2 sentences explaining why this is the highest priority",
  "tools": ["only tools from the available tools list above"],
  "requiredArtifacts": ["artifact keys needed to complete this action"]
}`,
      },
    ];
    return this.chatJSON(messages, nextBestActionSchema, {
      action: "Review available evidence and determine next investigative step",
      reason: "AI recommendation unavailable; analyst judgment required.",
      tools: input.availableTools.slice(0, 2),
      requiredArtifacts: input.missingArtifacts,
    }, 600);
  }

  async generateAnalysis(input: { incident: Incident; evidence: unknown; timeline: unknown }): Promise<AnalysisDraft> {
    const messages: Message[] = [
      { role: "system", content: INVESTIGATION_SYSTEM_PROMPT },
      {
        role: "user",
        content: `You are a SOC analyst. Write a security incident analysis. Be concise. Use ONLY the evidence provided.

Incident: ${input.incident.name} | Rule: ${input.incident.rule} | Severity: ${input.incident.severity}
Host: ${input.incident.host} | User: ${input.incident.user}
Source IP: ${input.incident.sourceIp} | Destination IP: ${input.incident.destinationIp}

Evidence (collected fields only):
${JSON.stringify((input.evidence as Array<{key:string;label:string;value:string|null}>).filter(e => e.value).map(e => `${e.label}: ${e.value}`), null, 2)}

Return ONLY this JSON (no markdown, no extra text):
{"summary":"2-3 sentences what was observed","technicalFindings":"key technical details from evidence","scope":"current scope and pending pivots","recommendedActions":"top 3 analyst actions"}`,
      },
    ];
    return this.chatJSON(messages, analysisDraftSchema, {
      summary: `Activity observed on ${input.incident.host} related to ${input.incident.name}. Investigation in progress.`,
      technicalFindings: "Review collected evidence in the Evidence tab for full details.",
      scope: "Scope requires additional pivots to confirm.",
      recommendedActions: "Review evidence, run platform queries, and complete outstanding investigation steps.",
    }, 1500);
  }

  async validateAnalysis(input: { text: string; evidence: unknown }): Promise<ValidationResult[]> {
    const messages: Message[] = [
      { role: "system", content: INVESTIGATION_SYSTEM_PROMPT },
      {
        role: "user",
        content: `${analysisValidationPrompt(input.text, input.evidence)}

Return a JSON array of issues found. Each item must match:
{
  "type": "grammar" | "evidence_mismatch" | "missing_artifact" | "unsupported_claim" | "terminology",
  "severity": "info" | "warning" | "critical",
  "message": "description of the issue",
  "source": "evidence source if applicable (optional)",
  "suggestedFix": "corrected text (optional)"
}

If no issues are found return an empty array [].
DO NOT modify the original analyst text. Only report issues.`,
      },
    ];
    return this.chatJSON(messages, validationResultSchema, []);
  }

  async generateExecutiveSummary(input: { evidence: unknown; timeline: unknown }): Promise<string> {
    const messages: Message[] = [
      { role: "system", content: INVESTIGATION_SYSTEM_PROMPT },
      {
        role: "user",
        content: `${executiveSummaryPrompt(input.evidence, input.timeline)}

Write a concise executive summary (3-5 sentences) for a non-technical audience.
Return plain text, not JSON.`,
      },
    ];
    try {
      return await this.chat(messages, { maxTokens: 300 });
    } catch {
      return "Executive summary generation failed. Please review evidence and timeline manually.";
    }
  }
}
