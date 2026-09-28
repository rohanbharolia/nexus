import { INVESTIGATION_SYSTEM_PROMPT } from "./system";
export { INVESTIGATION_SYSTEM_PROMPT };
export const investigationPlanPrompt = (incident: unknown, tools: string[]) => `${INVESTIGATION_SYSTEM_PROMPT}\n\nCreate a structured investigation plan for this incident using only these tools: ${tools.join(", ")}.\nIncident:\n${JSON.stringify(incident)}`;
export const queryGenerationPrompt = (input: unknown) => `${INVESTIGATION_SYSTEM_PROMPT}\n\nFill a validated platform query template. Do not invent a query syntax. Input:\n${JSON.stringify(input)}`;
export const analysisValidationPrompt = (analysis: string, evidence: unknown) => `${INVESTIGATION_SYSTEM_PROMPT}\n\nValidate this analyst text against evidence. Return issues only; preserve the original text.\nAnalysis:\n${analysis}\nEvidence:\n${JSON.stringify(evidence)}`;
export const executiveSummaryPrompt = (evidence: unknown, timeline: unknown) => `${INVESTIGATION_SYSTEM_PROMPT}\n\nGenerate a concise executive summary from observed evidence only. Label hypotheses and recommendations.\nEvidence:\n${JSON.stringify(evidence)}\nTimeline:\n${JSON.stringify(timeline)}`;
