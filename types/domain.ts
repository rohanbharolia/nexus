export type ToolCategory = "SIEM" | "EDR" | "IDENTITY" | "NETWORK" | "THREAT_INTEL" | "CLOUD" | "TICKETING";
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type IncidentStatus = "TRIAGE" | "INVESTIGATING" | "AWAITING_REVIEW" | "RESOLVED";
export type Confidence = "low" | "medium" | "high";

export interface ClientEnvironment {
  id: string;
  name: string;
  tools: ToolDefinition[];
  availableTools: string[];
}

export interface ToolDefinition { id: string; name: string; category: ToolCategory; enabled: boolean; adapter: string; }
export interface Incident { id: string; rule: string; name: string; severity: Severity; status: IncidentStatus; host: string; user: string; sourceIp: string; destinationIp: string; detectedAt: string; }
export interface ArtifactDefinition { key: string; label: string; required: boolean; recommendedSources: string[]; }
export interface InvestigationStep { index: number; title: string; purpose: string; recommendedTools: string[]; requiredArtifacts: string[]; complete: boolean; }
export interface IncidentTemplate { id: string; name: string; description: string; severities: Severity[]; requiredArtifacts: ArtifactDefinition[]; investigationSteps: InvestigationStep[]; recommendedLogSources: string[]; queryTemplates: QueryTemplate[]; analysisTemplate: string; }
export interface Evidence { key: string; label: string; value: string | null; sourceTool: string | null; sourceEventId: string | null; collectedAt: string | null; confidence: Confidence | null; rawReference: string | null; }
export interface QueryTemplate { id: string; platform: string; purpose: string; template: string; expectedEvidence: string[]; confidence: Confidence; }
export interface GeneratedQuery extends QueryTemplate { incidentId: string; indicator: string; timeRange: string; query: string; executedAt?: string; resultCount?: number; }
export interface TimelineEvent { id: string; timestamp: string; source: string; host: string; user: string; eventType: string; description: string; severity: "normal" | "warning" | "high"; }
export type ValidationType = "grammar" | "evidence_mismatch" | "missing_artifact" | "unsupported_claim" | "terminology";
export interface ValidationResult { type: ValidationType; severity: "info" | "warning" | "critical"; message: string; source?: string; suggestedFix?: string; }
export interface NextBestAction { action: string; reason: string; tools: string[]; requiredArtifacts: string[]; }
export interface AnalysisDraft { summary: string; technicalFindings: string; scope: string; recommendedActions: string; }
