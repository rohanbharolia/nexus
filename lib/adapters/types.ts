import type { ToolCategory } from "@/types/domain";

export interface SearchInput { query: string; indicator?: string; startTime?: string; endTime?: string; }
export interface NormalizedEvent { id: string; timestamp: string; source: string; eventType: string; description: string; host: string; user: string; severity: "normal" | "warning" | "high"; rawReference: string; }
export interface SearchResult { adapter: string; events: NormalizedEvent[]; evidence: Array<{ key: string; label: string; value: string; confidence: "low" | "medium" | "high"; sourceEventId: string; }>; }
export interface HostResult { hostname: string; user: string; processTree: string[]; sourceEventId: string; }
export interface UserResult { username: string; authenticationEvents: number; mfaSatisfied: boolean; sourceEventId: string; }
export interface NetworkResult { sourceIp: string; destinationIp: string; action: string; bytes: number; sourceEventId: string; }
export interface SecurityToolAdapter { name: string; category: ToolCategory; search(input: SearchInput): Promise<SearchResult>; getHost(hostname: string): Promise<HostResult>; getUser(username: string): Promise<UserResult>; getNetworkActivity(input: { sourceIp?: string; destinationIp?: string }): Promise<NetworkResult>; }
