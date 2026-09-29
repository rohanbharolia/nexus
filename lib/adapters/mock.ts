import type { SecurityToolAdapter, SearchInput, SearchResult, HostResult, UserResult, NetworkResult } from "./types";
import type { ToolCategory } from "@/types/domain";

const events = [
  { id: "MOCK-ENTRA-0814", rawReference: "MOCK-ENTRA-0814", timestamp: "2026-09-28T14:21:03Z", source: "Microsoft Entra ID", eventType: "AUTHENTICATION", description: "Interactive sign-in from 10.10.4.21; MFA satisfied", host: "WIN-PC-1042", user: "john.smith", severity: "normal" as const },
  { id: "MOCK-FALCON-0172", rawReference: "MOCK-FALCON-0172", timestamp: "2026-09-28T14:29:44Z", source: "CrowdStrike Falcon", eventType: "PROCESS_START", description: "powershell.exe spawned by cmd.exe with encoded argument", host: "WIN-PC-1042", user: "john.smith", severity: "high" as const },
  { id: "MOCK-PA-8831", rawReference: "MOCK-PA-8831", timestamp: "2026-09-28T14:30:02Z", source: "Palo Alto", eventType: "NETWORK_CONNECTION", description: "Outbound session to 185.199.110.153 permitted", host: "WIN-PC-1042", user: "john.smith", severity: "high" as const },
];
class MockAdapter implements SecurityToolAdapter {
  constructor(public name: string, public category: ToolCategory) {}
  async search(_input: SearchInput): Promise<SearchResult> { return { adapter: this.name, events, evidence: [{ key: "hostname", label: "Hostname", value: "WIN-PC-1042", confidence: "high", sourceEventId: events[1].id }, { key: "destination_ip", label: "Destination IP", value: "185.199.110.153", confidence: "medium", sourceEventId: events[2].id }] }; }
  async getHost(hostname: string): Promise<HostResult> { return { hostname, user: "john.smith", processTree: ["explorer.exe", "cmd.exe", "powershell.exe"], sourceEventId: "MOCK-FALCON-0172" }; }
  async getUser(username: string): Promise<UserResult> { return { username, authenticationEvents: 2, mfaSatisfied: true, sourceEventId: "MOCK-ENTRA-0814" }; }
  async getNetworkActivity(input: { sourceIp?: string; destinationIp?: string }): Promise<NetworkResult> { return { sourceIp: input.sourceIp ?? "10.10.4.21", destinationIp: input.destinationIp ?? "185.199.110.153", action: "ALLOW", bytes: 18420, sourceEventId: "MOCK-PA-8831" }; }
}
export class MockSplunkAdapter extends MockAdapter { constructor() { super("Splunk", "SIEM"); } }
export class MockCrowdStrikeAdapter extends MockAdapter { constructor() { super("CrowdStrike Falcon", "EDR"); } }
export class MockGoogleSecOpsAdapter extends MockAdapter { constructor() { super("Google SecOps", "SIEM"); } }
export class MockEntraAdapter extends MockAdapter { constructor() { super("Microsoft Entra ID", "IDENTITY"); } }
export class MockPaloAltoAdapter extends MockAdapter { constructor() { super("Palo Alto", "NETWORK"); } }
export class MockThreatIntelAdapter extends MockAdapter { constructor() { super("Google Threat Intelligence", "THREAT_INTEL"); } }
export const mockAdapters = [new MockSplunkAdapter(), new MockCrowdStrikeAdapter(), new MockGoogleSecOpsAdapter(), new MockEntraAdapter(), new MockPaloAltoAdapter(), new MockThreatIntelAdapter()];
