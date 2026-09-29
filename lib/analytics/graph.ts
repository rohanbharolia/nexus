export interface GraphNode { id: string; label: string; type: "user" | "host" | "ip" | "process" | "application" | "data"; risk?: number; }
export interface GraphEdge { from: string; to: string; relationship: string; source: string; confirmed: boolean; }
export function buildInvestigationGraph(input: { host: string; user: string; sourceIp: string; destinationIp: string; process: string }) {
  const nodes: GraphNode[] = [{ id: input.user, label: input.user, type: "user" }, { id: input.host, label: input.host, type: "host", risk: 82 }, { id: input.process, label: input.process, type: "process", risk: 61 }, { id: input.destinationIp, label: input.destinationIp, type: "ip", risk: 61 }, { id: input.sourceIp, label: input.sourceIp, type: "ip" }];
  const edges: GraphEdge[] = [{ from: input.user, to: input.host, relationship: "authenticated to", source: "Microsoft Entra ID", confirmed: true }, { from: input.host, to: input.process, relationship: "executed", source: "CrowdStrike Falcon", confirmed: true }, { from: input.process, to: input.destinationIp, relationship: "potentially connected to", source: "Palo Alto", confirmed: false }, { from: input.sourceIp, to: input.host, relationship: "source for", source: "Splunk", confirmed: true }];
  return { nodes, edges, label: "Observed relationships with potential links clearly marked" };
}
export function calculateBlastRadius() { return { users: 3, endpoints: 2, serviceAccounts: 1, applications: 4, cloudResources: 2, databases: 1, confidence: 58, caveat: "Potentially related assets require validation." }; }
