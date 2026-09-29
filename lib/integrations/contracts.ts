import type { SearchInput, SearchResult, HostResult, UserResult, NetworkResult } from "@/lib/adapters/types";

export interface OAuthConfig { clientId: string; clientSecret: string; tokenUrl: string; scopes: string[]; }
export interface IntegrationConfig { provider: string; baseUrl: string; oauth?: OAuthConfig; enabled: boolean; }
export interface LiveSecurityIntegration {
  name: string;
  configure(config: IntegrationConfig): void;
  search(input: SearchInput): Promise<SearchResult>;
  getHost(hostname: string): Promise<HostResult>;
  getUser(username: string): Promise<UserResult>;
  getNetworkActivity(input: { sourceIp?: string; destinationIp?: string }): Promise<NetworkResult>;
}

export class ConfigurationRequiredError extends Error { constructor(provider: string) { super(`${provider} integration requires server-side credentials and OAuth configuration before it can run.`); this.name = "ConfigurationRequiredError"; } }
export class IntegrationHTTPClient {
  constructor(private provider: string, private baseUrl: string, private accessToken: string, private timeoutMs = 12000) {}
  async request<T>(path: string, init: RequestInit = {}, schema?: import("zod").ZodType<T>): Promise<T> {
    const url = new URL(path, this.baseUrl);
    const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(url, { ...init, signal: controller.signal, headers: { Authorization: `Bearer ${this.accessToken}`, Accept: "application/json", ...init.headers } });
      if (!response.ok) throw new Error(`${this.provider} request failed with HTTP ${response.status}`);
      const payload: unknown = await response.json();
      return schema ? schema.parse(payload) : payload as T;
    } finally { clearTimeout(timeout); }
  }
}
export class NotConfiguredIntegration implements LiveSecurityIntegration {
  private config?: IntegrationConfig;
  constructor(public name: string) {}
  configure(config: IntegrationConfig) { this.config = config; }
  private fail(): never { throw new ConfigurationRequiredError(this.name); }
  async search(): Promise<SearchResult> { return this.fail(); }
  async getHost(): Promise<HostResult> { return this.fail(); }
  async getUser(): Promise<UserResult> { return this.fail(); }
  async getNetworkActivity(): Promise<NetworkResult> { return this.fail(); }
  get configured() { return Boolean(this.config?.enabled && this.config.oauth?.clientId && this.config.oauth.clientSecret); }
  get status() { return this.config?.enabled ? this.config.oauth?.clientId && this.config.oauth.clientSecret ? "credentials-present-transport-not-implemented" : "credentials-required" : "disabled"; }
}

export const liveIntegrations = ["Splunk", "CrowdStrike Falcon", "Google SecOps", "Microsoft Entra ID", "Palo Alto", "Google Threat Intelligence", "ServiceNow"].map(name => new NotConfiguredIntegration(name));
