import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { GET, POST, PATCH } from "@/app/api/[...path]/route";

const context = (path: string[]) => ({ params: Promise.resolve({ path }) });
const request = (url: string, init?: { method?: string; body?: BodyInit | null; headers?: HeadersInit }) => new NextRequest(`http://localhost${url}`, init);

describe("Nexus API contracts", () => {
  it("reports capabilities and readiness", async () => {
    const capabilities = await GET(request("/api/capabilities"), context(["capabilities"]));
    expect(capabilities.status).toBe(200);
    const ready = await GET(request("/api/ready"), context(["ready"]));
    expect([200, 503]).toContain(ready.status);
  });
  it("returns the template catalog", async () => {
    const response = await GET(request("/api/templates"), context(["templates"]));
    expect(response.status).toBe(200);
    expect((await response.json()).length).toBe(8);
  });
  it("rejects malformed query generation", async () => {
    const response = await POST(request("/api/queries/generate", { method: "POST", body: JSON.stringify({ platform: "Splunk" }), headers: { "Content-Type": "application/json" } }), context(["queries", "generate"]));
    expect(response.status).toBe(400);
  });
  it("does not attempt live integration calls by default", async () => {
    const response = await POST(request("/api/integrations/test", { method: "POST", body: JSON.stringify({ provider: "Splunk", enabled: true }), headers: { "Content-Type": "application/json" } }), context(["integrations", "test"]));
    expect(response.status).toBe(200);
    expect((await response.json()).connectionAttempted).toBe(false);
  });
  it("validates a step route shape", async () => {
    const response = await PATCH(request("/api/investigations/INC-1042/steps", { method: "PATCH", body: JSON.stringify({ stepIndex: 99, complete: true }), headers: { "Content-Type": "application/json" } }), context(["investigations", "INC-1042", "steps"]));
    expect(response.status).toBe(400);
  });
});
