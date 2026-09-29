import { db } from "@/lib/db";

export async function getOperationalMetrics() {
  const [incidents, investigations, evidence, auditEvents] = await Promise.all([
    db.incident.count(),
    db.investigation.count(),
    db.evidence.count(),
    db.auditEvent.count(),
  ]);
  return { incidents, investigations, evidence, auditEvents, process: { node: process.version, environment: process.env.NODE_ENV ?? "development" }, generatedAt: new Date().toISOString() };
}
