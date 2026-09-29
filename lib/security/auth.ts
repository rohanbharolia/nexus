export type Role = "ANALYST" | "SENIOR_ANALYST" | "MANAGER" | "ADMIN";
export type Permission = "investigation:read" | "investigation:write" | "evidence:collect" | "report:write" | "response:request" | "environment:admin" | "audit:read";
const rolePermissions: Record<Role, Permission[]> = {
  ANALYST: ["investigation:read", "investigation:write", "evidence:collect", "report:write", "response:request"],
  SENIOR_ANALYST: ["investigation:read", "investigation:write", "evidence:collect", "report:write", "response:request", "audit:read"],
  MANAGER: ["investigation:read", "report:write", "response:request", "audit:read"],
  ADMIN: ["investigation:read", "investigation:write", "evidence:collect", "report:write", "response:request", "environment:admin", "audit:read"],
};
export function can(role: Role, permission: Permission) { return rolePermissions[role].includes(permission); }
export function assertPermission(role: Role, permission: Permission) { if (!can(role, permission)) throw new Error(`Role ${role} is not permitted to perform ${permission}.`); }
export function tenantScope(userClientId: string, requestedClientId: string) { if (userClientId !== requestedClientId) throw new Error("Tenant boundary violation."); return requestedClientId; }

export interface SessionContext { userId: string; name: string; role: Role; clientId: string; authenticated: boolean; mode: "demo" | "oidc"; }
export function getSessionFromHeaders(headers: Headers): SessionContext {
  const userId = headers.get("x-nexus-user");
  const role = (headers.get("x-nexus-role") ?? "ANALYST") as Role;
  const clientId = headers.get("x-nexus-client") ?? "client-acme";
  if (userId && rolePermissions[role]) return { userId, name: userId, role, clientId, authenticated: true, mode: "oidc" };
  return { userId: "demo-analyst", name: "Alex Morgan", role: "ANALYST", clientId: "client-acme", authenticated: false, mode: "demo" };
}
