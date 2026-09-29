// ─── Types ────────────────────────────────────────────────────────────────────

export type Role = "ANALYST" | "SENIOR_ANALYST" | "MANAGER" | "ADMIN";

export type Permission =
  | "investigation:read"
  | "investigation:write"
  | "evidence:collect"
  | "report:write"
  | "report:approve"        // SENIOR_ANALYST + MANAGER + ADMIN only
  | "analysis:write"
  | "analysis:ai"           // can trigger AI draft generation
  | "query:generate"
  | "response:request"
  | "environment:admin"     // ADMIN only
  | "audit:read";

// ─── Role → Permission matrix ─────────────────────────────────────────────────

export const rolePermissions: Record<Role, Permission[]> = {
  ANALYST: [
    "investigation:read",
    "investigation:write",
    "evidence:collect",
    "report:write",
    "analysis:write",
    "analysis:ai",
    "query:generate",
    "response:request",
  ],
  SENIOR_ANALYST: [
    "investigation:read",
    "investigation:write",
    "evidence:collect",
    "report:write",
    "report:approve",
    "analysis:write",
    "analysis:ai",
    "query:generate",
    "response:request",
    "audit:read",
  ],
  MANAGER: [
    "investigation:read",
    "report:write",
    "report:approve",
    "analysis:write",
    "response:request",
    "audit:read",
  ],
  ADMIN: [
    "investigation:read",
    "investigation:write",
    "evidence:collect",
    "report:write",
    "report:approve",
    "analysis:write",
    "analysis:ai",
    "query:generate",
    "response:request",
    "environment:admin",
    "audit:read",
  ],
};

// ─── Permission helpers ───────────────────────────────────────────────────────

export function can(role: Role, permission: Permission): boolean {
  return rolePermissions[role]?.includes(permission) ?? false;
}

export function assertPermission(role: Role, permission: Permission): void {
  if (!can(role, permission)) {
    throw new RBACError(role, permission);
  }
}

export function tenantScope(userClientId: string, requestedClientId: string): string {
  if (userClientId !== requestedClientId) {
    throw new Error("Tenant boundary violation: cross-client access denied.");
  }
  return requestedClientId;
}

export class RBACError extends Error {
  readonly role: Role;
  readonly permission: Permission;
  constructor(role: Role, permission: Permission) {
    super(`Role "${role}" is not permitted to perform "${permission}".`);
    this.name = "RBACError";
    this.role = role;
    this.permission = permission;
  }
}

// ─── Session ──────────────────────────────────────────────────────────────────

export interface SessionContext {
  userId: string;
  name: string;
  role: Role;
  clientId: string;
  authenticated: boolean;
  mode: "demo" | "oidc";
  permissions: Permission[];
}

/** Demo personas — available in the UI switcher */
export const DEMO_USERS: SessionContext[] = [
  {
    userId:        "demo-analyst",
    name:          "Alex Morgan",
    role:          "ANALYST",
    clientId:      "client-acme",
    authenticated: true,
    mode:          "demo",
    permissions:   rolePermissions.ANALYST,
  },
  {
    userId:        "demo-senior",
    name:          "Jamie Chen",
    role:          "SENIOR_ANALYST",
    clientId:      "client-acme",
    authenticated: true,
    mode:          "demo",
    permissions:   rolePermissions.SENIOR_ANALYST,
  },
  {
    userId:        "demo-manager",
    name:          "Sam Rivera",
    role:          "MANAGER",
    clientId:      "client-acme",
    authenticated: true,
    mode:          "demo",
    permissions:   rolePermissions.MANAGER,
  },
  {
    userId:        "demo-admin",
    name:          "Dana Kim",
    role:          "ADMIN",
    clientId:      "client-acme",
    authenticated: true,
    mode:          "demo",
    permissions:   rolePermissions.ADMIN,
  },
];

const DEMO_USER_MAP = new Map(DEMO_USERS.map(u => [u.userId, u]));

/** Read session from request headers (set by UI or OIDC middleware) */
export function getSessionFromHeaders(headers: Headers): SessionContext {
  const userId   = headers.get("x-nexus-user") ?? "";
  const roleRaw  = (headers.get("x-nexus-role") ?? "") as Role;
  const clientId = headers.get("x-nexus-client") ?? "client-acme";

  // Named demo user
  if (userId && DEMO_USER_MAP.has(userId)) {
    return DEMO_USER_MAP.get(userId)!;
  }

  // Custom header-supplied role (e.g. from an OIDC proxy)
  if (userId && rolePermissions[roleRaw]) {
    return {
      userId,
      name: userId,
      role: roleRaw,
      clientId,
      authenticated: true,
      mode: "oidc",
      permissions: rolePermissions[roleRaw],
    };
  }

  // Unauthenticated fallback — read-only analyst
  return DEMO_USERS[0];
}
