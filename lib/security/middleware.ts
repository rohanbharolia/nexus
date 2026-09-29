import { NextRequest, NextResponse } from "next/server";
import { getSessionFromHeaders, RBACError, type Permission, type SessionContext } from "./auth";

type JsonFn = (data: unknown, status?: number) => NextResponse;

const json: JsonFn = (data, status = 200) =>
  NextResponse.json(data, { status, headers: { "Cache-Control": "no-store" } });

/**
 * Reads the session from the request headers and checks a required permission.
 *
 * Returns `{ session }` on success.
 * Returns `{ error: NextResponse }` when the permission check fails — the
 * caller must return that response immediately.
 */
export function requirePermission(
  request: NextRequest,
  permission: Permission,
): { session: SessionContext; error?: never } | { session?: never; error: NextResponse } {
  const session = getSessionFromHeaders(request.headers);
  if (!session.permissions.includes(permission)) {
    return {
      error: json(
        {
          error: "Forbidden",
          message: `Your role "${session.role}" does not have the "${permission}" permission.`,
          requiredPermission: permission,
          userRole: session.role,
          userId: session.userId,
        },
        403,
      ),
    };
  }
  return { session };
}

/**
 * Convenience wrapper: gets session without enforcing any permission.
 * Use for read endpoints that are open to all authenticated roles.
 */
export function getSession(request: NextRequest): SessionContext {
  return getSessionFromHeaders(request.headers);
}

/** Format an RBACError as a 403 JSON response */
export function rbacErrorResponse(err: RBACError): NextResponse {
  return json(
    {
      error: "Forbidden",
      message: err.message,
      requiredPermission: err.permission,
      userRole: err.role,
    },
    403,
  );
}
