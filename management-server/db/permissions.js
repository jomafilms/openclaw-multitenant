// Permission levels for resource shares
// - read: View resource data (GET requests)
// - list: List items in resource (GET collection endpoints)
// - write: Create/update data (POST, PUT, PATCH requests)
// - delete: Delete data (DELETE requests)
// - admin: Manage the resource itself
// - share: Can share resource with others

export const PERMISSION_LEVELS = ["read", "list", "write", "delete", "admin", "share"];

// Default permission set (read-only)
export const DEFAULT_PERMISSIONS = {
  read: true,
  list: false,
  write: false,
  delete: false,
  admin: false,
  share: false,
};

// Full permission set (all permissions)
export const FULL_PERMISSIONS = {
  read: true,
  list: true,
  write: true,
  delete: true,
  admin: true,
  share: true,
};

// Helper to normalize permissions input (supports both array and object formats)
export function normalizePermissions(permissions) {
  if (!permissions) {
    return DEFAULT_PERMISSIONS;
  }

  // If it's already an object (JSONB format), validate and return
  if (typeof permissions === "object" && !Array.isArray(permissions)) {
    const normalized = { ...DEFAULT_PERMISSIONS };
    for (const key of PERMISSION_LEVELS) {
      if (key in permissions) {
        normalized[key] = Boolean(permissions[key]);
      }
    }
    return normalized;
  }

  // If it's an array (legacy format), convert to object
  if (Array.isArray(permissions)) {
    const normalized = { ...DEFAULT_PERMISSIONS };
    for (const perm of permissions) {
      if (PERMISSION_LEVELS.includes(perm)) {
        normalized[perm] = true;
      }
    }
    return normalized;
  }

  return DEFAULT_PERMISSIONS;
}

// Check if a grant/share has a specific permission
export function hasPermission(grantOrShare, permission) {
  if (!grantOrShare || !grantOrShare.permissions) return false;
  const perms =
    typeof grantOrShare.permissions === "string"
      ? JSON.parse(grantOrShare.permissions)
      : grantOrShare.permissions;
  return Boolean(perms[permission]);
}

// Check multiple permissions at once (returns true if ANY are granted)
export function hasAnyPermission(grantOrShare, permissionList) {
  if (!grantOrShare || !grantOrShare.permissions) return false;
  const perms =
    typeof grantOrShare.permissions === "string"
      ? JSON.parse(grantOrShare.permissions)
      : grantOrShare.permissions;
  return permissionList.some((p) => Boolean(perms[p]));
}

// Check multiple permissions at once (returns true if ALL are granted)
export function hasAllPermissions(grantOrShare, permissionList) {
  if (!grantOrShare || !grantOrShare.permissions) return false;
  const perms =
    typeof grantOrShare.permissions === "string"
      ? JSON.parse(grantOrShare.permissions)
      : grantOrShare.permissions;
  return permissionList.every((p) => Boolean(perms[p]));
}

// Get required permission for an HTTP method
export function getRequiredPermissionForMethod(method) {
  const methodUpper = (method || "GET").toUpperCase();
  switch (methodUpper) {
    case "GET":
      return "read";
    case "POST":
    case "PUT":
    case "PATCH":
      return "write";
    case "DELETE":
      return "delete";
    default:
      return "read";
  }
}
