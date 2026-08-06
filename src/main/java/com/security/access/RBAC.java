package com.security.access;

import com.security.audit.AuditLogger;

/**
 * RBAC — Role-Based Access Control
 *
 * USAGE:
 *   // Check permission
 *   boolean allowed = RBAC.hasPermission("STAFF", Permission.VIEW_AUDIT_LOGS);
 *
 *   // Enforce (throws SecurityException if denied)
 *   RBAC.enforce("GUEST", Permission.MANAGE_ROOMS); // throws!
 *
 * PERMISSION MATRIX:
 * ┌─────────────────────┬───────┬───────┬───────┐
 * │ Permission          │ GUEST │ STAFF │ ADMIN │
 * ├─────────────────────┼───────┼───────┼───────┤
 * │ VIEW_OWN_DATA       │  ✓    │  ✓    │  ✓    │
 * │ CREATE_BOOKING      │  ✗    │  ✓    │  ✓    │
 * │ MANAGE_RECORDS      │  ✗    │  ✓    │  ✓    │
 * │ VIEW_REPORTS        │  ✗    │  ✗    │  ✓    │
 * │ VIEW_AUDIT_LOGS     │  ✗    │  ✗    │  ✓    │
 * │ MANAGE_USERS        │  ✗    │  ✗    │  ✓    │
 * │ SYSTEM_CONFIG       │  ✗    │  ✗    │  ✓    │
 * └─────────────────────┴───────┴───────┴───────┘
 */
public class RBAC {

    public enum Permission {
        VIEW_OWN_DATA,
        CREATE_BOOKING,
        MANAGE_RECORDS,
        VIEW_REPORTS,
        VIEW_AUDIT_LOGS,
        MANAGE_USERS,
        SYSTEM_CONFIG
    }

    /**
     * Check if a role has a specific permission.
     * @param role  "ADMIN", "STAFF", or "GUEST"
     */
    public static boolean hasPermission(String role, Permission permission) {
        if (role == null) return false;
        switch (role.toUpperCase()) {
            case "ADMIN":
                return true; // Admin has all permissions

            case "STAFF":
                return permission == Permission.VIEW_OWN_DATA
                    || permission == Permission.CREATE_BOOKING
                    || permission == Permission.MANAGE_RECORDS;

            case "GUEST":
                return permission == Permission.VIEW_OWN_DATA;

            default:
                return false;
        }
    }

    /**
     * Enforce a permission — throws SecurityException if denied.
     * Use this as a guard at the start of sensitive methods.
     *
     * Example:
     *   RBAC.enforce(currentUserRole, Permission.VIEW_AUDIT_LOGS);
     *   // Code here only runs if user is ADMIN
     */
    public static void enforce(String role, Permission permission) {
        enforce(role, permission, "unknown");
    }

    public static void enforce(String role, Permission permission, String identifier) {
        if (!hasPermission(role, permission)) {
            String msg = "ACCESS DENIED: Role [" + role + "] attempted: " + permission.name();
            AuditLogger.log("ACCESS_DENIED", identifier, msg);
            throw new SecurityException(msg);
        }
    }
}
