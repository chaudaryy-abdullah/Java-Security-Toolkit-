package com.security.auth;

import com.security.audit.AuditLogger;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * LoginLockout — Brute Force Protection
 *
 * USAGE:
 *   // Check BEFORE verifying password
 *   if (LoginLockout.isLocked("user@email.com")) {
 *       throw new SecurityException("Account locked. Try again in "
 *           + LoginLockout.minutesRemaining("user@email.com") + " minutes.");
 *   }
 *   // After failed login:
 *   LoginLockout.recordFailure("user@email.com");
 *   // After successful login:
 *   LoginLockout.reset("user@email.com");
 */
public class LoginLockout {

    public static final int  MAX_ATTEMPTS    = 5;
    public static final int  LOCKOUT_MINUTES = 15;

    private static final Map<String, FailRecord> records = new HashMap<>();

    /** Call this after a FAILED login attempt. */
    public static void recordFailure(String identifier) {
        FailRecord r = records.getOrDefault(identifier, new FailRecord());
        r.count++;
        r.lastAttempt = LocalDateTime.now();
        if (r.count >= MAX_ATTEMPTS) {
            r.lockedUntil = LocalDateTime.now().plusMinutes(LOCKOUT_MINUTES);
            AuditLogger.log("LOCKOUT", identifier,
                "Account locked after " + r.count + " failed attempts.");
        } else {
            AuditLogger.log("FAILED_LOGIN", identifier,
                "Failed attempt #" + r.count + " of " + MAX_ATTEMPTS);
        }
        records.put(identifier, r);
    }

    /** Call this after a SUCCESSFUL login. Clears the failure counter. */
    public static void reset(String identifier) {
        records.remove(identifier);
    }

    /** Returns true if the account is currently locked. Call this BEFORE password check. */
    public static boolean isLocked(String identifier) {
        FailRecord r = records.get(identifier);
        if (r == null || r.lockedUntil == null) return false;
        if (LocalDateTime.now().isAfter(r.lockedUntil)) {
            records.remove(identifier); // Lockout expired
            return false;
        }
        return true;
    }

    /** Returns how many minutes remain in the lockout (0 if not locked). */
    public static long minutesRemaining(String identifier) {
        FailRecord r = records.get(identifier);
        if (r == null || r.lockedUntil == null) return 0;
        return java.time.temporal.ChronoUnit.MINUTES.between(
            LocalDateTime.now(), r.lockedUntil);
    }

    public static int failureCount(String identifier) {
        FailRecord r = records.get(identifier);
        return r == null ? 0 : r.count;
    }

    private static class FailRecord {
        int count = 0;
        LocalDateTime lastAttempt;
        LocalDateTime lockedUntil;
    }
}
