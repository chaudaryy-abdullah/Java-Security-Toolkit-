package com.security.auth;

import com.security.audit.AuditLogger;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * SessionManager — UUID-based Session Token Management
 *
 * USAGE:
 *   String token = SessionManager.createSession("user@email.com", "ADMIN");
 *   boolean valid = SessionManager.isValid(token);
 *   String role   = SessionManager.getRole(token);
 *   SessionManager.invalidate(token); // logout
 */
public class SessionManager {

    private static final int SESSION_TIMEOUT_MINUTES = 30;
    private static final Map<String, Session> sessions = new HashMap<>();

    /** Create a new session. Returns the token. */
    public static String createSession(String identifier, String role) {
        // Invalidate any existing session for this user
        sessions.entrySet().removeIf(e -> e.getValue().identifier.equals(identifier));

        String token = UUID.randomUUID().toString();
        sessions.put(token, new Session(identifier, role, LocalDateTime.now()));
        AuditLogger.log("SESSION_CREATED", identifier, "Role: " + role
            + " | Token: " + token.substring(0, 8) + "...");
        return token;
    }

    /** Returns true if the token exists and has not expired. */
    public static boolean isValid(String token) {
        if (token == null) return false;
        Session s = sessions.get(token);
        if (s == null) return false;
        if (LocalDateTime.now().isAfter(s.createdAt.plusMinutes(SESSION_TIMEOUT_MINUTES))) {
            sessions.remove(token);
            AuditLogger.log("SESSION_EXPIRED", s.identifier, "Token expired.");
            return false;
        }
        s.lastActivity = LocalDateTime.now();
        return true;
    }

    /** Get the identifier (e.g. username/email) from a token. */
    public static String getIdentifier(String token) {
        Session s = sessions.get(token);
        return (s != null && isValid(token)) ? s.identifier : null;
    }

    /** Get the role from a token. */
    public static String getRole(String token) {
        Session s = sessions.get(token);
        return (s != null && isValid(token)) ? s.role : null;
    }

    /** Invalidate (logout) a session. */
    public static void invalidate(String token) {
        Session s = sessions.remove(token);
        if (s != null) AuditLogger.log("SESSION_ENDED", s.identifier, "Logged out.");
    }

    private static class Session {
        String identifier, role;
        LocalDateTime createdAt, lastActivity;

        Session(String identifier, String role, LocalDateTime createdAt) {
            this.identifier   = identifier;
            this.role         = role;
            this.createdAt    = createdAt;
            this.lastActivity = createdAt;
        }
    }
}
