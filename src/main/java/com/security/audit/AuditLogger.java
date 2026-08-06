package com.security.audit;

import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * AuditLogger — Append-Only Security Audit Trail
 *
 * USAGE:
 *   AuditLogger.log("LOGIN",        "ahmed@hotel.com", "Successful login");
 *   AuditLogger.log("FAILED_LOGIN", "hacker@x.com",   "Wrong password attempt #3");
 *   AuditLogger.log("ACCESS_DENIED","staff@hotel.com","Attempted admin action");
 *
 *   List<String> logs = AuditLogger.readLogs();
 *   List<String> fails = AuditLogger.readByType("FAILED_LOGIN");
 *
 * WHY AUDIT LOGGING:
 *   - Legal requirement under GDPR and UAE PDPL
 *   - Forensic trail for incident response
 *   - Detect brute force, insider threats, anomalies
 *   - Non-repudiation: prove who did what and when
 */
public class AuditLogger {

    private static final String LOG_FILE = "security-audit.log";
    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * Log a security event.
     * @param eventType  e.g. "LOGIN", "FAILED_LOGIN", "ACCESS_DENIED", "LOGOUT"
     * @param actor      who performed the action (username, email, IP)
     * @param details    human-readable description
     */
    public static synchronized void log(String eventType, String actor, String details) {
        String entry = String.format("[%s] [%-15s] [%s] %s",
            LocalDateTime.now().format(FMT),
            eventType.toUpperCase(),
            actor,
            details
        );
        // Print to console (visible during development/demo)
        System.out.println("AUDIT: " + entry);

        // Append to log file (immutable trail)
        try (BufferedWriter w = new BufferedWriter(new FileWriter(LOG_FILE, true))) {
            w.write(entry);
            w.newLine();
        } catch (IOException e) {
            System.err.println("WARNING: Could not write audit log: " + e.getMessage());
        }
    }

    /** Read all log entries. Most recent first. */
    public static List<String> readLogs() {
        List<String> lines = new ArrayList<>();
        File f = new File(LOG_FILE);
        if (!f.exists()) return lines;
        try (BufferedReader r = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = r.readLine()) != null)
                lines.add(0, line); // insert at front = newest first
        } catch (IOException e) {
            lines.add("Error reading log: " + e.getMessage());
        }
        return lines;
    }

    /** Read only entries of a specific event type. */
    public static List<String> readByType(String eventType) {
        List<String> result = new ArrayList<>();
        for (String line : readLogs())
            if (line.contains("[" + eventType.toUpperCase() + "]"))
                result.add(line);
        return result;
    }

    // Convenience methods
    public static void logLogin(String actor)        { log("LOGIN",        actor, "Successful login"); }
    public static void logLogout(String actor)       { log("LOGOUT",       actor, "User logged out"); }
    public static void logFailedLogin(String actor, int attempt) {
        log("FAILED_LOGIN", actor, "Failed attempt #" + attempt);
    }
    public static void logAdminAction(String actor, String action) {
        log("ADMIN_ACTION", actor, action);
    }
}
