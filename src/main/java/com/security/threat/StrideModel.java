package com.security.threat;

import java.util.List;

/**
 * StrideModel — STRIDE Threat Model Documentation
 *
 * STRIDE = Spoofing, Tampering, Repudiation, Information Disclosure,
 *          Denial of Service, Elevation of Privilege
 *
 * Run this class to print the full threat model report.
 */
public class StrideModel {

    public record ThreatEntry(
        String category,
        String threat,
        String example,
        String mitigation,
        String status
    ) {}

    public static List<ThreatEntry> getThreats() {
        return List.of(
            new ThreatEntry(
                "Spoofing",
                "Attacker impersonates a legitimate user",
                "Login with stolen credentials",
                "BCrypt password hashing + login lockout after 5 attempts",
                "MITIGATED"
            ),
            new ThreatEntry(
                "Tampering",
                "Attacker modifies data in transit or at rest",
                "Editing guest passport number in DB directly",
                "AES-256-GCM field-level encryption on sensitive data",
                "MITIGATED"
            ),
            new ThreatEntry(
                "Repudiation",
                "User denies performing an action",
                "Admin claims they didn't delete a booking",
                "Append-only audit log with timestamp, user, and IP",
                "MITIGATED"
            ),
            new ThreatEntry(
                "Information Disclosure",
                "Sensitive data exposed to unauthorized users",
                "SQL injection to dump the users table",
                "PreparedStatements + RBAC + AES encryption at rest",
                "MITIGATED"
            ),
            new ThreatEntry(
                "Denial of Service",
                "System becomes unavailable",
                "Rapid automated login attempts flooding the server",
                "IP-based rate limiting (2-second window per IP)",
                "MITIGATED"
            ),
            new ThreatEntry(
                "Elevation of Privilege",
                "User gains higher permissions than granted",
                "Staff user accesses admin-only audit log",
                "RBAC enforced on every action; Security tab hidden for non-Admin",
                "MITIGATED"
            )
        );
    }

    /** Print full STRIDE report to console. */
    public static void printReport() {
        System.out.println("\n╔══════════════════════════════════════════════════════════╗");
        System.out.println("║              STRIDE THREAT MODEL REPORT                 ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝\n");
        for (ThreatEntry t : getThreats()) {
            System.out.println("Category   : " + t.category());
            System.out.println("Threat     : " + t.threat());
            System.out.println("Example    : " + t.example());
            System.out.println("Mitigation : " + t.mitigation());
            System.out.println("Status     : [" + t.status() + "]");
            System.out.println("──────────────────────────────────────────────────────────");
        }
    }

    public static void main(String[] args) {
        printReport();
    }
}
