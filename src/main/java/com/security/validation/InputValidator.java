package com.security.validation;

import java.time.LocalDate;

/**
 * InputValidator — Input Validation + SQL Injection Prevention Demo
 *
 * USAGE:
 *   String err = InputValidator.validateEmail("user@email.com"); // null = valid
 *   String clean = InputValidator.sanitize(userInput);
 *   InputValidator.sqlInjectionDemo(); // prints attack vs protected query
 */
public class InputValidator {

    // Whitelist patterns — only allow expected characters
    private static final String NAME_PATTERN     = "^[a-zA-Z\\s\\-'.]{2,100}$";
    private static final String EMAIL_PATTERN    = "^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$";
    private static final String PHONE_PATTERN    = "^[+]?[0-9\\s\\-]{7,20}$";
    private static final String USERNAME_PATTERN = "^[a-zA-Z0-9._\\-]{3,50}$";

    /** @return null if valid, error message if invalid */
    public static String validateName(String name) {
        if (name == null || name.trim().isEmpty()) return "Name cannot be empty.";
        if (!name.matches(NAME_PATTERN))           return "Name contains invalid characters.";
        return null;
    }

    public static String validateEmail(String email) {
        if (email == null || email.trim().isEmpty()) return "Email cannot be empty.";
        if (!email.matches(EMAIL_PATTERN))           return "Invalid email format.";
        return null;
    }

    public static String validatePhone(String phone) {
        if (phone == null || phone.trim().isEmpty()) return "Phone cannot be empty.";
        if (!phone.matches(PHONE_PATTERN))           return "Invalid phone number.";
        return null;
    }

    public static String validateUsername(String username) {
        if (username == null || username.trim().isEmpty()) return "Username cannot be empty.";
        if (!username.matches(USERNAME_PATTERN))           return "Username: 3-50 chars, letters/numbers/._- only.";
        return null;
    }

    public static String validateDates(LocalDate start, LocalDate end) {
        if (start == null)            return "Start date is required.";
        if (end == null)              return "End date is required.";
        if (!start.isBefore(end))     return "End date must be after start date.";
        if (start.isBefore(LocalDate.now())) return "Start date cannot be in the past.";
        return null;
    }

    /**
     * Sanitize a string for safe display.
     * Strips HTML tags and dangerous characters.
     */
    public static String sanitize(String input) {
        if (input == null) return "";
        return input
            .replaceAll("<[^>]*>", "")        // Remove HTML tags
            .replaceAll("[<>\"'%;()&+]", "")  // Remove dangerous chars
            .trim();
    }

    /**
     * SQL INJECTION DEMO — Call this to show the attack vs protection.
     *
     * Run: InputValidator.sqlInjectionDemo();
     */
    public static void sqlInjectionDemo() {
        String attack = "' OR '1'='1'; DROP TABLE users; --";

        System.out.println("\n╔══════════════════════════════════════════════════╗");
        System.out.println("║         SQL INJECTION DEMONSTRATION             ║");
        System.out.println("╚══════════════════════════════════════════════════╝");
        System.out.println("Attack input: " + attack);

        System.out.println("\n❌ VULNERABLE (string concatenation):");
        String vulnerable = "SELECT * FROM users WHERE username = '" + attack + "'";
        System.out.println("   Query: " + vulnerable);
        System.out.println("   → Database EXECUTES the injected SQL!");
        System.out.println("   → Table dropped, authentication bypassed.");

        System.out.println("\n✅ PROTECTED (PreparedStatement):");
        System.out.println("   String sql = \"SELECT * FROM users WHERE username = ?\";");
        System.out.println("   stmt = conn.prepareStatement(sql);");
        System.out.println("   stmt.setString(1, userInput); // driver escapes it");
        System.out.println("   → Attack string treated as LITERAL DATA. Safe.");
        System.out.println("═══════════════════════════════════════════════════\n");
    }
}
