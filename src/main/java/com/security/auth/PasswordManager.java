package com.security.auth;

import org.mindrot.jbcrypt.BCrypt;

/**
 * PasswordManager — BCrypt Password Hashing
 *
 * USAGE:
 *   String hash = PasswordManager.hash("myPassword123");
 *   boolean ok  = PasswordManager.verify("myPassword123", hash);
 *
 * WHY BCRYPT:
 *   - Automatically salts every hash (two identical passwords → different hashes)
 *   - Cost factor 12 = ~300ms per hash → too slow for brute force
 *   - Industry standard for Java applications
 */
public class PasswordManager {

    private static final int BCRYPT_COST = 12;

    /** Hash a plain-text password using BCrypt. Store the result — never the plain text. */
    public static String hash(String plainPassword) {
        if (plainPassword == null || plainPassword.isEmpty())
            throw new IllegalArgumentException("Password cannot be empty.");
        return BCrypt.hashpw(plainPassword, BCrypt.gensalt(BCRYPT_COST));
    }

    /** Verify a plain-text password against a stored BCrypt hash. */
    public static boolean verify(String plainPassword, String storedHash) {
        if (plainPassword == null || storedHash == null) return false;
        try {
            return BCrypt.checkpw(plainPassword, storedHash);
        } catch (Exception e) {
            return false; // Malformed hash — deny access
        }
    }

    /**
     * Check password strength.
     * @return null if strong, or an error message if weak.
     */
    public static String checkStrength(String password) {
        if (password == null || password.length() < 8)
            return "Password must be at least 8 characters.";
        if (!password.matches(".*[A-Z].*"))
            return "Password must contain an uppercase letter.";
        if (!password.matches(".*[a-z].*"))
            return "Password must contain a lowercase letter.";
        if (!password.matches(".*\\d.*"))
            return "Password must contain a number.";
        if (!password.matches(".*[!@#$%^&*()_+\\-=].*"))
            return "Password must contain a special character.";
        return null; // null = strong
    }

    /**
     * Generate a new BCrypt hash for testing/seeding.
     * Example: generateHash("admin123") → "$2a$12$..."
     */
    public static void main(String[] args) {
        String[] testPasswords = {"admin123", "staff123", "guest123"};
        System.out.println("=== BCrypt Hash Generator ===");
        for (String p : testPasswords) {
            System.out.println(p + " → " + hash(p));
        }
    }
}
