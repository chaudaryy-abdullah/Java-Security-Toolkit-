package com.security;

import com.security.auth.PasswordManager;
import com.security.auth.LoginLockout;
import com.security.auth.SessionManager;
import com.security.crypto.AESEncryption;
import com.security.access.RBAC;
import com.security.validation.InputValidator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

public class SecurityToolkitTest {

    // ── PasswordManager ──────────────────────────────────────────────────
    @Test @DisplayName("BCrypt: hash should not equal plaintext")
    void testHashNotPlaintext() {
        String hash = PasswordManager.hash("Admin@123");
        assertNotEquals("Admin@123", hash);
        assertTrue(hash.startsWith("$2a$"));
    }

    @Test @DisplayName("BCrypt: verify should return true for correct password")
    void testVerifyCorrect() {
        String hash = PasswordManager.hash("Admin@123");
        assertTrue(PasswordManager.verify("Admin@123", hash));
    }

    @Test @DisplayName("BCrypt: verify should return false for wrong password")
    void testVerifyWrong() {
        String hash = PasswordManager.hash("Admin@123");
        assertFalse(PasswordManager.verify("WrongPassword", hash));
    }

    @Test @DisplayName("Password strength: weak password fails")
    void testWeakPassword() {
        assertNotNull(PasswordManager.checkStrength("abc"));
    }

    @Test @DisplayName("Password strength: strong password passes")
    void testStrongPassword() {
        assertNull(PasswordManager.checkStrength("Admin@123"));
    }

    // ── AESEncryption ────────────────────────────────────────────────────
    @Test @DisplayName("AES: decrypt(encrypt(x)) should equal x")
    void testEncryptDecrypt() {
        String original = "PASSPORT-AB123456";
        String encrypted = AESEncryption.encrypt(original);
        String decrypted = AESEncryption.decrypt(encrypted);
        assertEquals(original, decrypted);
    }

    @Test @DisplayName("AES: encrypted value should not equal original")
    void testEncryptedDifferent() {
        String original = "sensitive-data";
        assertNotEquals(original, AESEncryption.encrypt(original));
    }

    @Test @DisplayName("AES: same plaintext encrypts to different ciphertext each time")
    void testEncryptionRandomIV() {
        String e1 = AESEncryption.encrypt("test");
        String e2 = AESEncryption.encrypt("test");
        assertNotEquals(e1, e2); // Random IV ensures different ciphertext
    }

    // ── RBAC ─────────────────────────────────────────────────────────────
    @Test @DisplayName("RBAC: ADMIN has all permissions")
    void testAdminAllPermissions() {
        for (RBAC.Permission p : RBAC.Permission.values())
            assertTrue(RBAC.hasPermission("ADMIN", p));
    }

    @Test @DisplayName("RBAC: GUEST cannot view audit logs")
    void testGuestNoAuditLogs() {
        assertFalse(RBAC.hasPermission("GUEST", RBAC.Permission.VIEW_AUDIT_LOGS));
    }

    @Test @DisplayName("RBAC: enforce throws SecurityException for unauthorized role")
    void testEnforceThrows() {
        assertThrows(SecurityException.class, () ->
            RBAC.enforce("GUEST", RBAC.Permission.MANAGE_USERS));
    }

    // ── LoginLockout ─────────────────────────────────────────────────────
    @Test @DisplayName("Lockout: account locked after MAX_ATTEMPTS failures")
    void testLockoutAfterMaxAttempts() {
        String user = "locktest@test.com";
        for (int i = 0; i < LoginLockout.MAX_ATTEMPTS; i++)
            LoginLockout.recordFailure(user);
        assertTrue(LoginLockout.isLocked(user));
        LoginLockout.reset(user); // cleanup
    }

    @Test @DisplayName("Lockout: reset clears lockout")
    void testResetClearsLockout() {
        String user = "resettest@test.com";
        for (int i = 0; i < LoginLockout.MAX_ATTEMPTS; i++)
            LoginLockout.recordFailure(user);
        LoginLockout.reset(user);
        assertFalse(LoginLockout.isLocked(user));
    }

    // ── InputValidator ───────────────────────────────────────────────────
    @Test @DisplayName("Validator: valid email returns null")
    void testValidEmail() {
        assertNull(InputValidator.validateEmail("user@example.com"));
    }

    @Test @DisplayName("Validator: invalid email returns error")
    void testInvalidEmail() {
        assertNotNull(InputValidator.validateEmail("not-an-email"));
    }

    @Test @DisplayName("Validator: sanitize strips HTML tags")
    void testSanitize() {
        String result = InputValidator.sanitize("<script>alert('xss')</script>Hello");
        assertFalse(result.contains("<"));
        assertTrue(result.contains("Hello"));
    }
}
