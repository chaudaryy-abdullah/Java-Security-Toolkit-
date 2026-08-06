package com.security.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AESEncryption — AES-256-GCM Field-Level Encryption
 *
 * USAGE:
 *   String encrypted = AESEncryption.encrypt("passport-AB123456");
 *   String original  = AESEncryption.decrypt(encrypted);
 *
 * WHY AES-256-GCM:
 *   - AES-256: military-grade symmetric encryption
 *   - GCM mode: provides both encryption AND integrity checking
 *   - Random IV per encryption: same plaintext → different ciphertext every time
 *   - Even if DB is stolen, encrypted fields are unreadable without the key
 *
 * PRODUCTION NOTE:
 *   Store SECRET_KEY in environment variable or a key vault (e.g. AWS Secrets Manager).
 *   Never hardcode in source code for production systems.
 *   For demo/academic use, the hardcoded key below is acceptable.
 */
public class AESEncryption {

    private static final String ALGORITHM      = "AES/GCM/NoPadding";
    private static final int    GCM_TAG_LENGTH = 128;
    private static final int    GCM_IV_LENGTH  = 12;

    // For production: load from System.getenv("AES_SECRET_KEY")
    private static final String SECRET_KEY_B64 = "dGhpcyBpcyBhIDMyLWJ5dGUgc2VjcmV0IGtleXM=";

    private static SecretKey getKey() {
        byte[] raw = Base64.getDecoder().decode(SECRET_KEY_B64);
        byte[] key = new byte[32]; // 256-bit
        System.arraycopy(raw, 0, key, 0, Math.min(raw.length, 32));
        return new SecretKeySpec(key, "AES");
    }

    /**
     * Encrypt sensitive data before storing in database.
     * Returns Base64-encoded string with IV prepended.
     */
    public static String encrypt(String plainText) {
        if (plainText == null || plainText.isEmpty()) return plainText;
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, getKey(), new GCMParameterSpec(GCM_TAG_LENGTH, iv));

            byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF-8"));
            byte[] combined   = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypt a previously encrypted value from the database.
     */
    public static String decrypt(String encryptedBase64) {
        if (encryptedBase64 == null || encryptedBase64.isEmpty()) return encryptedBase64;
        try {
            byte[] combined = Base64.getDecoder().decode(encryptedBase64);
            byte[] iv         = new byte[GCM_IV_LENGTH];
            byte[] cipherText = new byte[combined.length - GCM_IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
            System.arraycopy(combined, GCM_IV_LENGTH, cipherText, 0, cipherText.length);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, getKey(), new GCMParameterSpec(GCM_TAG_LENGTH, iv));

            return new String(cipher.doFinal(cipherText), "UTF-8");
        } catch (Exception e) {
            return "[DECRYPTION FAILED]";
        }
    }

    /**
     * Generate a new AES-256 key (run once, copy to SECRET_KEY_B64).
     */
    public static String generateNewKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return Base64.getEncoder().encodeToString(kg.generateKey().getEncoded());
    }

    // Quick demo
    public static void main(String[] args) throws Exception {
        String original  = "PASSPORT-AB123456";
        String encrypted = encrypt(original);
        String decrypted = decrypt(encrypted);

        System.out.println("Original:  " + original);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
        System.out.println("Match: " + original.equals(decrypted));
    }
}
