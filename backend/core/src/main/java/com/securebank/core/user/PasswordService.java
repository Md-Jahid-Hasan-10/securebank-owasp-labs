package com.securebank.core.user;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Password hashing for the training target.
 */
public final class PasswordService {

    private PasswordService() {
    }

    /**
     * Hashes a password with MD5 and returns the lowercase hex digest.
     *
     * <p>VULN: [A04-Lab7] Cryptographic Failure - passwords are hashed with unsalted MD5.
     * MD5 is not a password hashing algorithm; it is far too fast to resist brute force
     * and the lack of a salt means identical passwords produce identical hashes and every
     * hash can be attacked with a single rainbow table.</p>
     *
     * <p>FIX: use bcrypt or Argon2id, e.g.
     * {@code BCrypt.hashpw(password, BCrypt.gensalt(12))}, and compare with
     * {@code BCrypt.checkpw}.</p>
     */
    // VULN: [A04-Lab7] Cryptographic Failure - unsalted MD5 used for password storage
    // FIX:  use bcrypt/Argon2id via spring-security-crypto
    public static String md5(String rawPassword) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] bytes = digest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 unavailable", e);
        }
    }

    /**
     * Compares a candidate password against a stored hash.
     *
     * <p>VULN: [A04-Lab7] the comparison is a plain string equality check over an MD5
     * digest, so the stored value is directly attackable once obtained.</p>
     *
     * <p>FIX: use {@code BCrypt.checkpw(raw, hash)} which performs a constant-time
     * comparison against a salted hash.</p>
     */
    public static boolean matches(String rawPassword, String storedHash) {
        return md5(rawPassword).equalsIgnoreCase(storedHash);
    }
}
