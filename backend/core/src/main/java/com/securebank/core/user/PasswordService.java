package com.securebank.core.user;

import org.springframework.security.crypto.bcrypt.BCrypt;

/**
 * Password hashing for the training target.
 */
public final class PasswordService {

    /**
     * The bcrypt work factor. Each increment doubles the cost of a single hash,
     * so 12 makes an offline guess roughly 100ms of CPU instead of the
     * microseconds an MD5 digest takes.
     */
    private static final int BCRYPT_COST = 12;

    private PasswordService() {
    }

    /**
     * Hashes a password with bcrypt and returns the encoded hash.
     *
     * <p>FIXED: [A04-Lab7] Cryptographic Failure - passwords are no longer hashed with
     * unsalted MD5. MD5 is not a password hashing algorithm: it is far too fast to
     * resist brute force, and the lack of a salt means identical passwords produce
     * identical hashes, so a single rainbow table attacks every account at once.
     *
     * <p>bcrypt generates a unique random salt per hash and embeds it in the
     * encoded string, so the same password yields a different stored value for
     * every user and each verification attempt costs ~100ms of CPU.</p>
     */
    public static String hash(String rawPassword) {
        return BCrypt.hashpw(rawPassword, BCrypt.gensalt(BCRYPT_COST));
    }

    /**
     * Compares a candidate password against a stored hash.
     *
     * <p>FIXED: [A04-Lab7] the comparison is no longer a plain string equality check
     * over an MD5 digest. BCrypt.checkpw re-derives the hash from the candidate
     * password using the salt embedded in the stored value and compares the
     * results in constant time.</p>
     */
    public static boolean matches(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null) {
            return false;
        }
        try {
            return BCrypt.checkpw(rawPassword, storedHash);
        } catch (IllegalArgumentException e) {
            // The stored value is not a bcrypt hash at all.
            return false;
        }
    }
}
