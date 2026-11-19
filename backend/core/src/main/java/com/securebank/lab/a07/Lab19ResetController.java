package com.securebank.lab.a07;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.securebank.core.user.PasswordService;
import com.securebank.core.user.User;
import com.securebank.core.user.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 19 — Insecure Password Reset: Predictable Token</h2>
 * <p>OWASP A07 — Authentication Failures · Severity: High</p>
 *
 * <p><b>Objective:</b> compute a valid password reset token without access to the
 * target's email.</p>
 */
@RestController
@RequestMapping("/api/a07/auth")
public class Lab19ResetController {

    /**
     * The window, in seconds, that a reset token stays valid.
     */
    private static final int WINDOW_SECONDS = 60;

    /**
     * FIXED: [A07-Lab19] The token store is keyed by the token itself and holds the
     * username it belongs to and the instant it expires. Nothing is derived from the
     * username, so there is nothing to compute.
     */
    private final Map<String, ResetToken> resetTokens = new ConcurrentHashMap<>();

    /**
     * FIXED: [A07-Lab19] The generator for reset tokens. {@link SecureRandom} is a
     * cryptographically strong source, so the token has 256 bits of entropy.
     */
    private final SecureRandom random = new SecureRandom();

    private final UserRepository users;

    public Lab19ResetController(UserRepository users) {
        this.users = users;
    }

    public record ResetRequest(String username) {
    }

    public record ResetConfirmRequest(String token, String newPassword) {
    }

    /**
     * A reset token that has been issued but not yet used.
     *
     * <p>FIXED: [A07-Lab19] the token itself is the key, so it can only be redeemed
     * by presenting exactly the value that was issued.</p>
     */
    private record ResetToken(String username, Instant expiresAt) {
    }

    /**
     * Issues a password reset token.
     */
    @PostMapping("/reset-request")
    public ResponseEntity<?> resetRequest(@RequestBody ResetRequest request) {
        String username = request.username() == null ? "" : request.username();

        User user = users.findByUsername(username).orElse(null);

        // FIXED: [A07-Lab19] User Enumeration - a missing account used to be reported
        // differently from a successful request, which turns the reset endpoint into
        // a username oracle.
        //
        // NOW: the response is the same either way. The token is only issued when the
        // account exists, but the caller cannot tell that from the response.
        String token = null;
        if (user != null) {
            // FIXED: [A07-Lab19] Predictable Password Reset Token - the token used to
            // be md5(username + epoch_second), so anyone who knew the username and
            // roughly when the request was made could derive it. The search space was
            // tiny: the attacker only had to try the seconds around the request time.
            //
            // NOW: the token is 256 bits of SecureRandom output. It is stored against
            // its expiry, and it is not derived from anything the attacker knows.
            token = newToken();
            resetTokens.put(token,
                    new ResetToken(username, Instant.now().plusSeconds(WINDOW_SECONDS)));
        }

        // The token is echoed here purely so the lab can be completed end-to-end. In
        // a real system it is emailed, never returned.
        return ResponseEntity.ok(Map.of(
                "username", username,
                "token", token == null ? "" : token,
                "expires_in_seconds", WINDOW_SECONDS,
                "note", "In a real system this token is emailed, never returned."));
    }

    /**
     * Consumes a password reset token.
     */
    @PostMapping("/reset-confirm")
    public ResponseEntity<?> resetConfirm(@RequestBody ResetConfirmRequest request) {
        String token = request.token() == null ? "" : request.token();
        String newPassword = request.newPassword() == null ? "" : request.newPassword();

        // FIXED: [A07-Lab19] Predictable Token - the token used to be accepted if it
        // matched any second in the window around the recorded issue time, so
        // brute-forcing 121 candidate seconds was enough. The token was also never
        // invalidated after use.
        //
        // NOW: the token is looked up in the store. An unknown token, or one whose
        // expiry has passed, is rejected. A valid token is removed from the store the
        // moment it is redeemed, so it cannot be used twice.
        ResetToken stored = resetTokens.get(token);

        if (stored == null || stored.expiresAt().isBefore(Instant.now())) {
            if (stored != null) {
                resetTokens.remove(token);
            }
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired token"));
        }

        resetTokens.remove(token);

        User user = users.findByUsername(stored.username()).orElse(null);
        if (user == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired token"));
        }

        // FIXED: [A04-Lab7] the reset password is stored as a bcrypt hash.
        users.updatePasswordHash(user.getId(), PasswordService.hash(newPassword));

        return ResponseEntity.ok(Map.of(
                "password_reset", true,
                "username", stored.username()));
    }

    /**
     * Generates a new, unguessable reset token.
     *
     * <p>FIXED: [A07-Lab19] 32 bytes of {@link SecureRandom} output, encoded with
     * the URL-safe base64 alphabet so the token can be carried in a URL without
     * escaping.</p>
     */
    private String newToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
