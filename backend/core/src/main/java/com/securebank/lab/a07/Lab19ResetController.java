package com.securebank.lab.a07;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
     * The window, in seconds, either side of the request time that is still accepted.
     */
    private static final int WINDOW_SECONDS = 60;

    /**
     * username -> the epoch second the token was issued for.
     */
    private final Map<String, Long> issuedAt = new ConcurrentHashMap<>();

    private final UserRepository users;

    public Lab19ResetController(UserRepository users) {
        this.users = users;
    }

    public record ResetRequest(String username) {
    }

    public record ResetConfirmRequest(String token, String newPassword) {
    }

    /**
     * Issues a password reset token.
     */
    @PostMapping("/reset-request")
    public ResponseEntity<?> resetRequest(@RequestBody ResetRequest request) {
        String username = request.username() == null ? "" : request.username();

        User user = users.findByUsername(username).orElse(null);
        if (user == null) {
            // VULN: [A07-Lab19] User Enumeration - a missing account is reported
            // differently from a successful request.
            // FIX:  always return the same neutral response.
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        long now = System.currentTimeMillis() / 1000;
        issuedAt.put(username, now);

        String token = computeToken(username, now);

        // VULN: [A07-Lab19] Predictable Password Reset Token - the token is
        // md5(username + epoch_second), so anyone who knows the username and roughly
        // when the request was made can derive it. The search space is tiny: the
        // attacker only has to try the seconds around the request time.
        // FIX:  use a cryptographically random token:
        //       String token = secrets.token_urlsafe(32);
        //       store it with a one-hour expiry, delete it after a single use, and do
        //       not return it in the response body.
        //
        // The token is echoed here purely so the lab can be completed end-to-end.
        return ResponseEntity.ok(Map.of(
                "username", username,
                "token", token,
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

        // VULN: [A07-Lab19] Predictable Token - the token is accepted if it matches any
        // second in the window around the recorded issue time, so brute-forcing 121
        // candidate seconds is enough. The token is also never invalidated after use.
        // FIX:  look the token up in a store, check its expiry, and delete it on use:
        //       ResetToken stored = resetTokens.get(token);
        //       if (stored == null || stored.expiresAt().isBefore(Instant.now())) {
        //           return ResponseEntity.badRequest().body(Map.of("error", "Invalid token"));
        //       }
        //       resetTokens.remove(token);
        for (Map.Entry<String, Long> entry : issuedAt.entrySet()) {
            String username = entry.getKey();
            long issued = entry.getValue();

            for (long offset = -WINDOW_SECONDS; offset <= WINDOW_SECONDS; offset++) {
                if (computeToken(username, issued + offset).equalsIgnoreCase(token)) {
                    User user = users.findByUsername(username).orElse(null);
                    if (user == null) {
                        return ResponseEntity.status(404).body(Map.of("error", "User not found"));
                    }

                    users.updatePasswordHash(user.getId(), PasswordService.md5(newPassword));

                    return ResponseEntity.ok(Map.of(
                            "password_reset", true,
                            "username", username));
                }
            }
        }

        return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired token"));
    }

    /**
     * Computes the reset token for a username and a second.
     */
    private String computeToken(String username, long epochSecond) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] bytes = digest.digest((username + epochSecond).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
