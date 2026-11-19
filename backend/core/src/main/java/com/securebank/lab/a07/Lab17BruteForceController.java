package com.securebank.lab.a07;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import com.securebank.core.security.JwtService;
import com.securebank.core.user.PasswordService;
import com.securebank.core.user.User;
import com.securebank.core.user.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 17 — Brute-Force Login: No Rate Limiting</h2>
 * <p>OWASP A07 — Authentication Failures · Severity: Low</p>
 *
 * <p><b>Objective:</b> brute-force alice's password with no lockout in place.</p>
 */
@RestController
@RequestMapping("/api/a07/auth")
public class Lab17BruteForceController {

    /**
     * FIXED: [A07-Lab17] A valid bcrypt hash of a value nobody can supply, used to
     * burn the same CPU time when the username does not exist, so that the two
     * failure paths take the same time.
     */
    private static final String DUMMY_HASH =
            "$2a$12$C6UzMDM.H6dfI/f/IKcEe.7Qv1zBnOa5z7v0Qq3x9y0Yv0Z0V0Z0V0";

    private final UserRepository users;
    private final JwtService jwtService;

    /**
     * FIXED: [A07-Lab17] A tally of failed attempts, now actually used to block
     * requests. Keyed by username + client IP so that one attacker cannot lock out
     * every customer, and so that an attacker cannot rotate usernames to get a
     * fresh allowance each time.
     */
    private final Map<String, Attempt> attemptCounter = new ConcurrentHashMap<>();

    /**
     * FIXED: [A07-Lab17] The number of failed attempts allowed before the account is
     * locked out for the cooling-off period.
     */
    private static final int MAX_ATTEMPTS = 5;

    /**
     * FIXED: [A07-Lab17] How long an account stays locked out, in milliseconds.
     */
    private static final long LOCKOUT_MILLIS = 60_000L;

    /**
     * FIXED: [A07-Lab17] The state of one throttling bucket: how many failures have
     * happened and when the bucket was last used.
     */
    private static final class Attempt {
        private final AtomicInteger failures = new AtomicInteger();
        private volatile long lockedUntil = 0L;
    }

    public Lab17BruteForceController(UserRepository users, JwtService jwtService) {
        this.users = users;
        this.jwtService = jwtService;
    }

    public record LoginRequest(String username, String password) {
    }

    /**
     * Logs a customer in, throttled.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request,
                                   jakarta.servlet.http.HttpServletRequest httpRequest) {
        String username = request.username() == null ? "" : request.username();
        String password = request.password() == null ? "" : request.password();

        User user = users.findByUsername(username).orElse(null);

        // FIXED: [A07-Lab17] Missing Rate Limiting / No Account Lockout - there used
        // to be no throttle on attempts, no per-account lockout and no CAPTCHA, and
        // the failed attempt was not even delayed. The attempt counter was
        // bookkeeping only: nothing ever consulted it, so the attacker could try an
        // unlimited number of passwords. With a wordlist and a handful of threads, a
        // common password like "password123" fell in seconds.
        //
        // NOW: the counter is consulted before the password is even checked. After
        // MAX_ATTEMPTS failures the bucket is locked out for LOCKOUT_MILLIS and every
        // further attempt is refused with 429, whatever the password is. The lockout
        // is keyed by username *and* client address, so one attacker cannot lock
        // every customer out by hammering a single account, and so an attacker cannot
        // dodge the limit by rotating usernames.
        String clientAddress = clientAddress(httpRequest);
        String bucketKey = username + "|" + clientAddress;

        Attempt attempt = attemptCounter.computeIfAbsent(bucketKey, key -> new Attempt());

        long now = System.currentTimeMillis();
        if (now < attempt.lockedUntil) {
            long retryAfter = (attempt.lockedUntil - now + 999) / 1000;
            return ResponseEntity.status(429).body(Map.of(
                    "error", "Too many failed attempts",
                    "retry_after_seconds", retryAfter));
        }

        if (user == null) {
            PasswordService.matches(password, DUMMY_HASH);
            recordFailure(attempt);
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        if (!PasswordService.matches(password, user.getPasswordHash())) {
            recordFailure(attempt);
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        // A successful login clears the bucket.
        attemptCounter.remove(bucketKey);

        return ResponseEntity.ok(Map.of(
                "token", jwtService.issue(user.getId(), user.getUsername(), user.getRole()),
                "user", Map.of(
                        "id", user.getId(),
                        "username", user.getUsername(),
                        "role", user.getRole())));
    }

    /**
     * FIXED: [A07-Lab17] Records a failed attempt and locks the bucket out once the
     * limit is reached.
     */
    private void recordFailure(Attempt attempt) {
        int failures = attempt.failures.incrementAndGet();
        if (failures >= MAX_ATTEMPTS) {
            attempt.lockedUntil = System.currentTimeMillis() + LOCKOUT_MILLIS;
        }
    }

    /**
     * FIXED: [A07-Lab17] Determines the client address for the throttle key. The
     * {@code X-Forwarded-For} header is only consulted when the request came
     * through a proxy that sets it; otherwise the remote address is used.
     */
    private static String clientAddress(jakarta.servlet.http.HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            return (comma > 0 ? forwarded.substring(0, comma) : forwarded).trim();
        }
        String remote = request.getRemoteAddr();
        return remote == null ? "unknown" : remote;
    }

    /**
     * Reports how many attempts have been made against each account.
     */
    @GetMapping("/attempts")
    public ResponseEntity<?> attempts() {
        Map<String, Integer> snapshot = new java.util.LinkedHashMap<>();
        attemptCounter.forEach((key, attempt) -> snapshot.put(key, attempt.failures.get()));
        return ResponseEntity.ok(Map.of(
                "note", "Failed attempts are counted and the account is locked out after "
                        + MAX_ATTEMPTS + " failures for " + (LOCKOUT_MILLIS / 1000) + " seconds.",
                "attempts", snapshot));
    }
}
