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

    private final UserRepository users;
    private final JwtService jwtService;

    /**
     * A tally of failed attempts, kept only so the lab can show how many were made.
     * It is never used to block anything.
     */
    private final Map<String, AtomicInteger> attemptCounter = new ConcurrentHashMap<>();

    public Lab17BruteForceController(UserRepository users, JwtService jwtService) {
        this.users = users;
        this.jwtService = jwtService;
    }

    public record LoginRequest(String username, String password) {
    }

    /**
     * Logs a customer in, with no throttling whatsoever.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        String username = request.username() == null ? "" : request.username();
        String password = request.password() == null ? "" : request.password();

        User user = users.findByUsername(username).orElse(null);

        // VULN: [A07-Lab17] Missing Rate Limiting / No Account Lockout - there is no
        // throttle on attempts, no per-account lockout and no CAPTCHA, and the failed
        // attempt is not even delayed. The attempt counter below is bookkeeping only:
        // nothing ever consults it, so the attacker can try an unlimited number of
        // passwords. With a wordlist and a handful of threads, a common password like
        // "password123" falls in seconds.
        // FIX:  add rate limiting and lockout, e.g. with Spring's Bucket4j or
        //       resilience4j:
        //       Bucket bucket = buckets.computeIfAbsent(username, k -> Bucket4j.builder()
        //               .addLimit(5).build());
        //       if (!bucket.tryConsume(1)) {
        //           return ResponseEntity.status(429).body(Map.of("error", "Too many attempts"));
        //       }
        //       Lock the account after N failures, and require a CAPTCHA on the
        //       web-facing form.
        if (user == null) {
            attemptCounter.computeIfAbsent(username, key -> new AtomicInteger()).incrementAndGet();
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        if (!PasswordService.matches(password, user.getPasswordHash())) {
            int attempts = attemptCounter.computeIfAbsent(username, key -> new AtomicInteger())
                    .incrementAndGet();
            return ResponseEntity.status(401).body(Map.of(
                    "error", "Invalid credentials",
                    "attempts_so_far", attempts));
        }

        attemptCounter.remove(username);

        return ResponseEntity.ok(Map.of(
                "token", jwtService.issue(user.getId(), user.getUsername(), user.getRole()),
                "user", Map.of(
                        "id", user.getId(),
                        "username", user.getUsername(),
                        "role", user.getRole())));
    }

    /**
     * Reports how many attempts have been made against each account.
     */
    @GetMapping("/attempts")
    public ResponseEntity<?> attempts() {
        Map<String, Integer> snapshot = new java.util.LinkedHashMap<>();
        attemptCounter.forEach((username, count) -> snapshot.put(username, count.get()));
        return ResponseEntity.ok(Map.of(
                "note", "The counter is informational only - nothing blocks the requests.",
                "attempts", snapshot));
    }
}
