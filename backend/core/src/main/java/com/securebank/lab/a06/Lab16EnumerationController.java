package com.securebank.lab.a06;

import java.util.Map;

import com.securebank.core.security.JwtService;
import com.securebank.core.user.PasswordService;
import com.securebank.core.user.User;
import com.securebank.core.user.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 16 — Account Enumeration via Error Messages</h2>
 * <p>OWASP A06 — Insecure Design · Severity: Low</p>
 *
 * <p><b>Objective:</b> enumerate valid usernames using different error messages.</p>
 */
@RestController
@RequestMapping("/api/a06/auth")
public class Lab16EnumerationController {

    /**
     * FIXED: [A06-Lab16] A valid bcrypt hash of a value nobody can supply, used to
     * burn the same CPU time when the username does not exist. Without it the
     * "user not found" path returns immediately while the "wrong password" path
     * costs a bcrypt comparison, and the timing difference alone enumerates
     * accounts even though both responses say the same thing.
     */
    private static final String DUMMY_HASH =
            "$2a$12$C6UzMDM.H6dfI/f/IKcEe.7Qv1zBnOa5z7v0Qq3x9y0Yv0Z0V0Z0V0";

    private final UserRepository users;
    private final JwtService jwtService;

    public Lab16EnumerationController(UserRepository users, JwtService jwtService) {
        this.users = users;
        this.jwtService = jwtService;
    }

    public record LoginRequest(String username, String password) {
    }

    /**
     * Logs a customer in.
     */
    @PostMapping("/login/")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        String username = request.username() == null ? "" : request.username();
        String password = request.password() == null ? "" : request.password();

        User user = users.findByUsername(username).orElse(null);

        // FIXED: [A06-Lab16] User Enumeration - the two failure modes used to be
        // reported differently. "User not found" told an attacker that the username did
        // not exist, while "Incorrect password" told them that it DID exist and only
        // the password was wrong. That was enough to build a list of valid accounts,
        // which then feeds a targeted brute-force, credential-stuffing or phishing
        // campaign.
        //
        // NOW: one identical message for every failure, and the same amount of work
        // in every case. When the username does not exist the comparison is still run
        // against a fixed dummy bcrypt hash, so the response takes the same time
        // whether the account exists or not - otherwise the difference would be
        // measurable even though the messages match.
        if (user == null) {
            PasswordService.matches(password, DUMMY_HASH);
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        if (!PasswordService.matches(password, user.getPasswordHash())) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        return ResponseEntity.ok(Map.of(
                "token", jwtService.issue(user.getId(), user.getUsername(), user.getRole()),
                "user", Map.of(
                        "id", user.getId(),
                        "username", user.getUsername(),
                        "role", user.getRole())));
    }
}
