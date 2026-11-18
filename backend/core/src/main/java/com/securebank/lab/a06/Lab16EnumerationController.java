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

        // VULN: [A06-Lab16] User Enumeration - the two failure modes are reported
        // differently. "User not found" tells an attacker that the username does not
        // exist, while "Incorrect password" tells them that it DOES exist and only the
        // password was wrong. That is enough to build a list of valid accounts, which
        // then feeds a targeted brute-force, credential-stuffing or phishing campaign.
        // FIX:  return one identical message for every failure:
        //       return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        //       The response should also take the same time whether the user exists or
        //       not, otherwise the difference is measurable even when the messages match.
        if (user == null) {
            return ResponseEntity.status(401).body(Map.of("error", "User not found"));
        }

        if (!PasswordService.matches(password, user.getPasswordHash())) {
            return ResponseEntity.status(401).body(Map.of("error", "Incorrect password"));
        }

        return ResponseEntity.ok(Map.of(
                "token", jwtService.issue(user.getId(), user.getUsername(), user.getRole()),
                "user", Map.of(
                        "id", user.getId(),
                        "username", user.getUsername(),
                        "role", user.getRole())));
    }
}
