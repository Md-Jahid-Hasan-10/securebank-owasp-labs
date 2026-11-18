package com.securebank.core.security;

import java.util.Map;

import com.securebank.core.user.PasswordService;
import com.securebank.core.user.User;
import com.securebank.core.user.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The login endpoint used by the banking frontend.
 *
 * <p>The lab-specific login endpoints under {@code /api/aXX/auth/} are deliberately
 * separate so that each lab can exhibit one specific weakness without interfering
 * with the others.</p>
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository users;
    private final JwtService jwtService;

    public AuthController(UserRepository users, JwtService jwtService) {
        this.users = users;
        this.jwtService = jwtService;
    }

    public record LoginRequest(String username, String password) {
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        User user = users.findByUsername(request.username()).orElse(null);

        if (user == null || !PasswordService.matches(request.password(), user.getPasswordHash())) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        // FIXED: [A02-Lab5] Default Credentials - this login path used to accept the
        // seeded factory password, so blocking it only on the admin console would
        // have left the default credential working everywhere else.
        // NOW: an account flagged for a mandatory password change cannot log in
        //       until the password has been replaced.
        if (user.mustChangePassword()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "error", "Password must be changed before this account can be used",
                    "must_change_password", true));
        }

        String token = jwtService.issue(user.getId(), user.getUsername(), user.getRole());
        return ResponseEntity.ok(Map.of(
                "token", token,
                "user", Map.of(
                        "id", user.getId(),
                        "username", user.getUsername(),
                        "email", user.getEmail(),
                        "role", user.getRole(),
                        "full_name", user.getFullName())));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me() {
        CurrentUser user = CurrentUserHolder.get();
        if (user == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }
        return ResponseEntity.ok(Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "role", user.getRole()));
    }
}
