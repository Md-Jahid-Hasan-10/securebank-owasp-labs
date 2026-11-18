package com.securebank.lab.a06;

import java.util.Map;

import com.securebank.core.user.User;
import com.securebank.core.user.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 15 — Mass Assignment: Self-Promote to Admin</h2>
 * <p>OWASP A06 — Insecure Design · Severity: Medium</p>
 *
 * <p><b>Objective:</b> promote a customer account to admin by exploiting an
 * over-permissive request binding.</p>
 */
@RestController
@RequestMapping("/api/a06")
public class Lab15MassAssignmentController {

    private final UserRepository users;

    public Lab15MassAssignmentController(UserRepository users) {
        this.users = users;
    }

    /**
     * The update payload. Note that it declares {@code role}, which is a field the
     * client should never be able to set.
     */
    public record ProfileUpdateRequest(String username, String email, String role) {
    }

    /**
     * Updates the caller's own profile.
     */
    @PatchMapping("/profile")
    public ResponseEntity<?> updateProfile(@RequestBody ProfileUpdateRequest request) {
        User user = users.findByUsername(request.username()).orElse(null);
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        // VULN: [A06-Lab15] Mass Assignment / Over-Exposed DTO - the request record
        // declares `role` as a bindable field and every field it declares is written
        // straight to the database row. A client that simply adds "role": "admin" to
        // the JSON body therefore elevates its own privileges, because the server
        // never decides which fields a client is allowed to change - the client does.
        // FIX:  do not bind privileged fields from user input. Either omit `role` from
        //       the request type entirely:
        //           public record ProfileUpdateRequest(String username, String email) { }
        //       or, in a framework that supports it, mark it read-only:
        //           @JsonProperty(access = Access.READ_ONLY)
        //       Role changes belong on a separate endpoint that requires admin rights.
        users.updateProfile(user.getId(),
                request.username(),
                request.email(),
                request.role() == null ? user.getRole() : request.role());

        User updated = users.findById(user.getId()).orElse(null);

        return ResponseEntity.ok(Map.of(
                "id", updated == null ? null : updated.getId(),
                "username", updated == null ? null : updated.getUsername(),
                "email", updated == null ? null : updated.getEmail(),
                "role", updated == null ? null : updated.getRole()));
    }

    /**
     * Returns the caller's profile.
     */
    @GetMapping("/profile")
    public ResponseEntity<?> profile() {
        String username = com.securebank.core.security.CurrentUserHolder.get() == null
                ? null
                : com.securebank.core.security.CurrentUserHolder.get().getUsername();

        User user = username == null ? null : users.findByUsername(username).orElse(null);
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        return ResponseEntity.ok(Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "email", user.getEmail(),
                "role", user.getRole()));
    }
}
