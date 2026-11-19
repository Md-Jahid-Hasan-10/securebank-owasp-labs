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
     * The update payload.
     *
     * <p>FIXED: [A06-Lab15] This record used to declare {@code role}, a field the
     * client should never be able to set. It no longer does: the server decides which
     * fields a client may change, so a field that is not on the record simply cannot
     * be bound from the request body.</p>
     */
    public record ProfileUpdateRequest(String email) {
    }

    /**
     * Updates the caller's own profile.
     */
    @PatchMapping("/profile")
    public ResponseEntity<?> updateProfile(@RequestBody ProfileUpdateRequest request) {
        // FIXED: [A06-Lab15] the account to update is now taken from the
        // authenticated principal, not from the request body. The old code looked
        // the user up by a client-supplied username, so a caller could update
        // somebody else's profile - a second bug hidden behind the first.
        com.securebank.core.security.CurrentUser caller =
                com.securebank.core.security.CurrentUserHolder.get();

        if (caller == null || caller.getId() == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        User user = users.findById(caller.getId()).orElse(null);
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        // FIXED: [A06-Lab15] Mass Assignment / Over-Exposed DTO - the request record
        // used to declare `role` as a bindable field and every field it declared was
        // written straight to the database row. A client that simply added
        // "role": "admin" to the JSON body therefore elevated its own privileges,
        // because the server never decided which fields a client was allowed to
        // change - the client did.
        //
        // NOW: the record only carries `email`. The role is taken from the stored
        // user, so it cannot be changed through this endpoint at all. Role changes
        // belong on a separate endpoint that requires admin rights.
        users.updateProfile(user.getId(),
                user.getUsername(),
                request.email() == null ? user.getEmail() : request.email(),
                user.getRole());

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
