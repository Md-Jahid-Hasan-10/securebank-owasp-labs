package com.securebank.lab.a02;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.securebank.core.account.Account;
import com.securebank.core.account.AccountRepository;
import com.securebank.core.security.CurrentUser;
import com.securebank.core.security.CurrentUserHolder;
import com.securebank.core.security.JwtService;
import com.securebank.core.transfer.Transfer;
import com.securebank.core.transfer.TransferRepository;
import com.securebank.core.user.PasswordService;
import com.securebank.core.user.User;
import com.securebank.core.user.UserRepository;
import com.securebank.lab.common.LabResponses;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 5 — Default Admin Credentials</h2>
 * <p>OWASP A02 — Security Misconfiguration · Severity: Low</p>
 *
 * <p><b>Objective:</b> log into the admin console with the default credentials.</p>
 *
 * <p>This is the Spring Boot analogue of Django's {@code /admin/} panel.</p>
 */
@RestController
@RequestMapping("/api/a02/admin")
public class Lab5DefaultAdminController {

    /**
     * FIXED: [A02-Lab5] Default Credentials - the seeded administrator account used to
     * ship with the factory password, so anyone who had read the seed script or the
     * public repository could log in as admin on a freshly deployed instance.
     * NOW: the seeded account is flagged must_change_password and cannot be used
     *       until its password has been changed, and new administrator accounts can
     *       only be created by an already authenticated administrator.
     */
    private static final String DEFAULT_ADMIN_PASSWORD = "admin";

    private final UserRepository users;
    private final AccountRepository accounts;
    private final TransferRepository transfers;
    private final JwtService jwtService;

    public Lab5DefaultAdminController(UserRepository users, AccountRepository accounts,
                                      TransferRepository transfers, JwtService jwtService) {
        this.users = users;
        this.accounts = accounts;
        this.transfers = transfers;
        this.jwtService = jwtService;
    }

    public record AdminLoginRequest(String username, String password) {
    }

    public record CreateAdminRequest(String username, String email, String password) {
    }

    public record ChangePasswordRequest(String username, String currentPassword, String newPassword) {
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AdminLoginRequest request) {
        User user = users.findByUsername(request.username()).orElse(null);

        // FIXED: [A02-Lab5] the credential check used to accept the default password
        // and the endpoint issued a fully privileged admin session token.
        // NOW: the password must be correct AND the account must no longer be
        //       flagged for a mandatory password change.
        if (user == null || !user.isAdmin()) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        if (!PasswordService.matches(request.password(), user.getPasswordHash())) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        // FIXED: [A02-Lab5] a seeded account whose password is still the factory
        // default must not be usable. Without this check the default credential
        // buys an attacker a permanent admin session.
        // NOW: refuse the login and tell the operator a change is required.
        if (user.mustChangePassword()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "error", "Password must be changed before this account can be used",
                    "must_change_password", true));
        }

        String token = jwtService.issue(user.getId(), user.getUsername(), user.getRole());

        return ResponseEntity.ok(LabResponses.map(
                "token", token,
                "user", LabResponses.map(
                        "id", user.getId(),
                        "username", user.getUsername(),
                        "role", user.getRole())));
    }

    @GetMapping("/users")
    public ResponseEntity<?> users() {
        List<User> all = users.findAll();
        return ResponseEntity.ok(Map.of("users", all.stream().map(user -> LabResponses.map(
                "id", user.getId(),
                "username", user.getUsername(),
                "email", user.getEmail(),
                "role", user.getRole())).toList()));
    }

    @GetMapping("/accounts")
    public ResponseEntity<?> accounts() {
        List<Account> all = accounts.findAll();
        return ResponseEntity.ok(Map.of("accounts", all.stream()
                .map(LabResponses::renderAccount).toList()));
    }

    @GetMapping("/transfers")
    public ResponseEntity<?> transfers() {
        List<Transfer> all = transfers.findAll();
        return ResponseEntity.ok(Map.of("transfers", all.stream()
                .map(LabResponses::renderTransfer).toList()));
    }

    /**
     * Creates a new administrator account, which demonstrates that access persists.
     */
    @PostMapping("/users")
    public ResponseEntity<?> createAdmin(@RequestBody CreateAdminRequest request) {
        CurrentUser caller = CurrentUserHolder.get();

        // FIXED: [A02-Lab5] Default Credentials - this endpoint used to accept a
        // create-admin request from ANY authenticated user, so a customer account
        // could mint itself an administrator and take over the whole back office.
        // NOW: the caller must hold the admin role. The role is taken from the
        //       verified JWT, never from the request body.
        if (caller == null || !caller.isAdmin()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Admin role required"));
        }

        if (users.findByUsername(request.username()).isPresent()) {
            return ResponseEntity.status(409).body(Map.of("error", "Username already exists"));
        }

        Map<String, Object> values = new HashMap<>();
        values.put("username", request.username());
        values.put("email", request.email());
        values.put("password_hash", PasswordService.md5(request.password()));
        values.put("role", "admin");
        values.put("full_name", request.username());
        values.put("sort_code", "20-00-00");
        values.put("must_change_password", Boolean.TRUE);

        Long newId = users.insert(values);

        return ResponseEntity.ok(Map.of(
                "created", true,
                "id", newId,
                "username", request.username(),
                "role", "admin"));
    }

    /**
     * Changes the caller's own password and clears the mandatory-change flag.
     */
    @PostMapping("/password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {
        // FIXED: [A02-Lab5] this endpoint used to require an admin session, but the
        // seeded administrator is refused a session until its password is changed,
        // so it could never clear the flag: the account locked itself out.
        // NOW: identity is proven by the username plus the current password, which
        //       is the only credential the account still has. The endpoint is on the
        //       AuthFilter's public list for the same reason.
        User user = users.findByUsername(request.username()).orElse(null);

        if (user == null || !user.isAdmin()
                || !PasswordService.matches(request.currentPassword(), user.getPasswordHash())) {
            return ResponseEntity.status(401).body(Map.of("error", "Current password is incorrect"));
        }

        if (request.newPassword() == null || request.newPassword().length() < 12) {
            return ResponseEntity.status(400)
                    .body(Map.of("error", "New password must be at least 12 characters"));
        }

        users.updatePasswordHash(user.getId(), PasswordService.md5(request.newPassword()));
        users.clearMustChangePassword(user.getId());

        return ResponseEntity.ok(Map.of("updated", true));
    }
}
