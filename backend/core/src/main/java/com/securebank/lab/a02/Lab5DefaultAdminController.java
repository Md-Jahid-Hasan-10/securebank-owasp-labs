package com.securebank.lab.a02;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.securebank.core.account.Account;
import com.securebank.core.account.AccountRepository;
import com.securebank.core.security.JwtService;
import com.securebank.core.transfer.Transfer;
import com.securebank.core.transfer.TransferRepository;
import com.securebank.core.user.PasswordService;
import com.securebank.core.user.User;
import com.securebank.core.user.UserRepository;
import com.securebank.lab.common.LabResponses;
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
     * VULN: [A02-Lab5] Default Credentials - the seeded administrator account still has the
     * factory password, so anyone who has read the seed script or the public repository
     * can log in as admin on a freshly deployed instance.
     * FIX:  force a password change on first login, or provision admin accounts from a
     *       secret manager with a generated password, and never ship default accounts.
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

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AdminLoginRequest request) {
        User user = users.findByUsername(request.username()).orElse(null);

        // VULN: [A02-Lab5] the credential check accepts the default password and the
        // endpoint issues a fully privileged admin session token.
        // FIX:  see the class-level note - never ship default credentials.
        if (user == null || !user.isAdmin()) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        if (!PasswordService.matches(request.password(), user.getPasswordHash())) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
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

        Long newId = users.insert(values);

        return ResponseEntity.ok(Map.of(
                "created", true,
                "id", newId,
                "username", request.username(),
                "role", "admin"));
    }
}
