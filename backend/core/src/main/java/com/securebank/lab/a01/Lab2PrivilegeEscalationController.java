package com.securebank.lab.a01;

import java.util.List;
import java.util.Map;

import com.securebank.core.account.Account;
import com.securebank.core.account.AccountRepository;
import com.securebank.core.security.CurrentUser;
import com.securebank.core.security.CurrentUserHolder;
import com.securebank.core.user.User;
import com.securebank.core.user.UserRepository;
import com.securebank.lab.common.LabResponses;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 2 — Privilege Escalation: Customer → Admin</h2>
 * <p>OWASP A01 — Broken Access Control · Severity: Medium</p>
 *
 * <p><b>Objective:</b> call the admin user-management endpoint as a regular customer.</p>
 */
@RestController
@RequestMapping("/api/a01/admin")
public class Lab2PrivilegeEscalationController {

    private final UserRepository users;
    private final AccountRepository accounts;

    public Lab2PrivilegeEscalationController(UserRepository users, AccountRepository accounts) {
        this.users = users;
        this.accounts = accounts;
    }

    /**
     * Lists every user in the system, including password hashes.
     */
    @GetMapping("/users")
    public ResponseEntity<?> users() {
        CurrentUser caller = CurrentUserHolder.get();

        // VULN: [A01-Lab2] Privilege Escalation / Missing Function Level Access Control -
        // the endpoint is reachable by any authenticated principal. It confirms that a
        // token exists but never checks that the token carries the admin role, so a
        // regular customer can enumerate every account, discover which users are
        // admins, and read their password hashes.
        // FIX:  require the admin role, e.g. in an @RequireRole("admin") annotation:
        //       if (!"admin".equals(caller.getRole())) {
        //           return ResponseEntity.status(HttpStatus.FORBIDDEN)
        //                   .body(Map.of("error", "Admin role required"));
        //       }
        List<User> all = users.findAll();

        return ResponseEntity.ok(LabResponses.map(
                "requested_by", caller == null ? null : caller.getUsername(),
                "requested_role", caller == null ? null : caller.getRole(),
                "users", all.stream().map(user -> LabResponses.map(
                        "id", user.getId(),
                        "username", user.getUsername(),
                        "email", user.getEmail(),
                        "password_hash", user.getPasswordHash(),
                        "role", user.getRole())).toList()));
    }

    /**
     * Lists every account in the system.
     */
    @GetMapping("/accounts")
    public ResponseEntity<?> accounts() {
        CurrentUser caller = CurrentUserHolder.get();

        // VULN: [A01-Lab2] the same missing role check as /users - every customer can
        // list every account and its balance.
        // FIX:  require the admin role before returning the list.
        List<Account> all = accounts.findAll();

        return ResponseEntity.ok(LabResponses.map(
                "requested_by", caller == null ? null : caller.getUsername(),
                "requested_role", caller == null ? null : caller.getRole(),
                "accounts", all.stream().map(account -> LabResponses.map(
                        "id", account.getId(),
                        "owner_user_id", account.getUserId(),
                        "account_number", account.getAccountNumber(),
                        "balance", account.getBalance(),
                        "currency", account.getCurrency())).toList()));
    }
}
