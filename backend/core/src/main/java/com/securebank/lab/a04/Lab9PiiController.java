package com.securebank.lab.a04;

import java.util.Map;

import com.securebank.core.account.Account;
import com.securebank.core.account.AccountRepository;
import com.securebank.core.security.CurrentUser;
import com.securebank.core.security.CurrentUserHolder;
import com.securebank.core.user.User;
import com.securebank.core.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 9 — PII in Cleartext API Responses and Logs</h2>
 * <p>OWASP A04 — Cryptographic Failures · Severity: Low</p>
 *
 * <p><b>Objective:</b> observe full personal and financial data travelling in
 * plaintext, and see the same data persisted in the application log.</p>
 */
@RestController
@RequestMapping("/api/a04")
public class Lab9PiiController {

    private static final Logger log = LoggerFactory.getLogger(Lab9PiiController.class);

    private final UserRepository users;
    private final AccountRepository accounts;

    public Lab9PiiController(UserRepository users, AccountRepository accounts) {
        this.users = users;
        this.accounts = accounts;
    }

    /**
     * Returns the full profile of the authenticated user.
     */
    @GetMapping("/profile")
    public ResponseEntity<?> profile() {
        CurrentUser caller = CurrentUserHolder.get();
        Long userId = caller == null ? 1L : caller.getId();

        User user = users.findById(userId).orElse(null);
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Profile not found"));
        }

        Account account = accounts.findByUserId(user.getId()).stream().findFirst().orElse(null);

        // VULN: [A04-Lab9] Cleartext Exposure of Sensitive Information - the full account
        // number, sort code, email, balance and legal name are returned unmasked. Over plain
        // HTTP (which this lab runs on) every network observer can read them, and the data
        // is also written to the log below where it persists for the life of the log file.
        // FIX:  mask sensitive fields in responses (ACC-****1001, sort code 20-**-**),
        //       never log PII, and serve the API exclusively over TLS.
        Map<String, Object> response = Map.of(
                "user_id", user.getId(),
                "full_name", user.getFullName(),
                "email", user.getEmail(),
                "account_number", account == null ? null : account.getAccountNumber(),
                "sort_code", user.getSortCode(),
                "balance", account == null ? null : account.getBalance(),
                "currency", account == null ? null : account.getCurrency());

        // VULN: [A04-Lab9] PII is also written to the application log, where it outlives
        // the request and is visible to anyone with log access (or a log aggregation
        // system that was never intended to hold personal data).
        // FIX:  log identifiers only, never names, account numbers, balances or emails.
        log.info("profile lookup for user={} account_number={} sort_code={} balance={}",
                user.getUsername(),
                account == null ? null : account.getAccountNumber(),
                user.getSortCode(),
                account == null ? null : account.getBalance());

        return ResponseEntity.ok(response);
    }
}
