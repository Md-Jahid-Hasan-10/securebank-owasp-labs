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
     * Returns the profile of the authenticated user, with sensitive fields masked.
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

        // FIXED: [A04-Lab9] Cleartext Exposure of Sensitive Information - the account
        // number, sort code, email, balance and legal name used to be returned unmasked,
        // so every network observer could read them.
        // NOW: the response carries masked values only. The account number keeps its
        //       last four digits (ACC-****1001) and the sort code its first segment
        //       (20-**-**), which is enough for the customer to recognise their own
        //       account without disclosing it. The balance is dropped entirely: it is
        //       the one field that carries no identification value at all, and the
        //       dashboard serves it from the authenticated account endpoint.
        //       The email address is masked to its first character and domain.
        Map<String, Object> response = Map.of(
                "user_id", user.getId(),
                "full_name", maskName(user.getFullName()),
                "email", maskEmail(user.getEmail()),
                "account_number", account == null ? null : maskAccountNumber(account.getAccountNumber()),
                "sort_code", user.getSortCode() == null ? null : maskSortCode(user.getSortCode()),
                "currency", account == null ? null : account.getCurrency());

        // FIXED: [A04-Lab9] PII used to be written to the application log, where it
        // outlived the request and was visible to anyone with log access.
        // NOW: the log line records identifiers only - no name, account number,
        //       sort code, balance or email address. This is enough to correlate
        //       and audit the request without copying personal data into a system
        //       that was never meant to hold it.
        log.info("profile lookup for user={} user_id={}", user.getUsername(), user.getId());

        return ResponseEntity.ok(response);
    }

    /**
     * Masks an account number, keeping only the last four characters.
     *
     * <p>FIXED: [A04-Lab9] e.g. {@code ACC-1001} becomes {@code ACC-****1001}. The
     * prefix is preserved so the customer can tell which product the account belongs
     * to; the middle is replaced with asterisks.</p>
     */
    private static String maskAccountNumber(String accountNumber) {
        if (accountNumber == null || accountNumber.length() <= 4) {
            return "****";
        }
        String tail = accountNumber.substring(accountNumber.length() - 4);
        int dash = accountNumber.indexOf('-');
        if (dash > 0 && dash < accountNumber.length() - 4) {
            // Keep the product prefix (ACC-) and mask only the numbering.
            return accountNumber.substring(0, dash + 1) + "****" + tail;
        }
        return "****" + tail;
    }

    /**
     * Masks a sort code, keeping only the first segment.
     *
     * <p>FIXED: [A04-Lab9] e.g. {@code 20-00-00} becomes {@code 20-**-**}. The bank
     * identifier is not personal data and is useful for display, but the middle
     * segment is what identifies the branch and the account together.</p>
     */
    private static String maskSortCode(String sortCode) {
        if (sortCode == null || sortCode.isBlank()) {
            return null;
        }
        String[] parts = sortCode.split("-");
        if (parts.length < 3) {
            return "**-**";
        }
        return parts[0] + "-**-**";
    }

    /**
     * Masks a personal name, keeping only the first character of each word.
     *
     * <p>FIXED: [A04-Lab9] e.g. {@code Alice Morgan} becomes {@code A**** ******}. The
     * response is a self-service profile, so the caller is entitled to see their own
     * name - but the response may be cached, logged by a proxy or written to a
     * support ticket, and a masked value limits what leaks with it.</p>
     */
    private static String maskName(String fullName) {
        if (fullName == null || fullName.isBlank()) {
            return null;
        }
        StringBuilder masked = new StringBuilder();
        for (String word : fullName.trim().split("\\s+")) {
            if (masked.length() > 0) {
                masked.append(' ');
            }
            masked.append(word.charAt(0)).append("*".repeat(word.length() - 1));
        }
        return masked.toString();
    }

    /**
     * Masks an email address, keeping the first character and the domain.
     *
     * <p>FIXED: [A04-Lab9] e.g. {@code alice@bank.com} becomes {@code a****@bank.com}.
     * The domain is not personal data, and keeping it means the address is still
     * recognisable to its owner.</p>
     */
    private static String maskEmail(String email) {
        if (email == null || email.isBlank()) {
            return null;
        }
        int at = email.indexOf('@');
        if (at <= 0) {
            return "****";
        }
        String local = email.substring(0, at);
        return local.charAt(0) + "*".repeat(local.length() - 1) + email.substring(at);
    }
}
