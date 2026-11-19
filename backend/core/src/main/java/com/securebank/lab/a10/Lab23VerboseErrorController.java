package com.securebank.lab.a10;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.securebank.core.account.Account;
import com.securebank.core.account.AccountRepository;
import com.securebank.core.transfer.Transfer;
import com.securebank.core.transfer.TransferRepository;
import com.securebank.lab.common.LabResponses;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 23 — Verbose Error: Stack Trace with Config Values</h2>
 * <p>OWASP A10 — Mishandling of Exceptional Conditions · Severity: Low</p>
 *
 * <p><b>Objective:</b> trigger an unhandled exception to extract internal
 * configuration.</p>
 */
@RestController
@RequestMapping("/api/a10/transfers")
public class Lab23VerboseErrorController {

    private final AccountRepository accounts;
    private final TransferRepository transfers;
    private final Environment environment;

    public Lab23VerboseErrorController(AccountRepository accounts, TransferRepository transfers,
                                       Environment environment) {
        this.accounts = accounts;
        this.transfers = transfers;
        this.environment = environment;
    }

    /**
     * Returns a summary of an account's transfers.
     */
    @GetMapping("/account-summary")
    public ResponseEntity<?> accountSummary(@RequestParam("id") String id) {
        // VULN: [A10-Lab23] Mishandling of Exceptional Conditions - the id is converted
        // to an integer without any validation or error handling, so "abc" raises an
        // unhandled NumberFormatException. Because server.error.include-stacktrace is
        // 'always', the full stack trace is rendered back to the client, revealing file
        // paths, library versions, the Spring configuration (including jwt.secret and
        // the datasource URL) and the internal call chain.
        // FIX:  validate the input and handle the conversion explicitly:
        //       int accountId;
        //       try {
        //           accountId = Integer.parseInt(id);
        //       } catch (NumberFormatException e) {
        //           return ResponseEntity.badRequest().body(Map.of("error", "Invalid id"));
        //       }
        //       and set server.error.include-stacktrace=never in production.
        int accountId = Integer.parseInt(id);

        Account account = accounts.findById((long) accountId).orElse(null);
        if (account == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Account not found"));
        }

        java.util.List<Transfer> history = transfers.findByAccountId(account.getId());

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("account", LabResponses.renderAccount(account));
        summary.put("transfer_count", history.size());
        summary.put("total_in", history.stream()
                .filter(t -> t.getToAccountId().equals(account.getId()))
                .map(t -> t.getAmount())
                .reduce(BigDecimalHolder.ZERO, BigDecimalHolder::add));
        summary.put("total_out", history.stream()
                .filter(t -> t.getFromAccountId().equals(account.getId()))
                .map(t -> t.getAmount())
                .reduce(BigDecimalHolder.ZERO, BigDecimalHolder::add));

        return ResponseEntity.ok(summary);
    }

    /**
     * Helper for summing transfer amounts.
     */
    static final class BigDecimalHolder {
        static final java.math.BigDecimal ZERO = java.math.BigDecimal.ZERO;

        private BigDecimalHolder() {
        }

        static java.math.BigDecimal add(java.math.BigDecimal a, java.math.BigDecimal b) {
            return a.add(b);
        }
    }

    /**
     * Returns the full transfer history.
     *
     * <p>This endpoint is what Lab 25 targets: with a valid token it returns the
     * caller's data, and with a deliberately malformed token the auth filter's
     * fail-open fallback hands the request to the admin principal instead.</p>
     */
    @GetMapping("/history")
    public ResponseEntity<?> history() {
        com.securebank.core.security.CurrentUser caller =
                com.securebank.core.security.CurrentUserHolder.get();

        List<Transfer> all = transfers.findAll();

        return ResponseEntity.ok(Map.of(
                "requested_by", caller == null ? null : caller.getUsername(),
                "requested_role", caller == null ? null : caller.getRole(),
                "transfers", all.stream().map(LabResponses::renderTransfer).toList()));
    }

    /**
     * Shows what the stack trace reveals, for reference.
     */
    @GetMapping("/leak-preview")
    public ResponseEntity<?> leakPreview() {
        Map<String, Object> leak = new LinkedHashMap<>();
        leak.put("server.error.include-stacktrace", environment.getProperty("server.error.include-stacktrace"));
        // FIXED: [A10-Lab23] The signing secret is never echoed in a response body.
        leak.put("jwt.secret", environment.getProperty("jwt.secret") == null ? null : "[redacted]");
        leak.put("spring.datasource.url", environment.getProperty("spring.datasource.url"));
        leak.put("tip", "Request /api/a10/transfers/account-summary?id=abc for the real thing.");
        return ResponseEntity.ok(leak);
    }
}
