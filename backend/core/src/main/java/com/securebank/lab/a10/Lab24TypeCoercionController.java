package com.securebank.lab.a10;

import java.math.BigDecimal;
import java.util.Map;

import com.securebank.core.account.Account;
import com.securebank.core.account.AccountRepository;
import com.securebank.core.transfer.Transfer;
import com.securebank.core.transfer.TransferRepository;
import com.securebank.lab.common.LabResponses;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 24 — Error-Based Info Disclosure: Type Coercion</h2>
 * <p>OWASP A10 — Mishandling of Exceptional Conditions · Severity: Medium</p>
 *
 * <p><b>Objective:</b> send a string as an amount to trigger a type error that reveals
 * the application's internal data model.</p>
 */
@RestController
@RequestMapping("/api/a10/transfers")
public class Lab24TypeCoercionController {

    private final AccountRepository accounts;
    private final TransferRepository transfers;

    public Lab24TypeCoercionController(AccountRepository accounts, TransferRepository transfers) {
        this.accounts = accounts;
        this.transfers = transfers;
    }

    /**
     * FIXED: [A10-Lab24] The amount is now bound as a {@link BigDecimal} rather than
     * as a String that has to be coerced by hand. A value that is not a number is
     * rejected by the JSON binder before the controller runs, through the normal
     * error handling, so no exception is ever caught and re-described here.
     */
    public record SendRequest(Long fromAccountId, Long toAccountId, BigDecimal amount) {
    }

    /**
     * Sends a transfer.
     */
    @PostMapping("/send")
    public ResponseEntity<?> send(@RequestBody SendRequest request) {
        // FIXED: [A10-Lab24] Error-Based Information Disclosure - the amount used to
        // arrive as a String and be converted with new BigDecimal(...) without any
        // validation, so "notanumber" raised a NumberFormatException. The exception
        // detail was caught and returned to the client verbatim, which named the
        // offending parameter, the internal variable names (amount, balance), the
        // SQL query text with its table and column names, and the Java types
        // involved. That was a precise map of the data model, which the attacker
        // then uses to write a targeted injection.
        //
        // NOW: the amount is bound as a BigDecimal. A value that is not a number is
        // rejected by the binder with a 400 and a generic body - no detail, no type
        // name, no stack trace. The value is also validated against the business
        // rules, so a negative or zero amount is refused rather than executed.
        BigDecimal amount = request.amount();
        if (amount == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid amount"));
        }

        if (amount.signum() <= 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid amount"));
        }

        if (request.fromAccountId() == null || request.toAccountId() == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Account not found"));
        }

        if (request.fromAccountId().equals(request.toAccountId())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Accounts must differ"));
        }

        Account from = accounts.findById(request.fromAccountId()).orElse(null);
        Account to = accounts.findById(request.toAccountId()).orElse(null);

        if (from == null || to == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Account not found"));
        }

        from.setBalance(from.getBalance().subtract(amount));
        to.setBalance(to.getBalance().add(amount));
        accounts.updateBalance(from.getId(), from.getBalance());
        accounts.updateBalance(to.getId(), to.getBalance());

        Long id = transfers.insert(from.getId(), to.getId(), amount, null);
        Transfer stored = transfers.findById(id).orElse(null);

        return ResponseEntity.ok(LabResponses.map(
                "transfer_id", id,
                "amount", amount,
                "from_account", LabResponses.renderAccount(from),
                "to_account", LabResponses.renderAccount(to),
                "transfer", stored == null ? null : LabResponses.renderTransfer(stored)));
    }
}
