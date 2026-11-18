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

    public record SendRequest(Long fromAccountId, Long toAccountId, String amount) {
    }

    /**
     * Sends a transfer, coercing the amount from a string.
     */
    @PostMapping("/send")
    public ResponseEntity<?> send(@RequestBody SendRequest request) {
        // VULN: [A10-Lab24] Error-Based Information Disclosure - the amount arrives as a
        // String and is converted with new BigDecimal(...) without any validation, so
        // "notanumber" raises a NumberFormatException. The exception detail is caught
        // and returned to the client verbatim, which names the offending parameter,
        // the internal variable names (amount, balance), the SQL query text with its
        // table and column names, and the Java types involved. That is a precise map
        // of the data model, which the attacker then uses to write a targeted
        // injection.
        // FIX:  validate at the input boundary and return a generic message:
        //       BigDecimal amount;
        //       try {
        //           amount = new BigDecimal(request.amount());
        //       } catch (NumberFormatException e) {
        //           return ResponseEntity.badRequest().body(Map.of("error", "Invalid amount"));
        //       }
        //       Better still, bind a BigDecimal in the request record so that Jackson
        //       performs the validation and rejects the request with a 400.
        BigDecimal amount;
        try {
            amount = new BigDecimal(request.amount());
        } catch (NumberFormatException | NullPointerException e) {
            // VULN: [A10-Lab24] the raw exception message AND the stack trace are
            // returned to the client.
            // FIX:  return a generic message and log the detail server-side.
            java.io.StringWriter sw = new java.io.StringWriter();
            e.printStackTrace(new java.io.PrintWriter(sw));
            return ResponseEntity.status(400).body(Map.of(
                    "error", "Could not process transfer",
                    "detail", e.getMessage(),
                    "parameter", "amount",
                    "type", e.getClass().getName(),
                    "stacktrace", sw.toString()));
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
