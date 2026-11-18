package com.securebank.lab.a06;

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
 * <h2>Lab 14 — Business Logic: Negative Transfer Amount</h2>
 * <p>OWASP A06 — Insecure Design · Severity: Medium</p>
 *
 * <p><b>Objective:</b> create money from nothing by sending a negative transfer.</p>
 */
@RestController
@RequestMapping("/api/a06/transfers")
public class Lab14BusinessLogicController {

    private final AccountRepository accounts;
    private final TransferRepository transfers;

    public Lab14BusinessLogicController(AccountRepository accounts, TransferRepository transfers) {
        this.accounts = accounts;
        this.transfers = transfers;
    }

    public record TransferRequest(Long fromAccountId, Long toAccountId, BigDecimal amount) {
    }

    /**
     * Moves money between two accounts.
     */
    @PostMapping("/")
    public ResponseEntity<?> transfer(@RequestBody TransferRequest request) {
        Account from = accounts.findById(request.fromAccountId()).orElse(null);
        Account to = accounts.findById(request.toAccountId()).orElse(null);

        if (from == null || to == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Account not found"));
        }

        BigDecimal amount = request.amount();
        if (amount == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Amount is required"));
        }

        // VULN: [A06-Lab14] Insecure Design / Business Logic Flaw - the amount is checked
        // for presence but never for sign. A negative amount subtracts a negative value
        // from the sender (increasing their balance) and adds a negative value to the
        // recipient (decreasing theirs), so the attacker creates money simply by
        // choosing a negative number.
        // FIX:  validate the amount as strictly positive at the input boundary:
        //       if (amount.signum() <= 0) {
        //           throw new ValidationException("Amount must be positive");
        //       }
        //       This is an insecure DESIGN flaw rather than a coding error - the rule
        //       that a transfer must move a positive sum was never written down, so no
        //       individual line was ever wrong.
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
