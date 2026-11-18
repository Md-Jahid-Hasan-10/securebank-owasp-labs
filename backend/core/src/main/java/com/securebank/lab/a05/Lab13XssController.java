package com.securebank.lab.a05;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import com.securebank.core.account.Account;
import com.securebank.core.account.AccountRepository;
import com.securebank.core.transfer.Transfer;
import com.securebank.core.transfer.TransferRepository;
import com.securebank.lab.common.LabResponses;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 13 — Stored XSS: Transaction Notes</h2>
 * <p>OWASP A05 — Injection · Severity: Medium</p>
 *
 * <p><b>Objective:</b> store an XSS payload that fires for every user viewing the
 * transfers page.</p>
 */
@RestController
@RequestMapping("/api/a05/transfers")
public class Lab13XssController {

    private final TransferRepository transfers;
    private final AccountRepository accounts;

    public Lab13XssController(TransferRepository transfers, AccountRepository accounts) {
        this.transfers = transfers;
        this.accounts = accounts;
    }

    public record SendTransferRequest(Long fromAccountId, Long toAccountId, BigDecimal amount, String note) {
    }

    /**
     * Creates a transfer, storing the note verbatim.
     */
    @PostMapping("/send")
    public ResponseEntity<?> send(@RequestBody SendTransferRequest request) {
        Account from = accounts.findById(request.fromAccountId()).orElse(null);
        Account to = accounts.findById(request.toAccountId()).orElse(null);

        if (from == null || to == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Account not found"));
        }

        if (request.amount() == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Amount is required"));
        }

        from.setBalance(from.getBalance().subtract(request.amount()));
        to.setBalance(to.getBalance().add(request.amount()));
        accounts.updateBalance(from.getId(), from.getBalance());
        accounts.updateBalance(to.getId(), to.getBalance());

        // VULN: [A05-Lab13] Stored XSS - the note is persisted exactly as supplied, with
        // no escaping and no sanitisation. The frontend later renders it with
        // dangerouslySetInnerHTML, so the payload executes in every victim's browser
        // that loads the transfers page.
        // FIX:  sanitise on write AND on render. The safest fix is to not use
        //       dangerouslySetInnerHTML for user data at all - render it as text.
        //       If HTML must be supported, sanitise with DOMPurify on the client.
        Long id = transfers.insert(from.getId(), to.getId(), request.amount(), request.note());

        Transfer stored = transfers.findById(id).orElse(null);

        return ResponseEntity.ok(LabResponses.map(
                "transfer_id", id,
                "from_balance", from.getBalance(),
                "to_balance", to.getBalance(),
                "transfer", stored == null ? null : LabResponses.renderTransfer(stored)));
    }

    /**
     * Lists every transfer, including the notes of other customers.
     */
    @GetMapping
    public ResponseEntity<?> list() {
        List<Transfer> all = transfers.findAll();
        return ResponseEntity.ok(Map.of(
                "transfers", all.stream().map(LabResponses::renderTransfer).toList()));
    }
}
