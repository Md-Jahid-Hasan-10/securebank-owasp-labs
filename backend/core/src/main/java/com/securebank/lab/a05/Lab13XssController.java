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
import org.springframework.web.util.HtmlUtils;

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

        // FIXED: [A05-Lab13] Stored XSS - the note used to be persisted exactly as
        // supplied, with no escaping and no sanitisation, and the frontend rendered it
        // with dangerouslySetInnerHTML, so a payload executed in every victim's
        // browser that loaded the transfers page.
        //
        // NOW: the note is sanitised on write AND the frontend renders it as text
        // rather than as markup. Sanitising on write alone would leave any note
        // stored before the fix still dangerous, so both halves matter: the client
        // treats the value as plain text, and the server refuses to store markup in
        // the first place.
        Long id = transfers.insert(from.getId(), to.getId(), request.amount(),
                sanitise(request.note()));

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

    /**
     * Strips anything that could be interpreted as markup from a note.
     *
     * <p>FIXED: [A05-Lab13] The note is a text field, so it should never contain
     * HTML. The tags and the event handlers inside them are removed, and the
     * remaining angle brackets are escaped so the value can be displayed safely
     * even by a client that has not been updated yet.</p>
     */
    private static String sanitise(String note) {
        if (note == null || note.isBlank()) {
            return note;
        }
        String withoutTags = note.replaceAll("<[^>]*>", "");
        return HtmlUtils.htmlEscape(withoutTags);
    }
}
