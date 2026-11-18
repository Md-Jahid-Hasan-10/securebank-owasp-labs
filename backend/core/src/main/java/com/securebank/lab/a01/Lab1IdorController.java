package com.securebank.lab.a01;

import java.util.List;
import java.util.Map;

import com.securebank.core.account.Account;
import com.securebank.core.account.AccountRepository;
import com.securebank.core.security.CurrentUser;
import com.securebank.core.security.CurrentUserHolder;
import com.securebank.core.transfer.Transfer;
import com.securebank.core.transfer.TransferRepository;
import com.securebank.lab.common.LabResponses;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 1 — IDOR: View Another Customer's Account</h2>
 * <p>OWASP A01 — Broken Access Control · Severity: Low</p>
 *
 * <p><b>Objective:</b> read account #ACC-1002 (bob's) while authenticated as alice.</p>
 *
 * <p>The endpoint authenticates the caller and then looks the account up purely by its
 * primary key. The account's {@code user_id} is never compared against the caller's
 * id, so any authenticated customer can read any other customer's balance and full
 * transaction history by changing the number in the URL.</p>
 */
@RestController
@RequestMapping("/api/a01/accounts")
public class Lab1IdorController {

    private final AccountRepository accounts;
    private final TransferRepository transfers;

    public Lab1IdorController(AccountRepository accounts, TransferRepository transfers) {
        this.accounts = accounts;
        this.transfers = transfers;
    }

    /**
     * Lists the signed-in customer's own accounts.
     *
     * <p>This endpoint IS correctly scoped - it always filters by the caller's id.
     * It exists so the dashboard has a legitimate way to obtain the account list,
     * which makes the flaw in {@link #accountDetail(Long)} stand out: the list is
     * filtered by owner, but fetching a single account by id is not.</p>
     */
    @GetMapping("/mine")
    public ResponseEntity<?> myAccounts() {
        CurrentUser caller = CurrentUserHolder.get();
        if (caller == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        List<Account> owned = accounts.findByUserId(caller.getId());

        return ResponseEntity.ok(LabResponses.map(
                "owner_user_id", caller.getId(),
                "accounts", owned.stream().map(LabResponses::renderAccount).toList()));
    }

    /**
     * Returns a single account by id, together with its transaction history.
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> accountDetail(@PathVariable Long id) {
        CurrentUser caller = CurrentUserHolder.get();

        // VULN: [A01-Lab1] IDOR / Broken Object Level Authorization - the account is fetched
        // by primary key only. The owning user_id is never compared with the authenticated
        // caller's id, so any logged-in customer can read any account in the system.
        // FIX:  load the account and reject the request unless account.user_id equals the
        //       authenticated caller's id, e.g.
        //       if (!Objects.equals(account.getUserId(), caller.getId())) {
        //           return ResponseEntity.status(HttpStatus.FORBIDDEN)
        //                   .body(Map.of("error", "Not your account"));
        //       }
        Account account = accounts.findById(id).orElse(null);

        if (account == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Account not found"));
        }

        List<Transfer> history = transfers.findByAccountId(account.getId());

        return ResponseEntity.ok(LabResponses.map(
                "account", LabResponses.renderAccount(account),
                "owner_user_id", account.getUserId(),
                "requested_by", caller == null ? null : caller.getUsername(),
                "transactions", history.stream().map(LabResponses::renderTransfer).toList()));
    }
}
