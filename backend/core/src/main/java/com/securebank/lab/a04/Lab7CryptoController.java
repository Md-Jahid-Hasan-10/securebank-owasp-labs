package com.securebank.lab.a04;

import java.util.List;
import java.util.Map;

import com.securebank.core.user.User;
import com.securebank.core.user.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 7 — MD5 Password Hashing: Crack with Hashcat</h2>
 * <p>OWASP A04 — Cryptographic Failures · Severity: Medium</p>
 *
 * <p><b>Objective:</b> obtain a user's password hash and crack it offline.</p>
 *
 * <p>The hash store is exposed verbatim. The hashes are unsalted MD5, so
 * {@code hashcat -m 0 hashes.txt rockyou.txt} recovers the password in seconds.</p>
 */
@RestController
@RequestMapping("/api/a04")
public class Lab7CryptoController {

    private final UserRepository users;

    public Lab7CryptoController(UserRepository users) {
        this.users = users;
    }

    /**
     * Lists the accounts in the system.
     *
     * <p>FIXED: [A04-Lab7] Cryptographic Failure - the hashes are no longer returned
     * in bulk. Even with bcrypt, handing every stored hash to a client gives an
     * attacker an offline target and a reason to keep attacking it, so the
     * endpoint no longer exposes them at all.</p>
     */
    @GetMapping("/hashes")
    public ResponseEntity<?> hashes() {
        List<User> all = users.findAll();

        // FIXED: [A04-Lab7] Cryptographic Failure - the password hashes are redacted.
        // The endpoint used to return every user's unsalted MD5 digest in bulk,
        // which is effectively plaintext: a single rainbow table attacks every
        // account, and a modern GPU tries billions of candidates per second.
        return ResponseEntity.ok(Map.of(
                "algorithm", "bcrypt",
                "salted", true,
                "hashes", all.stream().map(user -> Map.of(
                        "id", user.getId(),
                        "username", user.getUsername(),
                        "password_hash", "(redacted)")).toList()));
    }

    /**
     * The endpoint that used to crack the stored hashes on request.
     *
     * <p>FIXED: [A04-Lab7] Cryptographic Failure - the in-process cracker is gone.
     * It compared a small built-in word list against an unsalted MD5 digest, which
     * demonstrated in-process that MD5 gave no protection whatsoever against
     * offline guessing. Against bcrypt the same word list would cost ~100ms per
     * candidate, and the server has no reason to attempt to crack its own password
     * hashes in the first place.</p>
     */
    @GetMapping("/crack")
    public ResponseEntity<?> crack() {
        // FIXED: [A04-Lab7] Cryptographic Failure - the endpoint no longer cracks the
        // stored hashes. It used to perform an unsalted MD5 comparison against a
        // small built-in word list, taking microseconds per candidate.
        return ResponseEntity.ok(Map.of(
                "note", "Password hashes are stored with bcrypt, which makes each "
                        + "verification attempt cost ~100ms of CPU and uses a unique "
                        + "salt per user.",
                "cracked", Map.of()));
    }
}
