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
     * Dumps every user's password hash.
     */
    @GetMapping("/hashes")
    public ResponseEntity<?> hashes() {
        List<User> all = users.findAll();

        // VULN: [A04-Lab7] Cryptographic Failure - password hashes are returned to the client
        // in bulk, and the hashes themselves are unsalted MD5. Unsalted MD5 is effectively
        // plaintext: a single rainbow table attacks every account, and a modern GPU
        // tries billions of candidates per second.
        // FIX:  never expose hashes through an API at all. If they must be exposed for a
        //       legitimate reason, store bcrypt/Argon2id with a unique salt per user.
        return ResponseEntity.ok(Map.of(
                "algorithm", "MD5",
                "salted", false,
                "hashes", all.stream().map(user -> Map.of(
                        "id", user.getId(),
                        "username", user.getUsername(),
                        "password_hash", user.getPasswordHash())).toList()));
    }

    /**
     * Cracks a hash on request, which shows how trivial the offline attack is.
     */
    @GetMapping("/crack")
    public ResponseEntity<?> crack() {
        List<User> all = users.findAll();

        // VULN: [A04-Lab7] Cryptographic Failure - the endpoint performs an unsalted MD5
        // comparison against a small built-in word list, demonstrating in-process that
        // MD5 gives no protection whatsoever against offline guessing.
        // FIX:  replace MD5 with bcrypt/Argon2id so that each guess is expensive.
        java.util.Map<String, String> cracked = new java.util.LinkedHashMap<>();
        for (User user : all) {
            String found = bruteForce(user.getPasswordHash());
            cracked.put(user.getUsername(), found != null ? found : "(not found)");
        }

        return ResponseEntity.ok(Map.of(
                "note", "Unsalted MD5 is cracked in milliseconds. Compare with bcrypt, which "
                        + "deliberately makes each guess cost ~100ms of CPU.",
                "cracked", cracked));
    }

    private String bruteForce(String targetHash) {
        String[] candidates = {
                "password123", "qwerty", "admin", "charlie", "password", "letmein",
                "123456", "monkey", "dragon", "iloveyou", "trustno1", "baseball",
                "football", "shadow", "master", "hello", "freedom", "whatever",
                "qazwsx", "abc123", "welcome", "login", "starwars"
        };
        for (String candidate : candidates) {
            if (com.securebank.core.user.PasswordService.md5(candidate).equalsIgnoreCase(targetHash)) {
                return candidate;
            }
        }
        return null;
    }
}
