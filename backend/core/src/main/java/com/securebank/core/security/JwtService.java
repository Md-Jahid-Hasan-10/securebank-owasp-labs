package com.securebank.core.security;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * Issues and validates the JWTs used by the banking API.
 */
@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    private final String secret;
    private final long expirationSeconds;

    public JwtService(@Value("${jwt.secret}") String secret,
                      @Value("${jwt.expiration-seconds:3600}") long expirationSeconds) {
        this.secret = secret;
        this.expirationSeconds = expirationSeconds;

        // VULN: [A04-Lab8] Hardcoded Weak JWT Secret - the signing key is a trivially guessable
        // literal from the shipped application.yml, and it is echoed to the application log
        // at startup. Anyone with repo access, log access, or the exposed .env file (Lab 6)
        // can mint a token for any user, including admin.
        // FIX:  load a >= 256-bit random secret from an environment variable or a secret
        //       manager at startup, never from a committed file, and never log it.
        log.info("JWT signing key loaded (SECRET_KEY={})", secret);
    }

    /**
     * The decoded contents of a token.
     */
    public record TokenPayload(Long userId, String username, String role) {
    }

    /**
     * Signs a token for the given user.
     */
    public String issue(Long userId, String username, String role) {
        return Jwts.builder()
                .claim("user_id", userId)
                .claim("username", username)
                .claim("role", role)
                .signWith(signingKey(), Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Strictly validates a token: signature, algorithm and expiry are all enforced.
     *
     * <p>Used by the endpoints that are not part of a security lab.</p>
     */
    public Claims decodeStrict(String token) {
        return Jwts.parser()
                .verifyWith(signingKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Builds the HMAC signing key.
     *
     * <p>VULN: [A04-Lab8] the key material comes from a literal in the committed
     * application.yml, so it is known to anyone with repository access - and it is
     * echoed to the log at startup, so it is known to anyone with log access too.
     * The value is long enough to satisfy the JWA key-length rules (so the token is
     * a well-formed HS256 token) but it is a well-known constant, not a secret.</p>
     *
     * <p>FIX: generate a random secret per deployment - for example
     * {@code secrets.token_hex(32)} - and read it from the environment or a secret
     * manager. Never commit it, and never log it.</p>
     */
    // VULN: [A04-Lab8] Hardcoded Weak JWT Secret - a committed, well-known signing key
    // FIX:  load a >= 256-bit random secret from the environment; never commit it
    private SecretKey signingKey() {
        // The literal is padded to the 32-byte minimum that HS256 requires. The
        // padding is not secret - the whole value is published in application.yml,
        // in .env (Lab 6) and in the startup log.
        byte[] material = secret.getBytes(StandardCharsets.UTF_8);
        if (material.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(material, 0, padded, 0, material.length);
            for (int i = material.length; i < padded.length; i++) {
                padded[i] = '0';
            }
            material = padded;
        }
        return Keys.hmacShaKeyFor(material);
    }

    /**
     * Validates a token the way the application actually does at runtime.
     *
     * <p>VULN: [A08-Lab21] JWT Algorithm Confusion - a token whose header declares
     * {@code "alg": "none"} is accepted without any signature verification at all. The
     * header is attacker-controlled, so the attacker simply claims to be admin and
     * removes the signature.</p>
     *
     * <p>FIX: always verify the signature with a pinned algorithm list, e.g.
     * {@code Jwts.parser().verifyWith(key).build().parseSignedClaims(token)}, and
     * explicitly reject tokens whose header algorithm is not in the allowed set.</p>
     */
    public TokenPayload decode(String token) {
        try {
            String header = decodeSegment(token, 0);
            Map<String, Object> headerJson = parseJsonObject(header);

            Object alg = headerJson.get("alg");
            if ("none".equalsIgnoreCase(String.valueOf(alg))) {
                // VULN: [A08-Lab21] JWT Algorithm Confusion - unsigned token accepted as valid.
                // The payload is trusted verbatim, so the attacker becomes whoever they claim.
                // FIX:  reject "none" outright, or better, never branch on the token's own header.
                Map<String, Object> claims = parseJsonObject(decodeSegment(token, 1));
                return new TokenPayload(
                        asLong(claims.get("user_id")),
                        asString(claims.get("username")),
                        asString(claims.get("role")));
            }
        } catch (RuntimeException ignored) {
            // Fall through to the strict path - a malformed token is not a "none" token.
        }
        Claims claims = decodeStrict(token);
        return new TokenPayload(
                asLong(claims.get("user_id")),
                asString(claims.get("username")),
                asString(claims.get("role")));
    }

    private static Long asLong(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(String.valueOf(value));
    }

    private static String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private String decodeSegment(String token, int index) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("malformed token");
        }
        Base64.Decoder decoder = Base64.getUrlDecoder();
        byte[] decoded = decoder.decode(padBase64(parts[index]));
        return new String(decoded, StandardCharsets.UTF_8);
    }

    private String padBase64(String value) {
        int padding = value.length() % 4;
        if (padding == 0) {
            return value;
        }
        return value + "=".repeat(4 - padding);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseJsonObject(String json) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper()
                    .readValue(json, HashMap.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("malformed token segment", e);
        }
    }
}
