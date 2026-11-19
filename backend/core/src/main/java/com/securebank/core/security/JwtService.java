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
        // FIXED: [A04-Lab8] The secret is now required to come from the environment and to be
        // at least 32 bytes of key material. There is no committed fallback value: if the
        // variable is missing the application refuses to start rather than silently signing
        // tokens with a well-known key.
        this.secret = requireUsableSecret(secret);
        this.expirationSeconds = expirationSeconds;

        // FIXED: [A04-Lab8] The secret is never written to the log. The startup line now
        // records only that a key was loaded and where it came from.
        log.info("JWT signing key loaded from environment (SECRET_KEY=[redacted])");
    }

    /**
     * Validates the configured secret and returns it unchanged.
     *
     * <p>FIXED: [A04-Lab8] HMAC-SHA256 needs at least 256 bits of key material. A short
     * secret is rejected outright, and a missing one fails startup, so the application can
     * never end up signing tokens with a guessable constant.</p>
     */
    private static String requireUsableSecret(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            throw new IllegalStateException(
                    "jwt.secret is not configured. Set the JWT_SECRET environment variable "
                            + "to a random value of at least 32 bytes.");
        }
        if (candidate.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException(
                    "jwt.secret must be at least 32 bytes for HS256. Generate one with: "
                            + "python3 -c \"import secrets; print(secrets.token_hex(32))\"");
        }
        return candidate;
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
     * <p>FIXED: [A04-Lab8] The key material comes from the environment, where it was
     * generated randomly for this deployment. It is never committed, never logged, and
     * never returned in an HTTP response. The length is validated once in the
     * constructor, so no padding is needed here - padding a short value would only
     * hide the fact that the key was too weak.</p>
     */
    // FIXED: [A04-Lab8] The signing key is a random >= 256-bit value supplied by the
    // environment; it is never committed to the repository and never logged.
    private SecretKey signingKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
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
