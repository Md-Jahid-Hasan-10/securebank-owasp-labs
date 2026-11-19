package com.securebank.core.security;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

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
        // FIXED: [A08-Lab21] The token now carries an expiry. Without it a stolen token
        // stayed valid forever, so there was no window in which a leak could be closed
        // by waiting the credential out.
        Instant expiry = Instant.now().plusSeconds(expirationSeconds);
        return Jwts.builder()
                .claim("user_id", userId)
                .claim("username", username)
                .claim("role", role)
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(expiry))
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
     * <p>FIXED: [A08-Lab21] JWT Algorithm Confusion - the old code read the token's
     * own header, saw {@code "alg": "none"} and then trusted the payload without any
     * signature check at all. The header is entirely attacker-controlled, so removing
     * the signature was enough to become admin.</p>
     *
     * <p>NOW: the token is always parsed by the strict parser, which pins HS256,
     * verifies the signature against the environment-supplied key and enforces the
     * expiry. The header is never branched on, so there is no algorithm to confuse.
     * A token whose header asks for anything other than the pinned algorithm fails
     * the signature check, and an unsigned token fails it too, because there is no
     * signature to verify.</p>
     */
    public TokenPayload decode(String token) {
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
}
