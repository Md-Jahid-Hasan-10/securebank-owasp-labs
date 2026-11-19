package com.securebank.core.security;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;

import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Resolves the authenticated principal for protected endpoints.
 *
 * <p>Spring Security is deliberately not used in this project, so all authentication
 * behaviour is explicit here and in {@link JwtService}.</p>
 */
@Component
public class AuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    private final JwtService jwtService;

    public AuthFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /**
     * Endpoints that must never be gated. Everything else requires a valid principal.
     */
    private static boolean isPublic(String path) {
        // FIXED: [A02-Lab6] Sensitive File Exposure - /.env, /.git/config and
        // /backup.zip are no longer whitelisted as public. They were reachable by
        // any anonymous client, which handed over the environment file and the
        // whole database. They are not served at all any more, and even if one
        // were reintroduced into a served directory, it would now require a
        // valid principal.
        //
        // FIXED: [A08-Lab22] Unrestricted File Upload - "/uploads/" is no longer
        // whitelisted. Uploaded files used to be served anonymously from a static
        // handler; they now live outside the web root and are downloaded through an
        // authenticated endpoint that sets Content-Disposition: attachment.
        return path.startsWith("/api/auth/")
                || path.startsWith("/api/a05/auth/")
                || path.startsWith("/api/a06/auth/")
                || path.startsWith("/api/a07/auth/")
                || path.startsWith("/api/a07/session/")
                || path.startsWith("/api/labs")
                || path.startsWith("/api/a02/admin/login")
                // FIXED: [A02-Lab5] the password-change endpoint has to be reachable
                // without a session: the seeded administrator is refused a session
                // until its password is changed, so it could never clear the flag.
                // Identity is proven by the current password instead of a token.
                || path.startsWith("/api/a02/admin/password")
                || path.startsWith("/api/a02/exposed-files")
                || path.startsWith("/api/a10/transfers/account-summary")
                || path.startsWith("/api/report/")
                || path.equals("/api/health")
                || path.startsWith("/actuator")
                || path.startsWith("/h2-console");
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String path = request.getRequestURI();

        if (isPublic(path)) {
            chain.doFilter(request, response);
            return;
        }

        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            // No credential supplied at all - this is a legitimate unauthenticated request.
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Authentication required\"}");
            return;
        }

        String token = header.substring("Bearer ".length()).trim();

        // FIXED: [A10-Lab25] Insecure Fallback / Authentication Bypass on Exception.
        // A bare `catch` swallowed EVERY failure - malformed base64, bad signature,
        // expired token, unexpected type - and silently fell back to user_id 1, which
        // is the admin account. The "safe" default was actually the most privileged
        // possible value, so sending a deliberately invalid token was enough to become
        // admin. This was a fail-OPEN bug: an error in authentication granted access.
        //
        // NOW: the principal is built ONLY from a successfully verified token. There is
        // no default identity and no catch-all - a token that cannot be verified is
        // rejected with 401. Authentication always fails CLOSED.
        JwtService.TokenPayload payload;
        try {
            payload = jwtService.decode(token);
        } catch (io.jsonwebtoken.JwtException | IllegalArgumentException e) {
            // Malformed, unsigned, tampered-with or expired token. The reason is logged
            // for the operator but never returned to the caller.
            log.warn("token validation failed: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Invalid token\"}");
            return;
        }

        if (payload.userId() == null) {
            // FIXED: [A10-Lab25] a token without a subject cannot identify anybody, so
            // it must not be allowed to produce a principal at all.
            log.warn("token validation failed: token carries no user id");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Invalid token\"}");
            return;
        }

        CurrentUserHolder.set(new CurrentUser(
                payload.userId(),
                payload.username() == null ? "" : payload.username(),
                payload.role() == null ? "user" : payload.role()));

        try {
            chain.doFilter(request, response);
        } finally {
            CurrentUserHolder.clear();
        }
    }
}
