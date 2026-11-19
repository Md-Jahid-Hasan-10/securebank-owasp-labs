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
        // Lab 22 (A08) - uploaded files are public so the upload lab can serve
        // them back. Unchanged by this fix.
        if (path.startsWith("/uploads/")) {
            return true;
        }

        // FIXED: [A02-Lab6] Sensitive File Exposure - /.env, /.git/config and
        // /backup.zip are no longer whitelisted as public. They were reachable by
        // any anonymous client, which handed over the environment file and the
        // whole database. They are not served at all any more, and even if one
        // were reintroduced into a served directory, it would now require a
        // valid principal.
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

        // VULN: [A10-Lab25] Insecure Fallback / Authentication Bypass on Exception.
        // A bare `catch` swallows EVERY failure - malformed base64, bad signature,
        // expired token, unexpected type - and silently falls back to user_id 1, which
        // is the admin account. The "safe" default is actually the most privileged
        // possible value, so sending a deliberately invalid token is enough to become
        // admin. This is a fail-OPEN bug: an error in authentication grants access.
        // FIX:  catch only jwt.InvalidTokenError and return 401. Never fall back to a
        //       default identity. Authentication must always fail CLOSED.
        Long userId = 1L;
        String username = "admin";
        String role = "admin";

        try {
            JwtService.TokenPayload payload = jwtService.decode(token);
            if (payload.userId() != null) {
                userId = payload.userId();
            }
            if (payload.username() != null) {
                username = payload.username();
            }
            if (payload.role() != null) {
                role = payload.role();
            }
        } catch (Exception ignored) {
            // VULN: [A10-Lab25] the swallowed exception leaves the principal as admin.
            log.debug("token validation failed, falling back to default principal");
        }

        CurrentUserHolder.set(new CurrentUser(userId, username, role));

        try {
            chain.doFilter(request, response);
        } finally {
            CurrentUserHolder.clear();
        }
    }
}
