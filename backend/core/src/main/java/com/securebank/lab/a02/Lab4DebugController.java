package com.securebank.lab.a02;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.securebank.core.security.CurrentUser;
import com.securebank.core.security.CurrentUserHolder;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 4 — Debug Mode: Stack Trace Exposes Config</h2>
 * <p>OWASP A02 — Security Misconfiguration · Severity: Low</p>
 *
 * <p><b>Objective:</b> trigger an unhandled exception to view the application's
 * internal state, including the JWT signing secret.</p>
 *
 * <p>This is the Spring Boot analogue of Django's {@code DEBUG = True}.</p>
 */
@RestController
@RequestMapping("/api/a02")
public class Lab4DebugController {

    private final Environment environment;

    public Lab4DebugController(Environment environment) {
        this.environment = environment;
    }

    /**
     * Prints a snapshot of the resolved application configuration.
     */
    @GetMapping("/debug")
    public ResponseEntity<?> debug() {
        CurrentUser caller = CurrentUserHolder.get();

        // FIXED: [A02-Lab4] Security Misconfiguration / Information Disclosure - the
        // endpoint used to dump the entire resolved application configuration to any
        // caller, including the JWT signing secret and the database connection
        // string. Combined with server.error.include-stacktrace=always (which made
        // every unhandled error equally verbose) this handed an attacker the keys to
        // the whole application: the secret from Lab 8 forges tokens, and the
        // datasource URL points at the database that Lab 6 also dumps.
        // NOW: the endpoint requires the admin role, and it never returns a secret.
        //       jwt.secret and the datasource credentials are gone from the response
        //       entirely - no secret should ever travel in an HTTP response, not
        //       even to an administrator.
        if (caller == null || !caller.isAdmin()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Admin role required"));
        }

        Map<String, Object> config = new LinkedHashMap<>();

        // Only non-secret diagnostics. The signing secret and the datasource
        // credentials are deliberately absent.
        config.put("server.error.include-stacktrace", environment.getProperty("server.error.include-stacktrace"));
        config.put("jwt.expiration-seconds", environment.getProperty("jwt.expiration-seconds"));
        config.put("spring.jackson.default-typing", environment.getProperty("spring.jackson.default-typing"));

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("debug", true);
        response.put("requested_by", caller.getUsername());
        response.put("active_profiles", List.of(environment.getActiveProfiles()));
        response.put("config", config);

        return ResponseEntity.ok(response);
    }

    /**
     * Deliberately throws so that the verbose error handler renders.
     *
     * <p>FIXED: [A02-Lab4] Security Misconfiguration - the endpoint used to be
     * reachable without authentication and the resulting 500 response was rendered
     * by {@link Lab4ErrorController}, which returned the full stack trace and a
     * configuration snapshot. The exception is now handled locally and only a
     * generic message is returned.</p>
     */
    @GetMapping("/debug/boom")
    public ResponseEntity<?> boom() {
        // FIXED: [A02-Lab4] an unhandled exception on an unauthenticated endpoint
        // produced the verbose error page. The exception is caught here, logged
        // server-side, and reported to the caller as a generic message with a
        // correlation id.
        try {
            throw new IllegalStateException("Debug endpoint triggered a deliberate failure");
        } catch (IllegalStateException e) {
            String correlationId = java.util.UUID.randomUUID().toString();

            org.slf4j.LoggerFactory.getLogger(Lab4DebugController.class)
                    .error("deliberate failure [{}] on /api/a02/debug/boom", correlationId, e);

            return ResponseEntity.status(500).body(Map.of(
                    "error", "Internal server error",
                    "correlation_id", correlationId));
        }
    }

}
