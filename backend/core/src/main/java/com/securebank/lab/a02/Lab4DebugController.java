package com.securebank.lab.a02;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.core.env.Environment;
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
     * Prints the resolved application configuration.
     */
    @GetMapping("/debug")
    public ResponseEntity<?> debug() {
        Map<String, Object> config = new LinkedHashMap<>();

        // VULN: [A02-Lab4] Security Misconfiguration / Information Disclosure - a debug
        // endpoint dumps the entire resolved application configuration, including the
        // JWT signing secret and the database connection string. Combined with
        // server.error.include-stacktrace=always (which makes every unhandled error
        // equally verbose) this hands an attacker the keys to the whole application:
        // the secret from Lab 8 forges tokens, the datasource URL points at the database
        // that Lab 6 also dumps.
        // FIX:  remove the endpoint entirely, or gate it behind a build profile that
        //       can never be active in production. Never return secrets from an HTTP
        //       response, and set server.error.include-stacktrace=never.
        config.put("server.error.include-stacktrace", environment.getProperty("server.error.include-stacktrace"));
        config.put("jwt.secret", environment.getProperty("jwt.secret"));
        config.put("jwt.expiration-seconds", environment.getProperty("jwt.expiration-seconds"));
        config.put("spring.datasource.url", environment.getProperty("spring.datasource.url"));
        config.put("spring.datasource.username", environment.getProperty("spring.datasource.username"));
        config.put("spring.datasource.password", environment.getProperty("spring.datasource.password"));
        config.put("spring.jackson.default-typing", environment.getProperty("spring.jackson.default-typing"));

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("debug", true);
        response.put("active_profiles", java.util.List.of(environment.getActiveProfiles()));
        response.put("config", config);

        return ResponseEntity.ok(response);
    }

    /**
     * Deliberately throws so that the verbose error handler renders.
     *
     * <p>VULN: [A02-Lab4] Security Misconfiguration - the endpoint is reachable
     * without authentication and the resulting 500 response is rendered by
     * {@link Lab4ErrorController}, which returns the full stack trace and a
     * configuration snapshot.</p>
     *
     * <p>FIX:  return a generic error and log the detail server-side. A production
     * application must never render a stack trace or a configuration dump to an
     * unauthenticated caller.</p>
     */
    @GetMapping("/debug/boom")
    public ResponseEntity<?> boom() {
        // VULN: [A02-Lab4] an unhandled exception on an unauthenticated endpoint
        // produces the verbose error page.
        // FIX:  handle the exception and return a sanitised response.
        throw new IllegalStateException("Debug endpoint triggered a deliberate failure");
    }
}
