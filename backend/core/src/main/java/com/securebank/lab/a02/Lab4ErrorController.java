package com.securebank.lab.a02;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * <h2>Lab 4 / Lab 23 — Verbose Error Handler</h2>
 * <p>OWASP A02 — Security Misconfiguration (Lab 4) · A10 — Mishandling of
 * Exceptional Conditions (Lab 23) · Severity: Low</p>
 *
 * <p><b>Objective:</b> trigger an unhandled exception and read the application's
 * internal state out of the error response.</p>
 *
 * <p>This is the Spring Boot analogue of Django's {@code DEBUG = True}. Where the
 * original application returned Django's technical 500 page, this one returns the
 * exception message, the request that caused it and the full stack trace - and, on
 * top of that, a snapshot of the resolved configuration including the JWT signing
 * secret.</p>
 */
@RestControllerAdvice
public class Lab4ErrorController {

    private final Environment environment;

    public Lab4ErrorController(Environment environment) {
        this.environment = environment;
    }

    /**
     * Renders every unhandled exception as a verbose JSON error.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handle(Exception e, HttpServletRequest request) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", e.getClass().getName());
        body.put("message", e.getMessage());

        // VULN: [A02-Lab4] Security Misconfiguration / Information Disclosure - the
        // error response names the request URI and the handler that failed, which
        // maps the application's internal structure for an attacker.
        // FIX:  return a correlation id and a generic message; log the detail
        //       server-side only.
        body.put("path", request.getRequestURI());
        body.put("method", request.getMethod());

        // VULN: [A10-Lab23] Mishandling of Exceptional Conditions - the full stack
        // trace is returned to the client. It exposes file paths, third-party library
        // versions, the internal call chain and the names of internal variables.
        // FIX:  set server.error.include-stacktrace=never and log the trace instead.
        body.put("trace", sw.toString());

        // VULN: [A02-Lab4] the debug snapshot repeats the configuration disclosure of
        // Lab4DebugController on every error, so an attacker does not even need to
        // find /api/a02/debug - any 500 hands over the JWT signing secret.
        // FIX:  never include configuration values in an error response.
        body.put("debug", true);
        body.put("config", debugSnapshot());

        return ResponseEntity.status(500).body(body);
    }

    /**
     * The configuration snapshot leaked alongside the error.
     */
    private Map<String, Object> debugSnapshot() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("server.error.include-stacktrace",
                environment.getProperty("server.error.include-stacktrace"));
        config.put("jwt.secret", environment.getProperty("jwt.secret"));
        config.put("spring.datasource.url", environment.getProperty("spring.datasource.url"));
        config.put("spring.datasource.username", environment.getProperty("spring.datasource.username"));
        config.put("spring.datasource.password", environment.getProperty("spring.datasource.password"));
        return config;
    }
}
