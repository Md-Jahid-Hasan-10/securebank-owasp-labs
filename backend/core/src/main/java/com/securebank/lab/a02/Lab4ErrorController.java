package com.securebank.lab.a02;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private static final Logger log = LoggerFactory.getLogger(Lab4ErrorController.class);
    /**
     * Renders every unhandled exception as a verbose JSON error.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handle(Exception e, HttpServletRequest request) {
        // FIXED: [A02-Lab4] ...
        String correlationId = UUID.randomUUID().toString();

        // The detail goes to the server log, never to the client.
        log.error("unhandled exception [{}] on {} {}", correlationId, request.getMethod(), request.getRequestURI(), e);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "Internal server error");
        body.put("correlation_id", correlationId);

        return ResponseEntity.status(500).body(body);

    }

    /**
     * The configuration snapshot leaked alongside the error.
     */

}
