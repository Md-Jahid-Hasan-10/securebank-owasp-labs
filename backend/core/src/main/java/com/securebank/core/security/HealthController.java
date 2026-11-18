package com.securebank.core.security;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Liveness/readiness probe for the core service.
 *
 * <p>Whitelisted in {@link AuthFilter} so that container orchestrators can poll it
 * without credentials.</p>
 */
@RestController
@RequestMapping("/api/health")
public class HealthController {

    private final JdbcTemplate jdbc;

    public HealthController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("service", "securebank-core");
        body.put("status", "UP");

        try {
            Integer users = jdbc.queryForObject("SELECT COUNT(*) FROM users", Integer.class);
            body.put("database", "UP");
            body.put("users", users);
        } catch (Exception e) {
            body.put("status", "DOWN");
            body.put("database", "DOWN");
            return ResponseEntity.status(503).body(body);
        }

        return ResponseEntity.ok(body);
    }
}
