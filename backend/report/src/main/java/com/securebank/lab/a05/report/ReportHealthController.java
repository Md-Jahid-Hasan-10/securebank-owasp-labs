package com.securebank.lab.a05.report;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Liveness probe for the report service.
 *
 * <p>The report service has no authentication of its own - that is part of what
 * Lab 3's SSRF pivot exploits - so the probe is simply open.</p>
 */
@RestController
@RequestMapping("/api/report/health")
public class ReportHealthController {

    @GetMapping
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("service", "securebank-report");
        body.put("status", "UP");
        return ResponseEntity.ok(body);
    }
}
