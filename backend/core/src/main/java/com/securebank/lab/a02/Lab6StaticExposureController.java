package com.securebank.lab.a02;

import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 6 — Sensitive File Exposure: .env, .git, backup.zip</h2>
 * <p>OWASP A02 — Security Misconfiguration · Severity: Medium</p>
 *
 * <p><b>Objective:</b> recover secrets and the whole database from files that the web
 * server hands out without authentication.</p>
 */
@RestController
@RequestMapping("/api/a02")
public class Lab6StaticExposureController {

    /**
     * Lists the files that the web root currently exposes.
     *
     * <p>FIXED: [A02-Lab6] Sensitive File Exposure - the endpoint used to advertise
     * the three files that the web root exposed: the environment file, the
     * repository's git config and the database backup. It now reports an empty
     * list, because none of them is served any more.</p>
     */
    @GetMapping("/exposed-files")
    public ResponseEntity<?> exposedFiles() {
        // FIXED: [A02-Lab6] Sensitive File Exposure - the web root is no longer
        // served, the dot-prefixed resource handlers have been removed and the
        // database backup is no longer written into a served directory. There is
        // nothing left for an anonymous client to download.
        List<Map<String, Object>> files = List.of();

        return ResponseEntity.ok(Map.of(
                "web_root", "not exposed",
                "files", files));
    }

}
