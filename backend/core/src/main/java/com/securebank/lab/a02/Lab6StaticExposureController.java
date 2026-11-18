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
     */
    @GetMapping("/exposed-files")
    public ResponseEntity<?> exposedFiles() {
        // VULN: [A02-Lab6] Sensitive File Exposure - the Spring Boot static resource
        // directory IS the web root, and it contains .env, .git/config and a full
        // PostgreSQL backup. Every one of them is served to any anonymous client.
        // The AWS-style keys in .env would give cloud access, the backup contains every
        // account, balance and password hash, and .git/config reveals the internal
        // repository layout.
        // FIX:  never place secrets in a directory served by the web server. Keep
        //       static assets in a dedicated folder outside the web root, add .env and
        //       .git to .gitignore, and add a build-time check that fails the build if a
        //       secret file is found in the static tree.
        List<Map<String, Object>> files = List.of(
                Map.of(
                        "url", "/.env",
                        "description", "Environment file — fake AWS/Stripe credentials",
                        "contains", "AWS keys, Stripe secret, database password, JWT secret"),
                Map.of(
                        "url", "/.git/config",
                        "description", "Git configuration — reveals the internal repository",
                        "contains", "remote origin URL, branch configuration"),
                Map.of(
                        "url", "/backup.zip",
                        "description", "PostgreSQL database backup — the entire dataset",
                        "contains", "users, accounts, transfers, MD5 password hashes"));

        return ResponseEntity.ok(Map.of(
                "web_root", "src/main/resources/static/",
                "files", files));
    }
}
