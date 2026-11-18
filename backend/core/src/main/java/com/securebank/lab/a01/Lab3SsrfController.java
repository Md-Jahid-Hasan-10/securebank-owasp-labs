package com.securebank.lab.a01;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 3 — SSRF: Internal Metadata Fetch</h2>
 * <p>OWASP A01 — Broken Access Control · Severity: High</p>
 *
 * <p><b>Objective:</b> make the server fetch an internal URL that you choose.</p>
 */
@RestController
@RequestMapping("/api/a01/accounts")
public class Lab3SsrfController {

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    public record StatementEmailRequest(Long accountId, String callbackUrl) {
    }

    @PostMapping("/statement-email")
    public ResponseEntity<?> statementEmail(@RequestBody StatementEmailRequest request) {
        String callbackUrl = request.callbackUrl();

        if (callbackUrl == null || callbackUrl.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "callback_url is required"));
        }

        try {
            URI uri = URI.create(callbackUrl);

            // VULN: [A01-Lab3] Server-Side Request Forgery - the callback URL is used
            // verbatim as the target of a server-side HTTP request. There is no scheme
            // check, no host allowlist and no protection against private, loopback or
            // link-local address ranges, so the attacker reaches services that are
            // unreachable from the internet: cloud metadata endpoints (169.254.169.254),
            // internal admin panels and, in this lab, the report service on the Docker
            // network at http://report:8081/.
            // FIX:  validate the URL before fetching it - resolve the hostname, reject
            //       private/loopback/link-local ranges and the metadata IP, and allow
            //       only an explicit allowlist of hosts.
            HttpRequest httpRequest = HttpRequest.newBuilder(uri)
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            return ResponseEntity.ok(Map.of(
                    "sent_to", callbackUrl,
                    "status", response.statusCode(),
                    "body", response.body()));
        } catch (Exception e) {
            // The fetch was still attempted from the server's own network position -
            // that is the whole point of the SSRF. Reporting the target and the
            // failure proves the request left the application.
            return ResponseEntity.badRequest().body(Map.of(
                    "sent_to", callbackUrl,
                    "error", "Could not fetch callback URL",
                    "detail", e.toString()));
        }
    }
}
