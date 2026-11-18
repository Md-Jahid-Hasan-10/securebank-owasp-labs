package com.securebank.lab.a01;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

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

    /**
     * Hosts this application is allowed to fetch. Anything else is refused.
     */
    private static final Set<String> ALLOWED_HOSTS = Set.of("report");

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            // Redirects are never followed: an allowed host could otherwise
            // redirect us to an internal address and bypass the checks below.
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    public record StatementEmailRequest(Long accountId, String callbackUrl) {
    }

    @PostMapping("/statement-email")
    public ResponseEntity<?> statementEmail(@RequestBody StatementEmailRequest request) {
        String callbackUrl = request.callbackUrl();

        if (callbackUrl == null || callbackUrl.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "callback_url is required"));
        }

        // FIXED: [A01-Lab3] Server-Side Request Forgery - the callback URL was used
        // verbatim as the target of a server-side HTTP request, with no scheme check,
        // no host allowlist and no protection against private, loopback or link-local
        // address ranges. The server could therefore be made to reach services that
        // are unreachable from the internet: cloud metadata endpoints (169.254.169.254),
        // internal admin panels and the report service on the Docker network at
        // http://report:8081/.
        // NOW: the URL is validated before any request is made. The scheme must be
        //       http or https, the host must be on the allowlist, and every address
        //       the host resolves to must be outside the private, loopback and
        //       link-local ranges. Redirects are no longer followed, so an allowed
        //       host cannot bounce the request to a blocked target.
        try {
            URI uri = URI.create(callbackUrl);

            // Layer 1 - only http and https are accepted.
            String scheme = uri.getScheme();
            if (scheme == null
                    || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                return notAllowed();
            }

            // Layer 2 - the host must be on the allowlist.
            String host = uri.getHost();
            if (host == null || !ALLOWED_HOSTS.contains(host.toLowerCase(Locale.ROOT))) {
                return notAllowed();
            }

            // Layer 3 - resolve the host and check every address it resolves to.
            // Checking the hostname string is not enough: "localhost", "127.0.0.1"
            // and a public domain that resolves to 127.0.0.1 all slip past it.
            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (isBlocked(address)) {
                    return notAllowed();
                }
            }

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
    private boolean isBlocked(InetAddress address) {
        if (address.isLoopbackAddress()) {
            // 127.0.0.0/8 and ::1
            return true;
        }
        if (address.isLinkLocalAddress()) {
            // 169.254.0.0/16 - this covers the cloud metadata address
            return true;
        }
        if (address.isSiteLocalAddress()) {
            // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            return true;
        }
        if (address.isAnyLocalAddress()) {
            // 0.0.0.0
            return true;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc) {
            // IPv6 unique-local fc00::/7
            return true;
        }
        return false;
    }

    /**
     * The single rejection response for every blocked URL.
     *
     * <p>The same message is used for every reason so that the response does not
     * tell an attacker whether their guess hit something real.</p>
     */
    private ResponseEntity<?> notAllowed() {
        return ResponseEntity.badRequest().body(Map.of(
                "error", "Callback URL is not allowed"));
    }
}
