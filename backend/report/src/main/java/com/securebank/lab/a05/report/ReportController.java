package com.securebank.lab.a05.report;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 12 — SSTI + OS Command Injection: Report Service</h2>
 * <p>OWASP A05 — Injection · Severity: High</p>
 *
 * <p><b>Objective:</b> extract internal configuration via template injection, then get
 * remote code execution via command injection.</p>
 *
 * <p>This service is the analogue of the original Go report service. It runs as a
 * separate Spring Boot application on port 8081 and is reachable on the Docker
 * network as {@code http://report:8081/} — which is also the pivot target for the
 * SSRF lab (Lab 3).</p>
 */
@RestController
@RequestMapping("/api/report/report")
public class ReportController {

    /**
     * FIXED: [A05-Lab12] The internal configuration is no longer part of the template
     * model, so there is nothing in scope for a template to reach into.
     */
    private final ReportConfig config;
    private final String reportServiceName;

    public ReportController(ReportConfig config,
                            @Value("${spring.application.name:report}") String reportServiceName) {
        this.config = config;
        this.reportServiceName = reportServiceName;
    }

    public record GenerateRequest(String accountId, String template) {
    }

    public record DateFilterRequest(String fromDate, String toDate) {
    }

    /**
     * The template model.
     *
     * <p>FIXED: [A05-Lab12] Server-Side Template Injection - the model used to carry
     * the application's internal configuration object, so a template that could reach
     * into the model could read the secret key and the internal database path.</p>
     *
     * <p>NOW: the model carries only the values the template is allowed to show. The
     * configuration object is not reachable from it at all, so even if a template
     * could be evaluated there would be nothing to steal.</p>
     */
    public static final class TemplateModel {
        private final String accountId;
        private final String service;

        TemplateModel(String accountId, String service) {
            this.accountId = accountId;
            this.service = service;
        }

        public String getAccountId() {
            return accountId;
        }

        public String getService() {
            return service;
        }
    }

    /**
     * Renders a customer statement using a caller-supplied template.
     */
    @PostMapping("/generate")
    public ResponseEntity<?> generate(@RequestBody GenerateRequest request) {
        String template = request.template() == null ? "" : request.template();
        String accountId = request.accountId() == null ? "" : request.accountId();

        TemplateModel model = new TemplateModel(accountId, reportServiceName);

        try {
            // FIXED: [A05-Lab12] Server-Side Template Injection - the template string
            // used to come straight from the request body and was evaluated against a
            // model that contained the application's internal configuration object. The
            // payload
            //   ${config.secretKey}
            // read the internal secret key, and because a full evaluation context was
            // used, method calls on arbitrary types were reachable too:
            //   ${T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{"id"})}
            //
            // NOW: no user-supplied expression is ever evaluated. The template is
            // matched against a fixed set of server-side templates and the caller's
            // values are substituted as plain text. Anything that does not match a
            // known template is rejected, so there is no expression language in scope
            // at all - no type references, no method invocation, no command execution.
            String rendered = render(template, model);

            return ResponseEntity.ok(Map.of(
                    "account_id", accountId,
                    "template", template,
                    "output", rendered));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(400).body(Map.of(
                    "error", "Unknown report template"));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Could not render report"));
        }
    }

    /**
     * Filters transactions by date range.
     */
    @PostMapping("/date-filter")
    public ResponseEntity<?> dateFilter(@RequestBody DateFilterRequest request) {
        String fromDate = request.fromDate() == null ? "" : request.fromDate();
        String toDate = request.toDate() == null ? "" : request.toDate();

        try {
            // FIXED: [A05-Lab12] OS Command Injection - the date used to be
            // concatenated into a shell command string and handed to sh -c, so a value
            // like
            //   2024-01-01' && id && echo '
            // broke out of the intended argument and ran an arbitrary command with
            // the service's privileges.
            //
            // NOW: the dates are parsed with a strict formatter, so a value that is
            // not an ISO date is rejected before anything else happens. No shell is
            // involved at all any more - the range is formatted and returned as data.
            LocalDate from = LocalDate.parse(fromDate, DateTimeFormatter.ISO_LOCAL_DATE);
            LocalDate to = LocalDate.parse(toDate, DateTimeFormatter.ISO_LOCAL_DATE);

            if (to.isBefore(from)) {
                return ResponseEntity.status(400).body(Map.of(
                        "error", "Invalid date range"));
            }

            return ResponseEntity.ok(Map.of(
                    "from_date", from.toString(),
                    "to_date", to.toString(),
                    "command", "date-range " + from + " " + to,
                    "output", "Transactions from " + from + " to " + to));
        } catch (DateTimeParseException e) {
            // FIXED: [A05-Lab12] the error detail is not returned to the client. The
            // old response contained e.toString(), which leaked the parser's
            // expectations and the internal call chain.
            return ResponseEntity.status(400).body(Map.of(
                    "error", "Invalid date range"));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Could not filter transactions"));
        }
    }

    /**
     * Renders one of the fixed, server-side report templates.
     *
     * <p>FIXED: [A05-Lab12] This replaces the old {@code evaluate()} method, which
     * parsed the caller's string as a SpEL expression and evaluated it against a
     * root object with a full StandardEvaluationContext. There is no expression
     * parser here any more: the template is compared against known names and the
     * model's values are inserted as plain text.</p>
     */
    private String render(String template, TemplateModel model) {
        if (template == null || template.isBlank() || "statement".equals(template)) {
            return "Statement for account " + model.getAccountId()
                    + " generated by " + model.getService();
        }
        if ("summary".equals(template)) {
            return "Summary for account " + model.getAccountId()
                    + " generated by " + model.getService();
        }
        throw new IllegalArgumentException("unknown template: " + template);
    }
}
