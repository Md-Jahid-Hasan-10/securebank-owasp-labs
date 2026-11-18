package com.securebank.lab.a05.report;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
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
     * <p>VULN: [A05-Lab12] Server-Side Template Injection - the model carries the
     * application's internal configuration object, so a template that can reach into
     * the model can read the secret key and the internal database path.</p>
     */
    public static final class TemplateModel {
        private final String accountId;
        private final ReportConfig config;
        private final String service;

        TemplateModel(String accountId, ReportConfig config, String service) {
            this.accountId = accountId;
            this.config = config;
            this.service = service;
        }

        public String getAccountId() {
            return accountId;
        }

        public ReportConfig getConfig() {
            return config;
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

        TemplateModel model = new TemplateModel(accountId, config, reportServiceName);

        try {
            // VULN: [A05-Lab12] Server-Side Template Injection - the template string comes
            // straight from the request body and is evaluated against a model that
            // contains the application's internal configuration object. The payload
            //   ${config.secretKey}
            // reads the internal secret key, and because a full evaluation context is
            // used, method calls on arbitrary types are reachable too:
            //   ${T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{"id"})}
            // FIX:  never accept a user-supplied template. Render from a fixed set of
            //       server-side templates and pass dynamic values as model attributes.
            String rendered = evaluate(template, model);

            return ResponseEntity.ok(Map.of(
                    "account_id", accountId,
                    "template", template,
                    "output", rendered));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Could not render report",
                    "detail", e.toString()));
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
            // VULN: [A05-Lab12] OS Command Injection - the date is concatenated into a
            // shell command string and handed to sh -c, so a value like
            //   2024-01-01' && id && echo '
            // breaks out of the intended argument and runs an arbitrary command with
            // the service's privileges.
            // FIX:  parse and validate the date with a strict formatter, then pass the
            //       value as a separate argument to exec() rather than through sh -c:
            //       LocalDate from = LocalDate.parse(fromDate, DateTimeFormatter.ISO_LOCAL_DATE);
            //       ProcessBuilder pb = new ProcessBuilder("date", "--from", from.toString());
            String command = "echo 'From: " + fromDate + " To: " + toDate + "' && date";

            ProcessBuilder builder = new ProcessBuilder("sh", "-c", command);
            builder.redirectErrorStream(true);

            Process process = builder.start();
            String output;
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                output = sb.toString();
            }
            process.waitFor();

            return ResponseEntity.ok(Map.of(
                    "from_date", fromDate,
                    "to_date", toDate,
                    "command", command,
                    "output", output));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Could not filter transactions",
                    "detail", e.toString()));
        }
    }

    /**
     * Evaluates a template expression against the model.
     *
     * <p>This is the vulnerable evaluation itself, kept separate so the exploit steps
     * are easy to find.</p>
     */
    private String evaluate(String template, TemplateModel model) {
        org.springframework.expression.ExpressionParser parser =
                new org.springframework.expression.spel.standard.SpelExpressionParser();
        org.springframework.expression.spel.support.StandardEvaluationContext context =
                new org.springframework.expression.spel.support.StandardEvaluationContext();
        context.setRootObject(model);

        // The ${...} syntax is Thymeleaf/JSpringEL style; the SpEL expression inside
        // the braces is what actually gets evaluated.
        String expression = template;
        int start = template.indexOf("${");
        int end = template.lastIndexOf('}');
        if (start >= 0 && end > start) {
            expression = template.substring(start + 2, end);
        }

        // VULN: [A05-Lab12] StandardEvaluationContext permits type references and
        // arbitrary method invocation. SimpleEvaluationContext would forbid T(...).
        Object value = parser.parseExpression(expression).getValue(context);
        return value == null ? "" : String.valueOf(value);
    }
}
