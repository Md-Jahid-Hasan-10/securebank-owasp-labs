package com.securebank.lab.a05;

import java.util.Map;

import com.securebank.core.transfer.Transfer;
import com.securebank.core.transfer.TransferRepository;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 11 — SSTI: SpEL Remote Code Execution via Transaction Remark</h2>
 * <p>OWASP A05 — Injection · Severity: High</p>
 *
 * <p><b>Objective:</b> achieve remote code execution through the transaction remark
 * field.</p>
 *
 * <p>Spring Expression Language (SpEL) is the Java equivalent of Jinja2 or Go's
 * {@code text/template}. The same class of bug - evaluating user input as an
 * expression - produces the same class of outcome.</p>
 */
@RestController
@RequestMapping("/api/a05/transfers")
public class Lab11SstiController {

    private final TransferRepository transfers;
    private final ExpressionParser parser = new SpelExpressionParser();

    public Lab11SstiController(TransferRepository transfers) {
        this.transfers = transfers;
    }

    public record RemarkRequest(String remark) {
    }

    /**
     * Stores a remark and renders it back through expression evaluation.
     */
    @PostMapping("/{id}/remark")
    public ResponseEntity<?> setRemark(@PathVariable Long id, @RequestBody RemarkRequest request) {
        String remark = request.remark() == null ? "" : request.remark();

        Transfer transfer = transfers.findById(id).orElse(null);
        if (transfer == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Transfer not found"));
        }

        transfers.updateRemark(id, remark);

        String rendered;
        try {
            // VULN: [A05-Lab11] Server-Side Template Injection - the remark is parsed and
            // evaluated as a SpEL expression instead of being treated as plain text.
            // StandardEvaluationContext is used, which allows type references via T(...),
            // so the payload
            //   T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{"id"})
            // reaches Runtime.exec and executes an operating system command.
            // FIX:  never evaluate user input as an expression. If a template is needed,
            //       pass the user value as a *variable* into a fixed template, and use
            //       SimpleEvaluationContext (or no context at all) so that type
            //       references and method invocation are impossible.
            StandardEvaluationContext context = new StandardEvaluationContext();
            Expression expression = parser.parseExpression(remark);
            Object value = expression.getValue(context);
            rendered = render(value);
        } catch (SpelParseException e) {
            rendered = remark;
        } catch (Exception e) {
            // VULN: [A05-Lab11] the exception detail is returned to the client, which
            // leaks the evaluation context and the available types.
            // FIX:  return a generic error and log the detail server-side.
            rendered = remark;
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Could not render remark",
                    "detail", e.toString()));
        }

        // VULN: [A05-Lab11] the rendered result is also written back into an HTML
        // fragment that the frontend injects as raw markup, so the expression result
        // can carry a script payload straight into the victim's browser.
        // FIX:  HTML-escape the value before embedding it, and never use
        //       dangerouslySetInnerHTML for user-controlled content.
        return ResponseEntity.ok(Map.of(
                "transfer_id", id,
                "remark", remark,
                "rendered", "<p>Remark: " + rendered + "</p>"));
    }

    /**
     * Converts the evaluated value to text.
     *
     * <p>When the expression started a process (the RCE payload), the process's
     * output stream is read so that the command's result is visible in the response.</p>
     */
    private String render(Object value) {
        if (value instanceof Process process) {
            try {
                String output = new String(process.getInputStream().readAllBytes(),
                        java.nio.charset.StandardCharsets.UTF_8);
                process.waitFor();
                return output.trim();
            } catch (Exception e) {
                return String.valueOf(value);
            }
        }
        return String.valueOf(value);
    }
}
