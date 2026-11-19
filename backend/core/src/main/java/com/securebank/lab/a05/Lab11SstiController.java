package com.securebank.lab.a05;

import java.util.Map;

import com.securebank.core.transfer.Transfer;
import com.securebank.core.transfer.TransferRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

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

        // FIXED: [A05-Lab11] Server-Side Template Injection - the remark used to be
        // parsed and evaluated as a SpEL expression instead of being treated as plain
        // text. StandardEvaluationContext was used, which allows type references via
        // T(...), so the payload
        //   T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{"id"})
        // reached Runtime.exec and executed an operating system command.
        //
        // NOW: the remark is never evaluated. It is a string that gets stored and
        // displayed, and the only transformation applied to it is HTML escaping, so
        // it cannot reach a parser, a method call or an operating system command.
        String rendered = HtmlUtils.htmlEscape(remark);

        // FIXED: [A05-Lab11] the rendered result used to be written back into an HTML
        // fragment that the frontend injected as raw markup, so the expression result
        // could carry a script payload straight into the victim's browser.
        //
        // NOW: the value is HTML-escaped before it is embedded, so a remark containing
        // markup is displayed as the text it is rather than executed as HTML.
        return ResponseEntity.ok(Map.of(
                "transfer_id", id,
                "remark", remark,
                "rendered", "<p>Remark: " + rendered + "</p>"));
    }
}
