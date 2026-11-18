package com.securebank.lab.a08;

import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securebank.lab.a08.gadget.AccountImportJob;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/**
 * <h2>Lab 20 — Insecure Deserialization: RCE</h2>
 * <p>OWASP A08 — Software &amp; Data Integrity Failures · Severity: High</p>
 *
 * <p><b>Objective:</b> achieve remote code execution by uploading a malicious
 * payload file.</p>
 *
 * <p>This is the Java equivalent of the Python pickle lab. The mechanism is the same
 * in principle: a deserialiser that is allowed to instantiate arbitrary classes turns
 * a data file into a code execution primitive.</p>
 */
@RestController
@RequestMapping("/api/a08/integrity")
public class Lab20DeserializationController {

    private static final Logger log = LoggerFactory.getLogger(Lab20DeserializationController.class);

    /**
     * An ObjectMapper configured with polymorphic default typing.
     *
     * <p>VULN: [A08-Lab20] Insecure Deserialization - default typing means that the
     * <em>type</em> to instantiate is read from the document itself, so the attacker
     * chooses the class. Combined with a gadget class whose creator has a side
     * effect (see {@link AccountImportJob}), a JSON document can run
     * Runtime.exec() during deserialisation.</p>
     *
     * <p>FIX: never enable default typing on an ObjectMapper that reads untrusted
     * input. Use a concrete target type, or a JsonTypeInfo with a closed allowlist of
     * subtypes.</p>
     */
    private final ObjectMapper vulnerableMapper = new ObjectMapper()
            .activateDefaultTyping(
                    com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator.instance,
                    ObjectMapper.DefaultTyping.EVERYTHING,
                    com.fasterxml.jackson.annotation.JsonTypeInfo.As.PROPERTY);

    @PostMapping("/import-account")
    public ResponseEntity<?> importAccount(@RequestParam("data") MultipartFile file) {
        try {
            byte[] content = file.getBytes();

            // VULN: [A08-Lab20] the uploaded file is deserialised with an ObjectMapper
            // that has polymorphic default typing enabled. The document's own
            // "@class" property selects the class to instantiate, so uploading a
            // gadget chain executes arbitrary code on the server during this call.
            // FIX:  parse into a fixed, known type with a plain ObjectMapper:
            //       AccountImport import = new ObjectMapper()
            //               .readValue(content, AccountImport.class);
            Object parsed = vulnerableMapper.readValue(content, Object.class);

            log.info("account import processed, {} bytes", content.length);

            Map<String, Object> body = new java.util.LinkedHashMap<>();
            body.put("imported", true);
            body.put("filename", file.getOriginalFilename());
            body.put("bytes", content.length);
            body.put("deserialized_type", parsed == null ? null : parsed.getClass().getName());

            // VULN: [A08-Lab20] the response echoes the gadget's captured output
            // straight back, which is how the attacker confirms code execution.
            if (parsed instanceof AccountImportJob job) {
                body.put("command", job.getCommand());
                body.put("command_output", job.getOutput());
            }

            return ResponseEntity.ok(body);
        } catch (Exception e) {
            // VULN: [A08-Lab20] the exception detail is returned to the client, which
            // helps the attacker tune their payload.
            // FIX:  log the detail server-side and return a generic error.
            log.warn("account import failed", e);
            return ResponseEntity.status(400).body(Map.of(
                    "error", "Could not import account file",
                    "detail", e.getMessage()));
        }
    }

    /**
     * Shows what the vulnerable ObjectMapper accepts, for reference.
     */
    @PostMapping("/import-account/describe")
    public ResponseEntity<?> describe() {
        return ResponseEntity.ok(Map.of(
                "default_typing", vulnerableMapper.getPolymorphicTypeValidator() != null
                        ? "enabled (LaissezFaireSubTypeValidator)" : "disabled",
                "type_property", "@class",
                "note", "Any class on the classpath can be named in the document's @class property.",
                "known_gadget", "com.securebank.lab.a08.gadget.AccountImportJob",
                "historical_gadget", "org.apache.commons.collections.functors.InvokerTransformer",
                "historical_note", "Jackson 2.17 hard-blocks that class, so this lab ships its own gadget."));
    }
}
