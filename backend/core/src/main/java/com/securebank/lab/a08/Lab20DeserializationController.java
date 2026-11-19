package com.securebank.lab.a08;

import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
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
     * FIXED: [A08-Lab20] A plain ObjectMapper with no polymorphic default typing.
     *
     * <p>The old mapper had default typing enabled with
     * {@code LaissezFaireSubTypeValidator}, which means the <em>type</em> to
     * instantiate was read from the document itself, so the attacker chose the
     * class. Combined with a gadget class whose creator had a side effect, a JSON
     * document could run Runtime.exec() during deserialisation.</p>
     *
     * <p>NOW: the mapper has no type information in it at all. The target type is
     * fixed by the call site, so a document that names a class is simply rejected as
     * an unknown property.</p>
     */
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * The concrete shape an account import document must have.
     *
     * <p>FIXED: [A08-Lab20] the import file is parsed into this fixed type. There is
     * no {@code @class} property to honour, and nothing in the document can choose
     * what gets instantiated.</p>
     */
    public record AccountImport(String username, String accountNumber, String currency) {
    }

    /**
     * FIXED: [A08-Lab20] The mapper the import endpoint uses.
     *
     * <p>The application sets {@code spring.jackson.property-naming-strategy=SNAKE_CASE}
     * for the HTTP layer, but this mapper is built by hand, so it does not pick that
     * up. The import document uses {@code account_number}, so the mapper is told to
     * use the same snake-case naming strategy the rest of the API uses. Without this
     * the well-formed document would be rejected as an unknown property.</p>
     */
    private final ObjectMapper importMapper = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);

    @PostMapping("/import-account")
    public ResponseEntity<?> importAccount(@RequestParam("data") MultipartFile file) {
        try {
            byte[] content = file.getBytes();

            // FIXED: [A08-Lab20] the uploaded file used to be deserialised with an
            // ObjectMapper that had polymorphic default typing enabled. The document's
            // own "@class" property selected the class to instantiate, so uploading a
            // gadget chain executed arbitrary code on the server during this call.
            //
            // NOW: the document is parsed into a fixed, known type. A document that
            // carries a "@class" property fails to bind - the property is unknown -
            // and no code runs while it is being read.
            AccountImport parsed = importMapper.readValue(content, AccountImport.class);

            log.info("account import processed, {} bytes", content.length);

            Map<String, Object> body = new java.util.LinkedHashMap<>();
            body.put("imported", true);
            body.put("filename", file.getOriginalFilename());
            body.put("bytes", content.length);
            body.put("deserialized_type", AccountImport.class.getName());
            body.put("username", parsed == null ? null : parsed.username());
            body.put("account_number", parsed == null ? null : parsed.accountNumber());
            body.put("currency", parsed == null ? null : parsed.currency());

            return ResponseEntity.ok(body);
        } catch (Exception e) {
            // FIXED: [A08-Lab20] the exception detail used to be returned to the
            // client, which helped the attacker tune their payload. The detail is
            // logged server-side and the response is generic.
            log.warn("account import failed", e);
            return ResponseEntity.status(400).body(Map.of(
                    "error", "Could not import account file"));
        }
    }

    /**
     * Shows how the import endpoint parses its input.
     */
    @PostMapping("/import-account/describe")
    public ResponseEntity<?> describe() {
        return ResponseEntity.ok(Map.of(
                "default_typing", "disabled",
                "target_type", AccountImport.class.getName(),
                "type_property", "none - the document cannot name a class",
                "note", "The import file is parsed into a fixed type, so a document that "
                        + "names a class is rejected rather than instantiated."));
    }
}
