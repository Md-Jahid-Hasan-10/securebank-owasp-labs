package com.securebank.lab.a08;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/**
 * <h2>Lab 22 — Unverified File Upload</h2>
 * <p>OWASP A08 — Software &amp; Data Integrity Failures · Severity: High</p>
 *
 * <p><b>Objective:</b> upload a file of any type and have it served back from the
 * web root.</p>
 */
@RestController
@RequestMapping("/api/a08")
public class Lab22UploadController {

    /**
     * FIXED: [A08-Lab22] The extensions a KYC document is allowed to have. Only
     * document and image formats are accepted; executable and markup formats
     * (.jsp, .php, .py, .html, .svg, .js) are not, because a file the web server
     * can execute is a file the attacker can execute.
     */
    private static final Set<String> ALLOWED_EXTENSIONS =
            Set.of(".pdf", ".png", ".jpg", ".jpeg", ".doc", ".docx", ".txt");

    /**
     * FIXED: [A08-Lab22] The maximum size of an upload, enforced in the controller
     * as well as by the global multipart limit.
     */
    private static final long MAX_BYTES = 5L * 1024L * 1024L;

    private final Path uploadDirectory;

    public Lab22UploadController(@Value("${app.upload-dir:data/uploads}") String uploadDir) {
        this.uploadDirectory = Paths.get(uploadDir).toAbsolutePath().normalize();
    }

    /**
     * Lists what is currently sitting in the upload directory.
     */
    @GetMapping("/kyc-upload")
    public ResponseEntity<?> list() {
        try {
            if (!Files.isDirectory(uploadDirectory)) {
                return ResponseEntity.ok(Map.of("uploads", List.of()));
            }
            try (var stream = Files.list(uploadDirectory)) {
                return ResponseEntity.ok(Map.of("uploads",
                        stream.map(p -> p.getFileName().toString()).toList()));
            }
        } catch (IOException e) {
            return ResponseEntity.status(400).body(Map.of("error", "Could not list uploads"));
        }
    }

    /**
     * Stores an uploaded KYC document.
     */
    @PostMapping("/kyc-upload")
    public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) {
        // FIXED: [A08-Lab22] Unrestricted File Upload - the client's filename used to
        // be used verbatim, the extension and content type were never checked, and
        // the file was written into the static web root. An attacker could therefore
        // place a .py, .jsp, .html or .svg file inside the document root and have it
        // served back, or use traversal sequences in the filename to write outside the
        // upload directory entirely.
        //
        // NOW: the extension is checked against an allowlist, the size is capped, the
        // file is stored under a UUID name so the original name never reaches the
        // filesystem, and the resolved path is verified to stay inside the upload
        // directory. The upload directory itself lives outside the web root.
        String originalName = file.getOriginalFilename();

        if (file.isEmpty()) {
            return ResponseEntity.status(400).body(Map.of("error", "Upload failed"));
        }

        if (file.getSize() > MAX_BYTES) {
            return ResponseEntity.status(400).body(Map.of("error", "Upload failed"));
        }

        String extension = extensionOf(originalName);
        if (!ALLOWED_EXTENSIONS.contains(extension)) {
            return ResponseEntity.status(400).body(Map.of(
                    "error", "Upload failed",
                    "allowed_types", "pdf, png, jpg, jpeg, doc, docx, txt"));
        }

        try {
            Files.createDirectories(uploadDirectory);

            // FIXED: [A08-Lab22] the stored name is generated, never taken from the
            // client, so a traversal sequence in the original name cannot escape the
            // upload directory and a second upload cannot overwrite the first.
            String storedName = UUID.randomUUID() + extension;
            Path target = uploadDirectory.resolve(storedName).normalize();

            if (!target.startsWith(uploadDirectory)) {
                throw new IOException("Invalid filename");
            }

            Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);

            return ResponseEntity.ok(Map.of(
                    "uploaded", true,
                    "original_filename", originalName,
                    "stored_filename", storedName,
                    "url", "/api/a08/kyc-download/" + storedName));
        } catch (IOException e) {
            // FIXED: [A08-Lab22] the error detail is no longer returned: it used to
            // contain the absolute server path.
            return ResponseEntity.status(400).body(Map.of(
                    "error", "Upload failed"));
        }
    }

    /**
     * Returns the lower-case extension of a filename, including the dot.
     *
     * <p>FIXED: [A08-Lab22] the extension is taken from the last dot only, so a name
     * such as {@code payload.pdf.jsp} is classified as {@code .jsp} and rejected.</p>
     */
    private static String extensionOf(String filename) {
        if (filename == null) {
            return "";
        }
        int dot = filename.lastIndexOf('.');
        if (dot < 0 || dot == filename.length() - 1) {
            return "";
        }
        return filename.substring(dot).toLowerCase(Locale.ROOT);
    }

    /**
     * Serves an uploaded file as a download.
     *
     * <p>FIXED: [A08-Lab22] the uploaded files used to be served by a static
     * resource handler, which meant the browser decided how to interpret them. A
     * .html or .svg file became an active payload in the victim's browser.</p>
     *
     * <p>NOW: the file is served with {@code Content-Disposition: attachment} and a
     * fixed {@code application/octet-stream} content type, so it is downloaded
     * rather than rendered, and the path is resolved and verified so that a
     * traversal sequence in the requested name cannot escape the upload
     * directory.</p>
     */
    @GetMapping("/kyc-download/{name}")
    public ResponseEntity<?> download(@PathVariable String name) {
        try {
            Path target = uploadDirectory.resolve(name).normalize();
            if (!target.startsWith(uploadDirectory) || !Files.isRegularFile(target)) {
                return ResponseEntity.status(404).body(Map.of("error", "Not found"));
            }

            byte[] content = Files.readAllBytes(target);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"" + target.getFileName() + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .contentLength(content.length)
                    .body(content);
        } catch (IOException e) {
            return ResponseEntity.status(404).body(Map.of("error", "Not found"));
        }
    }
}
