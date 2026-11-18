package com.securebank.lab.a08;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
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

    private final Path uploadDirectory;

    public Lab22UploadController(@Value("${app.upload-dir:static/uploads}") String uploadDir) {
        this.uploadDirectory = Paths.get(uploadDir).toAbsolutePath().normalize();
    }

    /**
     * Lists what is currently sitting in the upload directory.
     */
    @org.springframework.web.bind.annotation.GetMapping("/kyc-upload")
    public ResponseEntity<?> list() {
        try {
            if (!Files.isDirectory(uploadDirectory)) {
                return ResponseEntity.ok(Map.of("uploads", java.util.List.of()));
            }
            try (var stream = Files.list(uploadDirectory)) {
                return ResponseEntity.ok(Map.of("uploads",
                        stream.map(p -> p.getFileName().toString()).toList()));
            }
        } catch (IOException e) {
            return ResponseEntity.status(400).body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Stores an uploaded KYC document.
     */
    @PostMapping("/kyc-upload")
    public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) {
        // VULN: [A08-Lab22] Unrestricted File Upload - the client's filename is used
        // verbatim, the extension and content type are never checked, and the file is
        // written into the static web root. An attacker can therefore place a .py,
        // .jsp, .html or .svg file inside the document root and have it served back,
        // or use traversal sequences in the filename to write outside the upload
        // directory entirely.
        // FIX:  validate the extension and the real content type server-side, generate
        //       a UUID-based filename so the original name is never used, store uploads
        //       OUTSIDE the web root, and serve them through a handler that sets
        //       Content-Disposition: attachment and a fixed content type.
        String originalName = file.getOriginalFilename();

        try {
            Files.createDirectories(uploadDirectory);

            Path target = uploadDirectory.resolve(originalName == null ? "upload" : originalName);

            // VULN: [A08-Lab22] the traversal sequences in the filename are NOT removed,
            // so "../../shell.txt" escapes the upload directory.
            // FIX:  resolve the target and verify it stays inside the upload directory:
            //       Path target = uploadDirectory.resolve(uuid + ".bin").normalize();
            //       if (!target.startsWith(uploadDirectory)) {
            //           throw new IOException("Invalid filename");
            //       }
            Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);

            return ResponseEntity.ok(Map.of(
                    "uploaded", true,
                    "original_filename", originalName,
                    "stored_path", target.toString(),
                    "url", "/uploads/" + originalName));
        } catch (IOException e) {
            return ResponseEntity.status(400).body(Map.of(
                    "error", "Upload failed",
                    "detail", e.getMessage()));
        }
    }
}
