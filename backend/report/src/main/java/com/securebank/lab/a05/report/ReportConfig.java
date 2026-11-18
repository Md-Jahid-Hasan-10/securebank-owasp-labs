package com.securebank.lab.a05.report;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Internal configuration of the report service.
 *
 * <p>This is the analogue of the Go service's {@code Config} struct, and it is
 * reachable through the template injection in {@link ReportController}.</p>
 */
@Component
public class ReportConfig {

    private final String secretKey;
    private final String dbPath;
    private final boolean internalOnly;

    public ReportConfig(@Value("${report.secret-key}") String secretKey,
                        @Value("${report.db-path}") String dbPath,
                        @Value("${report.internal-only:false}") boolean internalOnly) {
        this.secretKey = secretKey;
        this.dbPath = dbPath;
        this.internalOnly = internalOnly;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public String getDbPath() {
        return dbPath;
    }

    public boolean isInternalOnly() {
        return internalOnly;
    }
}
