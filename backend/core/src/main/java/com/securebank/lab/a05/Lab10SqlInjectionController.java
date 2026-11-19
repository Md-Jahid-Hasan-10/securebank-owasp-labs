package com.securebank.lab.a05;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import com.securebank.core.user.PasswordService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 10 — SQL Injection: Login Bypass &amp; Data Dump</h2>
 * <p>OWASP A05 — Injection · Severity: High</p>
 *
 * <p><b>Objective:</b> bypass authentication and dump the database.</p>
 *
 * <p>This controller talks to the database through raw JDBC on purpose. The
 * {@code JdbcTemplate}-based repositories elsewhere in the application use
 * parameter binding; these queries do not.</p>
 */
@RestController
@RequestMapping("/api/a05")
public class Lab10SqlInjectionController {

    private final DataSource dataSource;
    private final String jdbcUrl;
    private final String jdbcUser;
    private final String jdbcPassword;
    private final com.securebank.core.security.JwtService tokenService;

    public Lab10SqlInjectionController(DataSource dataSource,
                                       com.securebank.core.security.JwtService tokenService,
                                       @Value("${spring.datasource.url}") String jdbcUrl,
                                       @Value("${spring.datasource.username}") String jdbcUser,
                                       @Value("${spring.datasource.password}") String jdbcPassword) {
        this.dataSource = dataSource;
        this.tokenService = tokenService;
        this.jdbcUrl = jdbcUrl;
        this.jdbcUser = jdbcUser;
        this.jdbcPassword = jdbcPassword;
    }

    public record LoginRequest(String username, String password) {
    }

    /**
     * The vulnerable login.
     */
    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        String username = request.username() == null ? "" : request.username();
        String password = request.password() == null ? "" : request.password();

        // VULN: [A05-Lab10] SQL Injection - the username is concatenated straight
        // into the SQL text, so the attacker controls the statement. The classic
        // payload is username = "admin' --" which comments out the rest of the
        // statement, or "' OR '1'='1' --" which matches every row.
        // FIX:  use parameter binding:
        //       PreparedStatement ps = conn.prepareStatement(
        //           "SELECT username, password_hash, email, role, id FROM users "
        //           + "WHERE username = ?");
        //       ps.setString(1, username);
        String sql = "SELECT username, password_hash, email, role, id FROM users WHERE username = '"
                + username + "'";

        try (Connection conn = openConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            List<Map<String, Object>> rows = new ArrayList<>();
            while (rs.next()) {
                rows.add(row(rs));
            }

            if (rows.isEmpty()) {
                return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
            }

            Map<String, Object> user = rows.get(0);

            // FIXED: [A04-Lab7] Cryptographic Failure - the password is verified with
            // bcrypt instead of being compared inside the SQL text. A bcrypt hash is
            // salted, so the database cannot compare it: the check has to happen in
            // Java with BCrypt.checkpw, which re-derives the hash using the salt
            // embedded in the stored value.
            //
            // The injection above is still exploitable, which is Lab 10's own flaw:
            // the attacker controls the WHERE clause, so "admin' --" selects the
            // administrator and the password check is skipped for a query that was
            // manipulated. The check is only applied when the query returned the row
            // that the literal username would have selected.
            if (!isInjected(username, user) && !PasswordService.matches(password, (String) user.get("password_hash"))) {
                return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
            }

            return ResponseEntity.ok(Map.of(
                    "token", issueToken(user),
                    "user", user));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Database error",
                    "detail", e.getMessage()));
        }
    }

    /**
     * Reports whether the injected query returned a row that the literal username
     * could not have selected on its own.
     *
     * <p>Used by the login so that the bcrypt check can be applied to a legitimate
     * login without closing the SQL injection that Lab 10 demonstrates. When the
     * requested username is a plain value, the query returns exactly the row with
     * that username. When the username carries an injection, the returned row is
     * a different account - which is precisely the bypass.</p>
     */
    private boolean isInjected(String requestedUsername, Map<String, Object> returnedUser) {
        String returnedUsername = String.valueOf(returnedUser.get("username"));
        return !returnedUsername.equals(requestedUsername);
    }

    /**
     * A UNION-injectable search endpoint over the users table.
     */
    @GetMapping("/transfers/search")
    public ResponseEntity<?> search(@RequestParam("q") String query) {
        // The base query selects five columns. The UNION payload in the walkthrough
        // matches that arity and column order exactly:
        //   ' UNION SELECT username,password_hash,email,role,id FROM users--
        // VULN: [A05-Lab10] SQL Injection - the search term is concatenated into the
        // query, so an attacker can append a UNION SELECT and read any table, or
        // comment out the rest of the statement with --.
        // FIX:  use a PreparedStatement with a ? placeholder for the search term.
        String sql = "SELECT username, password_hash, email, role, id FROM users WHERE username LIKE '%"
                + query + "%'";

        try (Connection conn = openConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            List<Map<String, Object>> rows = new ArrayList<>();
            while (rs.next()) {
                rows.add(row(rs));
            }

            return ResponseEntity.ok(Map.of(
                    "query", query,
                    "count", rows.size(),
                    "results", rows));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Database error",
                    "detail", e.getMessage()));
        }
    }

    /**
     * Lists the database's tables and columns, showing what is available to dump.
     */
    @GetMapping("/schema")
    public ResponseEntity<?> schema() {
        Map<String, Object> tables = new LinkedHashMap<>();

        // VULN: [A05-Lab10] the information_schema query is parameterised on purpose so
        // that it works reliably; it is here to show the trainee the shape of the data
        // that the injection in /transfers/search can reach.
        try (Connection conn = openConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(
                     "SELECT table_name, column_name, data_type FROM information_schema.columns "
                             + "WHERE table_schema = 'public' ORDER BY table_name, ordinal_position")) {

            while (rs.next()) {
                String table = rs.getString("table_name");
                @SuppressWarnings("unchecked")
                Map<String, Object> columns = (Map<String, Object>)
                        tables.computeIfAbsent(table, key -> new LinkedHashMap<String, Object>());
                columns.put(rs.getString("column_name"), rs.getString("data_type"));
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }

        return ResponseEntity.ok(Map.of("schema", tables));
    }

    private Map<String, Object> row(ResultSet rs) throws Exception {
        Map<String, Object> row = new LinkedHashMap<>();
        // The column order here matches the SELECT in both queries:
        //   username, password_hash, email, role, id
        // which is also the order of the UNION payload in the walkthrough:
        //   ' UNION SELECT username,password_hash,email,role,id FROM users--
        // Keeping the two identical is what lets the UNION payload type-check.
        row.put("username", rs.getString("username"));
        row.put("password_hash", rs.getString("password_hash"));
        row.put("email", rs.getString("email"));
        row.put("role", rs.getString("role"));
        row.put("id", rs.getLong("id"));
        return row;
    }

    private String issueToken(Map<String, Object> user) {
        return tokenService.issue(
                ((Number) user.get("id")).longValue(),
                String.valueOf(user.get("username")),
                String.valueOf(user.get("role")));
    }

    /**
     * Opens a raw JDBC connection.
     *
     * <p>VULN: [A05-Lab10] the connection is opened with autocommit on and no explicit
     * transaction handling, which is what makes the injected query able to commit its
     * own results.</p>
     */
    private Connection openConnection() throws Exception {
        return DriverManager.getConnection(jdbcUrl, jdbcUser, jdbcPassword);
    }
}
