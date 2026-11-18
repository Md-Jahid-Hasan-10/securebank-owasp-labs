package com.securebank.core.user;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {

    private static final RowMapper<User> MAPPER = (rs, rowNum) -> new User(
            rs.getLong("id"),
            rs.getString("username"),
            rs.getString("email"),
            rs.getString("password_hash"),
            rs.getString("role"),
            rs.getString("full_name"),
            rs.getString("sort_code"),
            rs.getBoolean("must_change_password"));

    private final JdbcTemplate jdbc;

    public UserRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<User> findByUsername(String username) {
        List<User> found = jdbc.query(
                "SELECT id, username, email, password_hash, role, full_name, sort_code, must_change_password "
                        + "FROM users WHERE username = ?",
                MAPPER, username);
        return found.stream().findFirst();
    }

    public Optional<User> findById(Long id) {
        List<User> found = jdbc.query(
                "SELECT id, username, email, password_hash, role, full_name, sort_code, must_change_password "
                        + "FROM users WHERE id = ?",
                MAPPER, id);
        return found.stream().findFirst();
    }

    public List<User> findAll() {
        return jdbc.query(
                "SELECT id, username, email, password_hash, role, full_name, sort_code, must_change_password "
                        + "FROM users ORDER BY id",
                MAPPER);
    }

    public void updateProfile(Long id, String username, String email, String role) {
        jdbc.update("UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
                username, email, role, id);
    }

    public void updatePasswordHash(Long id, String passwordHash) {
        jdbc.update("UPDATE users SET password_hash = ? WHERE id = ?", passwordHash, id);
    }
    /**
     * Clears the mandatory-password-change flag once the password has been replaced.
     *
     * <p>FIXED: [A02-Lab5] the flag is what stops the seeded factory password from
     * being a permanent way in, so it must be cleared as soon as a real password is
     * set - and only then.</p>
     */
    public void clearMustChangePassword(Long id) {
        jdbc.update("UPDATE users SET must_change_password = FALSE WHERE id = ?", id);
    }

    /**
     * Inserts a new user and returns its generated id.
     */
    public Long insert(Map<String, Object> values) {
        org.springframework.jdbc.support.GeneratedKeyHolder keyHolder =
                new org.springframework.jdbc.support.GeneratedKeyHolder();
        jdbc.update(conn -> {
            var ps = conn.prepareStatement(
                    "INSERT INTO users (username, email, password_hash, role, full_name, sort_code, must_change_password) "
                            + "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    new String[] { "id" });
            ps.setString(1, (String) values.get("username"));
            ps.setString(2, (String) values.get("email"));
            ps.setString(3, (String) values.get("password_hash"));
            ps.setString(4, (String) values.getOrDefault("role", "customer"));
            ps.setString(5, (String) values.get("full_name"));
            ps.setString(6, (String) values.get("sort_code"));
            ps.setBoolean(7, Boolean.TRUE.equals(values.get("must_change_password")));
            return ps;
        }, keyHolder);
        return keyHolder.getKey().longValue();
    }
}
